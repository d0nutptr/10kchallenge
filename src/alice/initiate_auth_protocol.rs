use std::pin::Pin;
use gotham::state::{State, FromState};
use shared_lib::*;
use gotham::handler::HandlerFuture;
use futures::FutureExt;
use std::borrow::BorrowMut;
use crate::{AliceStates, ADDR_IAM, ADDR_BOB, apply_state_gate_alice};
use std::env;
use hyper::{StatusCode, HeaderMap};
use tokio::spawn;
use reqwest::Proxy;
use tokio::time::Duration;
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::{PublicKey, PaddingScheme, RSAPublicKey, BigUint};
use rsa::hash::Hashes;
use gotham::helpers::http::response::create_empty_response;
use hyper::body::Buf;

pub fn initiate_auth_protocol(state: State) -> Pin<Box<HandlerFuture>> {
    initiate_auth_protocol_async(state).boxed()
}

async fn initiate_auth_protocol_async(mut state: State) -> AsyncHandlerResponse {
    // 0. validate we in state 0
    // 1. request iam for pub key
    // 2. on pubkey returned, set new alice state
    // 3. issue request to cited party
    let (state_id, state_sig, alice_state_map) = match apply_state_gate_alice(&state, AliceStates::INITIAL) {
        Ok((state_id, state_sig, state_map, _)) => (state_id, state_sig, state_map),
        _ => return Ok(return_generic_error(state))
    };

    let infra_state = InfraState::borrow_from(&state);
    let iam_public_key = {
        infra_state.iam_pub_key.lock().unwrap().clone().unwrap()
    };

    // grab body json
    let challenge_initiate_request: ChallengeInitiateRequest = match extract_json(&mut state).await {
        Some(request) => request,
        None => return Ok(return_generic_error(state))
    };

    spawn(async move {
        let proxy_addr = challenge_initiate_request.proxy_config;
        let proxy = match Proxy::http(&proxy_addr) {
            Ok(proxy) => proxy,
            _ => return
        };

        let mut http_client = match create_async_http_client(Some(proxy)) {
            Some(client) => client,
            None => return
        };

        let public_key_report = match get_publickey_from_iam(&mut http_client, iam_public_key, Participant::ALICE, challenge_initiate_request.participant).await {
            Ok(public_key_report) => public_key_report,
            _ => return
        };

        let target_party_public_key = match public_key_report.get_public_key() {
            Some(public_key) => public_key,
            _ => return
        };

        let target_party_address = match get_participant_address(public_key_report.payload.subject.clone()) {
            Some(address) => address,
            None => return
        };

        let nonce_a = generate_nonce();

        // update alice's state
        {
            let new_state = AliceStates::AWAITING_NONCE {
                party_public_key: target_party_public_key.clone(),
                party: public_key_report.payload.subject,
                nonce_a: nonce_a.clone()
            };

            alice_state_map.lock().unwrap().insert(state_id.clone(), new_state);
        }

        let nonce_exchange_payload = {
            let nonce_exchange_payload_inner = AliceNoncePayloadInner {
                nonce_a,
                party: Participant::ALICE
            };

            let nonce_payload_str = serde_json::to_string(&nonce_exchange_payload_inner).unwrap();

            let encrypted_payload = match target_party_public_key.smart_encrypt(nonce_payload_str.into_bytes()) {
                Some(payload) => payload.b64_encode(),
                _ => return
            };

            AliceNoncePayload {
                enc_payload: encrypted_payload
            }
        };

        // send a request to address initiating the nonce exchange
        let _ = http_client.post(&format!("{}/challenge/receive_nonce", target_party_address))
            .header(X_PROXY_ADDR, proxy_addr)
            .header(X_PROTO_STATE_ID, state_id)
            .header(X_PROTO_STATE_SIG, state_sig)
            .body(serde_json::to_string(&nonce_exchange_payload).unwrap())
            .timeout(Duration::new(30, 0))
            .send()
            .await;
    });

    let response = create_empty_response(&state, StatusCode::OK);

    Ok((state, response))
}
