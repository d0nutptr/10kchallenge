use gotham::state::{State, FromState};
use std::pin::Pin;
use gotham::handler::HandlerFuture;
use futures::FutureExt;
use shared_lib::*;
use crate::ADDR_IAM;
use hyper::{HeaderMap, StatusCode};
use std::env;
use tokio::spawn;
use gotham::helpers::http::response::create_empty_response;
use reqwest::Proxy;
use std::time::Duration;
use std::any::TypeId;
use shared_lib::PartyState;

pub fn receive_nonce(state: State) -> Pin<Box<HandlerFuture>> {
    receive_nonce_async(state).boxed()
}

async fn receive_nonce_async(mut state: State) -> AsyncHandlerResponse {
    /*
        1. get current state (from state tracker)
        2. check we're in the good state (BobStates::Initial)
        3. extract the json
        4. decrypt the inner payload
        5. ask iam for the subject's public key
        6. record nonce_a, party, and party's public key into the state and update state to the listening for nonce
        7. ping party with nonce_b
     */
    let (state_id, state_sig, state_map) = match apply_state_gate(&state, PartyState::initial_id()) {
        Ok((state_id, state_sig, state_map, _)) => (state_id, state_sig, state_map),
        _ => return Ok(return_generic_error(state))
    };

    let proxy_addr = match HeaderMap::borrow_from(&state).get(X_PROXY_ADDR) {
        Some(addr) => addr.to_str().unwrap_or("").to_string(),
        _ => return Ok(return_generic_error(state))
    };

    let infra_state = InfraState::borrow_from(&state);
    let iam_public_key = {
        infra_state.iam_pub_key.lock().unwrap().clone().unwrap()
    };

    let alice_nonce_payload = match extract_and_decrypt_alice_payload(&mut state).await {
        Some(alice_nonce_payload) => alice_nonce_payload,
        _ => return Ok(return_generic_error(state))
    };

    spawn(async move {
        let proxy = match Proxy::http(&proxy_addr) {
            Ok(proxy) => proxy,
            _ => return
        };

        let mut http_client = match create_async_http_client(Some(proxy)) {
            Some(client) => client,
            None => return
        };

        let public_key_report = match get_publickey_from_iam(&mut http_client, iam_public_key, Participant::BOB, alice_nonce_payload.party).await {
            Ok(public_key_report) => public_key_report,
            _ => return
        };

        let target_party_public_key = match public_key_report.get_public_key() {
            Some(key) => key,
            _ => return
        };

        let nonce_a = alice_nonce_payload.nonce_a.clone();
        let nonce_b = generate_nonce();

        {
            let new_state = PartyState::AWAITING_NONCE {
                party_public_key: target_party_public_key.clone(),
                party: public_key_report.payload.subject.clone(),
                nonce_a: nonce_a.clone(),
                nonce_b: nonce_b.clone()
            };

            state_map.lock().unwrap().insert(state_id.clone(), new_state);
        }

        let target_party_address = match get_participant_address(public_key_report.payload.subject.clone()) {
            Some(address) => address,
            None => return
        };

        let nonce_exchange_payload = {
            let bob_nonce_payload = BobNoncePayloadInner {
                nonce_a,
                nonce_b
            };

            let nonce_payload_str = serde_json::to_string(&bob_nonce_payload).unwrap();

            let encrypted_payload = match target_party_public_key.smart_encrypt(nonce_payload_str.into_bytes()) {
                Some(payload) => payload.b64_encode(),
                _ => return
            };

            BobNoncePayload {
                enc_payload: encrypted_payload
            }
        };

        // send a request to address initiating the nonce exchange
        let _ = http_client.post(&format!("{}/challenge/verify_nonce", target_party_address))
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

async fn extract_and_decrypt_alice_payload(state: &mut State) -> Option<AliceNoncePayloadInner> {
    let alice_nonce_payload: AliceNoncePayload = {
        match extract_json(state).await {
            Some(request) => request,
            None => return None
        }
    };

    let service_state = ServiceKeyState::borrow_from(&state);
    match service_state.priv_key.smart_decrypt(alice_nonce_payload.enc_payload.b64_tolerant_decode())
        .map(|payload|serde_json::from_slice(&payload)) {
        Some(Ok(payload)) => payload,
        _ => None
    }
}