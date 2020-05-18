use std::pin::Pin;
use gotham::state::{State, FromState};
use shared_lib::{AsyncHandlerResponse, ChallengeInitiateRequest, extract_json, return_generic_error, StateTrackerState, PublicKeyInquiry, Participant, X_PROXY_ADDR, create_async_http_client, IAMPublicKeyReport, InfraState, AliceNoncePayloadInner, B64String, SmartRSAPublicKey, B64Vec, AliceNoncePayload, X_PROTO_STATE_ID, X_PROTO_STATE_SIG};
use gotham::handler::HandlerFuture;
use futures::FutureExt;
use std::borrow::BorrowMut;
use crate::{AliceStates, ADDR_IAM, ADDR_BOB};
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
    let state_tracker = StateTrackerState::<AliceStates>::borrow_from(&state);
    let infra_state = InfraState::borrow_from(&state);

    let state_id = state_tracker.get_current_state_id();
    let state_sig = state_tracker.get_current_state_signature();
    let mut alice_state_map = state_tracker.internal_states.clone();

    let current_state = {
        alice_state_map.lock().unwrap().get(&state_id).unwrap().clone()
    };

    let iam_public_key = {
        infra_state.iam_pub_key.lock().unwrap().clone().unwrap()
    };

    // enforce state is initial state
    match current_state {
        AliceStates::INITIAL => {},
        _ => return Ok(return_generic_error(state))
    };

    let challenge_initiate_request: ChallengeInitiateRequest = match extract_json(&mut state).await {
        Some(request) => request,
        None => return Ok(return_generic_error(state))
    };

    let iam_service_address = match env::var(ADDR_IAM) {
        Ok(addr) => addr,
        _ => panic!("{} not set", ADDR_IAM)
    };

    let public_key_inquiry_payload = PublicKeyInquiry {
        inquiring_party: Participant::ALICE,
        subject: challenge_initiate_request.participant
    };

    let proxy_addr = challenge_initiate_request.proxy_config;

    spawn(async move {
        let proxy = match Proxy::http(&proxy_addr) {
            Ok(proxy) => proxy,
            _ => return
        };

        let mut http_client = match create_async_http_client(Some(proxy)) {
            Some(client) => client,
            None => return
        };

        let iam_response = http_client.post(&format!("{}/challenge/get_public_key", iam_service_address))
            .body(serde_json::to_string(&public_key_inquiry_payload).unwrap())
            .timeout(Duration::new(15, 0))
            .send()
            .await;

        let iam_response = match iam_response {
            Ok(response) => response,
            _ => return
        };

        let pubkey_report: IAMPublicKeyReport = match iam_response.json::<IAMPublicKeyReport>().await {
            Ok(report) => report,
            _ => return
        };

        //validate signature
        let payload_str = serde_json::to_string(&pubkey_report.payload).unwrap_or("".to_string());
        let payload_signature = match base64::decode(pubkey_report.signature) {
            Ok(sig) => sig,
            _ => return
        };

        // verify the signature of the payload
        if !iam_public_key.smart_verify(payload_str.as_bytes().to_vec(), payload_signature) {
            return;
        }

        let address = match get_participant_address(pubkey_report.payload.subject.clone()) {
            Some(address) => address,
            None => return
        };

        let other_participant_pubkey = match RSAPublicKey::new(BigUint::from_bytes_le(&pubkey_report.payload.n.b64_tolerant_decode()), BigUint::from_bytes_le(&pubkey_report.payload.e.b64_tolerant_decode())) {
            Ok(key) => key,
            _ => return
        };

        let mut nonce_a = [0u8; 32];
        let mut rng = OsRng::default();
        rng.fill_bytes(&mut nonce_a);

        let nonce_a_str = base64::encode(nonce_a.to_vec());

        // set the state
        {
            let new_state = AliceStates::AWAITING_NONCE {
                party_public_key: other_participant_pubkey.clone(),
                party: pubkey_report.payload.subject,
                nonce_a: nonce_a_str.clone()
            };

            alice_state_map.lock().unwrap().insert(state_id.clone(), new_state);
        }

        let nonce_exchange_payload_inner = AliceNoncePayloadInner {
            nonce_a: nonce_a_str,
            party: Participant::ALICE
        };

        let nonce_payload_str = serde_json::to_string(&nonce_exchange_payload_inner).unwrap();

        let encrypted_payload = match other_participant_pubkey.smart_encrypt(nonce_payload_str.into_bytes()) {
            Some(payload) => payload.b64_encode(),
            _ => return
        };

        let nonce_exchange_payload = AliceNoncePayload {
            enc_payload: encrypted_payload
        };

        // send a request to address initiating the nonce exchange
        let bob_response = http_client.post(&format!("{}/challenge/receive_nonce", address))
            .header(X_PROXY_ADDR, proxy_addr)
            .header(X_PROTO_STATE_ID, state_id)
            .header(X_PROTO_STATE_SIG, state_sig)
            .body(serde_json::to_string(&nonce_exchange_payload).unwrap())
            .timeout(Duration::new(15, 0))
            .send()
            .await;
    });

    let response = create_empty_response(&state, StatusCode::OK);

    Ok((state, response))
}

fn get_participant_address(participant: Participant) -> Option<String> {
    match participant {
        Participant::EVE => {
            Some("http://example.com".to_string())
        },
        Participant::BOB => {
            match env::var(ADDR_BOB) {
                Ok(addr) => Some(addr),
                _ => panic!("{} not set", ADDR_BOB)
            }
        },
        Participant::ALICE => {
            Some("http://example.com".to_string())
        }
    }
}