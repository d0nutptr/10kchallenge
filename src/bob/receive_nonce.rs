use gotham::state::{State, FromState};
use std::pin::Pin;
use gotham::handler::HandlerFuture;
use futures::FutureExt;
use shared_lib::{AsyncHandlerResponse, StateTrackerState, InfraState, return_generic_error, X_PROXY_ADDR, Participant, PublicKeyInquiry, extract_json, AliceNoncePayload, B64String, ServiceKeyState, SmartRSAPrivateKey, AliceNoncePayloadInner};
use crate::{BobStates, ADDR_IAM};
use hyper::HeaderMap;
use std::env;

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
    let state_tracker = StateTrackerState::<BobStates>::borrow_from(&state);
    let infra_state = InfraState::borrow_from(&state);

    let state_id = state_tracker.get_current_state_id();
    let state_sig = state_tracker.get_current_state_signature();
    let mut bob_state_map = state_tracker.internal_states.clone();

    let current_state = {
        bob_state_map.lock().unwrap().get(&state_id).unwrap().clone()
    };

    let iam_public_key = {
        infra_state.iam_pub_key.lock().unwrap().clone().unwrap()
    };

    // enforce state is initial state
    match current_state {
        BobStates::INITIAL => {},
        _ => return Ok(return_generic_error(state))
    };

    let alice_nonce_payload: AliceNoncePayload = {
        match extract_json(&mut state).await {
            Some(request) => request,
            None => return Ok(return_generic_error(state))
        }
    };

    let service_state = ServiceKeyState::borrow_from(&state);

    let alice_nonce_payload_inner: AliceNoncePayloadInner = match service_state.priv_key.smart_decrypt(alice_nonce_payload.enc_payload.b64_tolerant_decode())
        .map(|payload|serde_json::from_slice(&payload)) {
        Some(Ok(payload)) => payload,
        _ => return Ok(return_generic_error(state))
    };

    let nonce_a = alice_nonce_payload_inner.nonce_a;

    let public_key_inquiry_payload = PublicKeyInquiry {
        inquiring_party: Participant::BOB,
        subject: alice_nonce_payload_inner.party
    };

    let iam_service_address = match env::var(ADDR_IAM) {
        Ok(addr) => addr,
        _ => panic!("{} not set", ADDR_IAM)
    };

    let proxy_addr = match HeaderMap::borrow_from(&state).get(X_PROXY_ADDR) {
        Some(addr) => addr.to_str().unwrap_or("").to_string(),
        _ => return Ok(return_generic_error(state))
    };


    unimplemented!()
}