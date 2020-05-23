use futures::FutureExt;
use gotham::state::{State, FromState};
use std::pin::Pin;
use gotham::handler::HandlerFuture;
use shared_lib::{AsyncHandlerResponse, return_generic_error, Participant, eve_key, BobNoncePayload, extract_json, BobNoncePayloadInner, ServiceKeyState, B64String, SmartRSAPrivateKey, time_safe_comparison, X_PROXY_ADDR, create_async_http_client, AliceNoncePayload, AliceAckPayloadInner, SmartRSAPublicKey, B64Vec, get_participant_address, X_PROTO_STATE_ID, X_PROTO_STATE_SIG, AliceAckPayload, PartyState, apply_state_gate};
use rsa::{RSAPublicKey, RSAPrivateKey, BigUint};
use hyper::{StatusCode, HeaderMap};
use gotham::helpers::http::response::create_empty_response;
use reqwest::Proxy;
use std::time::Duration;
use std::any::TypeId;

pub fn verify_nonce(state: State) -> Pin<Box<HandlerFuture>> {
    verify_nonce_async(state).boxed()
}

async fn verify_nonce_async(mut state: State) -> AsyncHandlerResponse {
    /*
        1. verify the state is "waiting for nonce"
        2. grab the payload and decrypt it
        3. verify nonce_a matches expected
        4. create payload and encrypt it with the stateful public key
        5. send back to the expected party based on the state
     */

    let (state_id, state_sig, state_map, current_state) = match apply_state_gate(&state, PartyState::awaiting_nonce_id()) {
        Ok((state_id, state_sig, state_map, current_state)) => (state_id, state_sig, state_map, current_state),
        _ => return Ok(return_generic_error(state))
    };

    // grab body json
    let nonce_report_request = match extract_and_decrypt_bob_payload(&mut state).await {
        Some(request) => request,
        None => return Ok(return_generic_error(state))
    };

    // gather the stateful elements
    let (party_public_key, target_party, known_nonce_a) = match current_state {
        PartyState::AWAITING_NONCE {
            party_public_key, party, nonce_a, nonce_b
        } => (party_public_key, party, nonce_a),
        // this should never happen because of the gate above; we have this here because rust tries to protect us unnecessarily
        _ => return Ok(return_generic_error(state))
    };

    // verify the nonce's match
    if !check_nonces_match(known_nonce_a, nonce_report_request.nonce_a.clone()) {
        // We failed the nonce check and some shenanigans are going on..
        return Ok(return_generic_error(state));
    }

    let proxy_addr = match HeaderMap::borrow_from(&state).get(X_PROXY_ADDR) {
        Some(addr) => addr.to_str().unwrap_or("").to_string(),
        _ => return Ok(return_generic_error(state))
    };


    // okay everything checks out; lets report back that we are good to go
    tokio::spawn(async move {
        let proxy = match Proxy::http(&proxy_addr) {
            Ok(proxy) => proxy,
            _ => return
        };

        let mut http_client = match create_async_http_client(Some(proxy)) {
            Some(client) => client,
            None => return
        };

        let alice_nonce_ack_payload: AliceAckPayload = {
            let inner = AliceAckPayloadInner {
                nonce_b: nonce_report_request.nonce_b
            };

            let inner_str = serde_json::to_string(&inner).unwrap();

            let encrypted_payload = match party_public_key.smart_encrypt(inner_str.into_bytes()) {
                Some(payload) => payload.b64_encode(),
                _ => return
            };

            AliceAckPayload {
                enc_payload: encrypted_payload
            }
        };

        let target_party_address = match get_participant_address(target_party) {
            Some(address) => address,
            None => return
        };

        // finish with updating alice to be done
        state_map.lock().unwrap().insert(state_id.clone(), PartyState::DONE);

        let _ = http_client.post(&format!("{}/challenge/ack_nonce", target_party_address))
            .header(X_PROXY_ADDR, proxy_addr)
            .header(X_PROTO_STATE_ID, state_id)
            .header(X_PROTO_STATE_SIG, state_sig)
            .body(serde_json::to_string(&alice_nonce_ack_payload).unwrap())
            .timeout(Duration::new(30, 0))
            .send()
            .await;
    });

    let response = create_empty_response(&state, StatusCode::OK);

    Ok((state, response))
}

fn check_nonces_match(expected_nonce_a: String, provided_nonce_a: String) -> bool {
    let expected = expected_nonce_a.b64_tolerant_decode();
    let provided = provided_nonce_a.b64_tolerant_decode();

    time_safe_comparison(expected, provided)
}


async fn extract_and_decrypt_bob_payload(state: &mut State) -> Option<BobNoncePayloadInner> {
    let bob_nonce_payload: BobNoncePayload = {
        match extract_json(state).await {
            Some(request) => request,
            None => return None
        }
    };

    let service_state = ServiceKeyState::borrow_from(&state);
    match service_state.priv_key.smart_decrypt(bob_nonce_payload.enc_payload.b64_tolerant_decode())
        .map(|payload|serde_json::from_slice(&payload)) {
        Some(Ok(payload)) => payload,
        _ => None
    }
}