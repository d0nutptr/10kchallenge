use gotham::state::{State, FromState};
use std::pin::Pin;
use gotham::handler::HandlerFuture;
use futures::FutureExt;
use shared_lib::{AsyncHandlerResponse, eve_key, Participant, return_generic_error, AliceAckPayloadInner, AliceAckPayload, extract_json, ServiceKeyState, B64String, SmartRSAPrivateKey, time_safe_comparison, SECRET_KEY_SIZE, create_async_http_client, X_PROXY_ADDR, BobSecretMessage, get_participant_address, X_PROTO_STATE_ID, X_PROTO_STATE_SIG, PartyState, apply_state_gate};
use std::env;
use sha2::digest::generic_array::GenericArray;
use rand::rngs::OsRng;
use chacha20poly1305::XChaCha20Poly1305;
use rand::RngCore;
use aead::{Aead, NewAead};
use reqwest::Proxy;
use hyper::{HeaderMap, StatusCode};
use std::time::Duration;
use gotham::helpers::http::response::create_empty_response;
use std::any::TypeId;

const SECRET_MESSAGE: &str = "SECRET_MESSAGE";

pub fn ack_nonce(state: State) -> Pin<Box<HandlerFuture>> {
    ack_nonce_async(state).boxed()
}

async fn ack_nonce_async(mut state: State) -> AsyncHandlerResponse {
    /*
        1. validate that we're in the pending nonce ack state
        2. extract and decrypt the payload
        3. validate that the nonces match up as expected (and are 16 bytes each)
        4. xor the nonces together
        5. encrypt the secret message (FROM ENV VARIABLE)
        6. set bob state to done
        7. send to party
     */

    let (state_id, state_sig, state_map, current_state) = match apply_state_gate(&state, PartyState::awaiting_nonce_id()) {
        Ok((state_id, state_sig, state_map, current_state)) => (state_id, state_sig, state_map, current_state),
        _ => return Ok(return_generic_error(state))
    };

    // grab body json
    let nonce_report_request = match extract_and_decrypt_alice_payload(&mut state).await {
        Some(request) => request,
        None => return Ok(return_generic_error(state))
    };

    let (target_party, nonce_a, nonce_b) = match current_state {
        PartyState::AWAITING_NONCE {
            party_public_key, party, nonce_a, nonce_b
        } => (party, nonce_a, nonce_b),
        _ => return Ok(return_generic_error(state))
    };

    // validate the nonce is expected
    if !validate_nonces(nonce_b.clone(), nonce_report_request.nonce_b.clone()) {
        return Ok(return_generic_error(state));
    }

    // validate nonce_a and nonce_b are SECRET_KEY_SIZE bytes
    if nonce_a.b64_tolerant_decode().len() != SECRET_KEY_SIZE || nonce_b.b64_tolerant_decode().len() != SECRET_KEY_SIZE {
        return Ok(return_generic_error(state));
    }

    let secret_message = get_message_for_participant(&target_party);

    let (cipher_text, nonce) = encrypt_secret_message(secret_message, nonce_a.clone(), nonce_b.clone());

    let proxy_addr = match HeaderMap::borrow_from(&state).get(X_PROXY_ADDR) {
        Some(addr) => addr.to_str().unwrap_or("").to_string(),
        _ => return Ok(return_generic_error(state))
    };

    tokio::spawn(async move {
        let proxy = match Proxy::http(&proxy_addr) {
            Ok(proxy) => proxy,
            _ => return
        };

        let mut http_client = match create_async_http_client(Some(proxy)) {
            Some(client) => client,
            None => return
        };

        let payload = BobSecretMessage {
            ciphertext: base64::encode(cipher_text),
            nonce: base64::encode(nonce)
        };

        let target_party_address = match get_participant_address(target_party) {
            Some(address) => address,
            None => return
        };

        let _ = http_client.post(&format!("{}/challenge/receive_secret_message", target_party_address))
            .header(X_PROXY_ADDR, proxy_addr)
            .header(X_PROTO_STATE_ID, state_id)
            .header(X_PROTO_STATE_SIG, state_sig)
            .body(serde_json::to_string(&payload).unwrap())
            .timeout(Duration::new(15, 0))
            .send()
            .await;
    });

    let response = create_empty_response(&state, StatusCode::OK);

    Ok((state, response))
}

fn get_message_for_participant(party: &Participant) -> String {
    match party {
        Participant::ALICE => {
            match env::var(SECRET_MESSAGE) {
                Ok(addr) => addr,
                _ => panic!("{} not set", SECRET_MESSAGE)
            }
        },
        Participant::BOB => {
            "nani?".to_string()
        },
        Participant::EVE => {
            "wait a minute.. you're not alice!!! NO SECRET 4 U".to_string()
        }
    }
}

async fn extract_and_decrypt_alice_payload(state: &mut State) -> Option<AliceAckPayloadInner> {
    let alice_nonce_payload: AliceAckPayload = {
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

fn validate_nonces(expected_nonce_b: String, provided_nonce_b: String) -> bool {
    let expected = expected_nonce_b.b64_tolerant_decode();
    let provided = expected_nonce_b.b64_tolerant_decode();

    time_safe_comparison(expected, provided)
}

fn create_encryption_key(nonce_a: String, nonce_b: String) -> Vec<u8> {
    let nonce_a_bytes = nonce_a.b64_tolerant_decode();
    let nonce_b_bytes = nonce_b.b64_tolerant_decode();

    nonce_a_bytes.into_iter().zip(nonce_b_bytes)
        .map(|(left_byte, right_byte)| {
            left_byte ^ right_byte
        }).collect()
}

/// returns (ciphertext, nonce)
fn encrypt_secret_message(secret_message: String, nonce_a: String, nonce_b: String) -> (Vec<u8>, Vec<u8>) {
    let enc_key = create_encryption_key(nonce_a, nonce_b);

    let encryption_key = GenericArray::clone_from_slice(&enc_key);
    let aead = XChaCha20Poly1305::new(encryption_key);
    let nonce = {
        let mut nonce = [0u8; 24];
        let mut rng = OsRng::default();
        rng.fill_bytes(&mut nonce);
        GenericArray::clone_from_slice(&nonce)
    };

    let ciphertext = aead.encrypt(&nonce, secret_message.into_bytes().as_ref()).expect("FAILED ENCRYPTION");

    (ciphertext, nonce.to_vec())
}

fn decrypt_secret_message(ciphertext: Vec<u8>, nonce: Vec<u8>, nonce_a: String, nonce_b: String) -> String {
    let enc_key = create_encryption_key(nonce_a, nonce_b);
    let encryption_key = GenericArray::clone_from_slice(&enc_key);
    let aead = XChaCha20Poly1305::new(encryption_key);
    let nonce = GenericArray::clone_from_slice(&nonce);

    String::from_utf8(aead.decrypt(&nonce, ciphertext.as_ref()).expect("FAILED ENCRYPTION")).unwrap()
}