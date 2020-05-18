use futures::FutureExt;
use gotham::handler::HandlerFuture;
use std::pin::Pin;
use shared_lib::{AsyncHandlerResponse, extract_json, PubKeyReport, return_json, PubKeyResponse, ServiceKeyState, PublicKeyInquiry, return_generic_error, Participant, eve_key, IAMPublicKeyReportSecure, IAMPublicKeyReport, B64Vec};
use gotham::hyper::StatusCode;
use gotham::state::{State, FromState};
use gotham::helpers::http::response::{create_empty_response, create_response};
use futures::future::ok;
use crate::iam_state::{ServiceIdentity, IAMState};
use gotham::hyper::Body;
use rand::rngs::OsRng;
use rsa::{RSAPublicKey, BigUint, PublicKey};

pub fn report_pubkey_alice(state: State) -> Pin<Box<HandlerFuture>> {
    report_pubkey(state, ServiceIdentity::ALICE).boxed()
}

pub fn report_pubkey_bob(state: State) -> Pin<Box<HandlerFuture>> {
    report_pubkey(state, ServiceIdentity::BOB).boxed()
}

async fn report_pubkey(mut state: State, service_identity: ServiceIdentity) -> AsyncHandlerResponse {
    // get the json from the request
    let json_body = match extract_json::<PubKeyReport>(&mut state).await {
        Some(key) => key,
        None => return Ok(return_generic_error(state))
    };

    let reported_public_key = match RSAPublicKey::new(BigUint::from_bytes_le(&json_body.n), BigUint::from_bytes_le(&json_body.e)) {
        Ok(key) => key,
        _ => return Ok(return_generic_error(state))
    };

    let iam_state = IAMState::borrow_from(&state);

    // set the public key to the appropriate service member (ALICE or BOB)
    match service_identity {
        ServiceIdentity::ALICE => iam_state.alice_pub_key.lock().unwrap().replace(reported_public_key),
        ServiceIdentity::BOB => iam_state.bob_pub_key.lock().unwrap().replace(reported_public_key)
    };

    // get the IAM public key from the PublicKeyState
    let pub_key_state = ServiceKeyState::borrow_from(&state);

    // create a public key response for serialization
    let iam_pub_key = PubKeyResponse {
        n: pub_key_state.pub_key.n().to_bytes_le(),
        e: pub_key_state.pub_key.e().to_bytes_le()
    };

    let response = return_json(&state, iam_pub_key);

    Ok((state, response))
}

/// fetches bob or alice's public key
pub fn challenge_get_public_key(state: State) -> Pin<Box<HandlerFuture>> {
    challenge_get_public_key_async(state).boxed()
}

async fn challenge_get_public_key_async(mut state: State) -> AsyncHandlerResponse {
    // 1. get the json body
    // 2. identify the public key to return from the participant
    // 3. just respond with the public key

    let json_body: PublicKeyInquiry = match extract_json::<PublicKeyInquiry>(&mut state).await {
        Some(json_body) => json_body,
        _ => return Ok(return_generic_error(state))
    };

    let public_key_state = ServiceKeyState::borrow_from(&state);
    // pull iamstate out to read public keys
    let iam_state = IAMState::borrow_from(&state);

    let public_key_to_report = match json_body.subject {
        Participant::ALICE => {
            iam_state.alice_pub_key.lock().unwrap().as_ref().unwrap().clone()
        },
        Participant::BOB => {
            iam_state.bob_pub_key.lock().unwrap().as_ref().unwrap().clone()
        },
        Participant::EVE => eve_key().0
    };

    let payload = IAMPublicKeyReportSecure {
        n: public_key_to_report.n().to_bytes_le().b64_encode(),
        e: public_key_to_report.e().to_bytes_le().b64_encode(),
        subject: json_body.subject,
    };

    let signature = match public_key_state.sign_message(&payload) {
        Some(signature) => base64::encode(signature),
        None => return Ok(return_generic_error(state))
    };

    let signed_payload = IAMPublicKeyReport {
        payload,
        signature
    };

    let response = return_json(&state, signed_payload);

    Ok((state, response))
}