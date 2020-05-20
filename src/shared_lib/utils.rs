use hyper::{Body, Response};
use gotham::state::{State, FromState};
use std::future::Future;
use serde::Serialize;
use hyper::StatusCode;
use hyper::body::to_bytes;
use gotham::helpers::http::response::create_response;
use futures::{TryFutureExt, FutureExt};
use reqwest::{Client, Proxy};
use reqwest::redirect::Policy;
use rand::{Rng, thread_rng, RngCore};
use rand::distributions::Alphanumeric;
use tokio::time::Duration;
use crate::{Participant, ChallengeState, StateTrackerState, PublicKeyInquiry, IAMPublicKeyReport, InfraState};
use rsa::{RSAPrivateKey, PaddingScheme, RSAPublicKey, PublicKey};
use sha2::{Sha256, Digest};
use rsa::hash::Hashes;
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::env;

const ADDR_IAM: &str = "ADDR_IAM";
const ADDR_BOB: &str = "ADDR_BOB";
const ADDR_ALICE: &str = "ADDR_ALICE";
pub const SECRET_KEY_SIZE: usize = 32;

// https://github.com/gotham-rs/gotham/issues/351#issuecomment-525527301
pub fn extract_json<T>(state: &mut State) -> impl Future<Output = Option<T>>
    where
        T: serde::de::DeserializeOwned,
{
    let body = Body::take_from(state);

    to_bytes(body)
        .map_ok(|data| {
            serde_json::from_slice(&data[..]).ok()
        })
        .map(|result| match result {
            Ok(inner) => inner,
            _ => None
        })
}

pub fn return_json<T>(state: &State, obj: T) -> Response<Body>
    where T: Serialize
{
    create_response(
        &state,
        StatusCode::OK,
        mime::APPLICATION_JSON,
        serde_json::to_vec(&obj).expect("Failed to return pub key")
    )
}

pub fn return_generic_error(state: State) -> (State, Response<Body>) {
    let response = create_response(
        &state,
        StatusCode::INTERNAL_SERVER_ERROR,
        mime::APPLICATION_OCTET_STREAM,
        Body::from("An error occurred.")
    );

    (state, response)
}

pub fn create_async_http_client(proxy: Option<Proxy>) -> Option<Client> {
    let mut builder = reqwest::Client::builder();

    builder = match proxy {
        Some(proxy) => {
            builder.proxy(proxy)
        },
        None => builder
    };

    builder.redirect(Policy::none())
        .timeout(Duration::new(15, 0))
        .build()
        .ok()
}

pub fn generate_random_string(len: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .collect()
}

pub trait SmartRSAPrivateKey {
    fn smart_sign(&self, message: Vec<u8>) -> Option<Vec<u8>>;
    fn smart_decrypt(&self, message: Vec<u8>) -> Option<Vec<u8>>;
}

impl SmartRSAPrivateKey for RSAPrivateKey {
    fn smart_sign(&self, message: Vec<u8>) -> Option<Vec<u8>> {
        let mut hasher = Sha256::new();
        hasher.input(&message);
        self.sign(PaddingScheme::PKCS1v15, Some(&Hashes::SHA2_256), &hasher.result().to_vec()).ok()
    }

    fn smart_decrypt(&self, ciphertext: Vec<u8>) -> Option<Vec<u8>> {
        self.decrypt(PaddingScheme::PKCS1v15, &ciphertext).ok()
    }
}

pub trait SmartRSAPublicKey {
    fn smart_verify(&self, message: Vec<u8>, signature: Vec<u8>) -> bool;
    fn smart_encrypt(&self, message: Vec<u8>) -> Option<Vec<u8>>;
}

impl SmartRSAPublicKey for RSAPublicKey {
    fn smart_verify(&self, message: Vec<u8>, signature: Vec<u8>) -> bool {
        let mut hasher = Sha256::new();
        hasher.input(&message);
        self.verify(PaddingScheme::PKCS1v15, Some(&Hashes::SHA2_256), &hasher.result().to_vec(), &signature).is_ok()
    }

    fn smart_encrypt(&self, message: Vec<u8>) -> Option<Vec<u8>> {
        let mut rng = OsRng::default();
        self.encrypt(&mut rng, PaddingScheme::PKCS1v15, &message).ok()
    }
}

pub fn time_safe_comparison(left: Vec<u8>, right: Vec<u8>) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut tracker_value: u8 = 0;

    for (left_value, right_value) in left.iter().zip(right) {
        tracker_value |= left_value ^ right_value;
    }

    tracker_value == 0
}

pub trait B64Vec {
    fn b64_encode(&self) -> String;
}

impl B64Vec for Vec<u8> {
    fn b64_encode(&self) -> String {
        base64::encode(self)
    }
}

pub trait B64String {
    fn b64_tolerant_decode(&self) -> Vec<u8>;
}

impl B64String for String {
    fn b64_tolerant_decode(&self) -> Vec<u8> {
        base64::decode(self.trim()).unwrap_or(vec![])
    }
}

pub fn get_current_state<S>(state: &State) -> (String, String, Arc<Mutex<HashMap<String, S>>>, S) where
    S: ChallengeState + 'static
{
    let state_tracker: &StateTrackerState<S> = StateTrackerState::borrow_from(state);
    let state_id = state_tracker.get_current_state_id();
    let state_sig = state_tracker.get_current_state_signature();
    let state_map = state_tracker.internal_states.clone();

    let current_state = state_map.lock().unwrap().get(&state_id).unwrap().clone();

    (state_id, state_sig, state_map, current_state)
}

pub async fn get_publickey_from_iam(http_client: &mut Client, iam_public_key: RSAPublicKey, inquiring_party: Participant, subject: Participant) -> Result<IAMPublicKeyReport, ()> {
    let iam_service_address = match env::var(ADDR_IAM) {
        Ok(addr) => addr,
        _ => panic!("{} not set", ADDR_IAM)
    };

    // craft payload for request to iam
    let public_key_inquiry_payload = PublicKeyInquiry {
        inquiring_party,
        subject
    };

    let iam_response = http_client.post(&format!("{}/challenge/get_public_key", iam_service_address))
        .body(serde_json::to_string(&public_key_inquiry_payload).unwrap())
        .timeout(Duration::new(30, 0))
        .send()
        .await;

    let iam_response = match iam_response {
        Ok(response) => response,
        _ => return Err(())
    };

    let pubkey_report: IAMPublicKeyReport = match iam_response.json::<IAMPublicKeyReport>().await {
        Ok(report) => report,
        _ => return Err(())
    };

    //validate signature
    let payload_str = serde_json::to_string(&pubkey_report.payload).unwrap_or("".to_string());
    let payload_signature = match base64::decode(pubkey_report.signature.clone()) {
        Ok(sig) => sig,
        _ => return Err(())
    };

    // verify the signature of the payload
    if !iam_public_key.smart_verify(payload_str.as_bytes().to_vec(), payload_signature) {
        return Err(());
    }

    Ok(pubkey_report)
}

pub fn generate_nonce() -> String {
    let mut nonce_a = [0u8; SECRET_KEY_SIZE];
    let mut rng = OsRng::default();
    rng.fill_bytes(&mut nonce_a);

    base64::encode(nonce_a.to_vec())
}

pub fn get_participant_address(participant: Participant) -> Option<String> {
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
            match env::var(ADDR_ALICE) {
                Ok(addr) => Some(addr),
                _ => panic!("{} not set", ADDR_ALICE)
            }
        }
    }
}