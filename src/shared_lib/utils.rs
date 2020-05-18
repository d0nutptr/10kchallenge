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
use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;
use tokio::time::Duration;
use crate::Participant;
use rsa::{RSAPrivateKey, PaddingScheme, RSAPublicKey, PublicKey};
use sha2::{Sha256, Digest};
use rsa::hash::Hashes;
use rand::rngs::OsRng;

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
        base64::decode(self).unwrap_or(vec![])
    }
}