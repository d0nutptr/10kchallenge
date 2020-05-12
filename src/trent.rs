#[macro_use]
extern crate gotham_derive;

use gotham::state::{State, FromState};
use gotham::router::Router;
use gotham::router::builder::{build_simple_router, DrawRoutes, DefineSingleRoute, build_router};
use crate::utils::{extract_json, AsyncHandlerResponse, return_json};
use crate::models::*;
use std::pin::Pin;
use gotham::handler::HandlerFuture;
use futures::FutureExt;
use hyper::{Body, StatusCode, Response};
use gotham::helpers::http::response::{create_response, create_empty_response};
use mime::Mime;
use std::str::FromStr;
use gotham::middleware::state::StateMiddleware;
use gotham::pipeline::single_middleware;
use gotham::pipeline::single::single_pipeline;
use crate::models::internal::InternalServicePubKeyReportingRequest;

mod models;
mod utils;

/// Is Steps 1-2, 4-5/6
/// {"client": "Alice", "remote": "Bob"} -> {"remote_pub_key": "<B64>", "remote": "Bob", "trent_sig": "<B64>"}
async fn get_pub_key_impl(mut state: State) -> AsyncHandlerResponse {
    let request = match extract_json::<GetPubKeyRequest>(&mut state).await {
        Some(data) => data,
        _ => {
            let response = create_response(
                &state,
                StatusCode::INTERNAL_SERVER_ERROR,
                mime::TEXT_PLAIN,
                Body::from("Error."));
            return Ok((state, response))
        }
    };

    let response = create_response(
        &state,
        StatusCode::OK,
        mime::TEXT_PLAIN,
        Body::from(request.client));
    return Ok((state, response))
}

async fn report_alice_pub_key_impl(mut state: State) -> AsyncHandlerResponse {
    let mut secrets = TrentServiceSecretState::take_from(&mut state);
    let request = match extract_json::<InternalServicePubKeyReportingRequest>(&mut state).await {
        Some(data) => data,
        _ => {
            let response = create_response(
                &state,
                StatusCode::INTERNAL_SERVER_ERROR,
                mime::TEXT_PLAIN,
                Body::from("Error."));
            return Ok((state, response))
        }
    };

    secrets.client_pub_keys.lock().unwrap().insert(String::from("Bob"), request.pub_key);

    let response = create_empty_response(&state, StatusCode::OK);
    Ok((state, response))
}

async fn report_bob_pub_key_impl(mut state: State) -> AsyncHandlerResponse {
    let mut secrets = TrentServiceSecretState::take_from(&mut state);
    let request = match extract_json::<InternalServicePubKeyReportingRequest>(&mut state).await {
        Some(data) => data,
        _ => {
            let response = create_response(
                &state,
                StatusCode::INTERNAL_SERVER_ERROR,
                mime::TEXT_PLAIN,
                Body::from("Error."));
            return Ok((state, response))
        }
    };

    secrets.client_pub_keys.lock().unwrap().insert(String::from("Bob"), request.pub_key);

    let response = create_empty_response(&state, StatusCode::OK);
    Ok((state, response))
}

fn get_pub_key(mut state: State) -> Pin<Box<HandlerFuture>> {
    get_pub_key_impl(state).boxed()
}

fn report_alice_pub_key(mut state: State) -> Pin<Box<HandlerFuture>> {
    report_alice_pub_key_impl(state).boxed()
}

fn report_bob_pub_key(mut state: State) -> Pin<Box<HandlerFuture>> {
    report_bob_pub_key_impl(state).boxed()
}

/// Trent's pub key
fn index(mut state: State) -> (State, Response<Body>) {
    let mut secrets = TrentServiceSecretState::take_from(&mut state);

    let pub_key: String = base64::encode(secrets.service_keypair.lock().unwrap().public.to_bytes());

    let pub_key_response = TrentPubKeyResponse {
        pub_key
    };

    let response = return_json(&state, pub_key_response);
    (state, response)
}

fn trent_router(service_secrets: TrentServiceSecretState) -> Router {
    let middleware = StateMiddleware::new(service_secrets);
    let pipeline = single_middleware(middleware);

    let (chain, pipelines) = single_pipeline(pipeline);

    build_router(chain, pipelines, |route| {
        route.get("/").to(index);
        route.scope("/challenge", |route| {
            route.post("/get_pub_key").to(get_pub_key);
        });
        route.scope("/_internal/h6789s3214oh87fsr78", |route| {
            route.post("/report_alice_pub_key").to(report_alice_pub_key);
            route.post("/report_bob_pub_key").to(report_bob_pub_key);
        });
    })
}

fn main() {
    /*
    0. Trent starts         (5001)
    1. Core Service starts  (5000)
    2. Alice start          (5002)
    3. Bob starts           (5003)
    4. Core Service reports its public key to Trent
    5. Alice reports her public key to Trent (Trent reports pub key back)
    6. Bob reports his public key to trent (Trent reports pub key back)
    7. User fills out input field with their proxy address
    8. User starts "Alice to Bob" communication (user -> core service message)
        1. Core service back channel messages Alice to begin with Proxy Settings and a target (signed by cs INTERNAL_PRIVATE)
        // comms now use proxy settings signed in header
        2. Alice -> (Proxy) -> Trent: Alice, Bob
        3. Trent -> (Proxy) -> Alice: S(T){Pub_b, Bob}
        4. Alice -> (Proxy) -> Bob: E(B){Nonce_A, Alice}
        5. Bob -> (Proxy) -> Trent: Bob, Alice
        6. Trent -> (Proxy) -> Bob: S(T){Pub_a, Alice}
        7. Bob -> (Proxy) -> Alice: E(A){Nonce_A, Nonce_B}
        8. Alice -> (Proxy) -> Bob: E(B){Nonce_B}
        9. Bob -> (Proxy) -> Alice: E(N_a/N_b){SECRET MESSAGE}
    9. User starts "Alice to Malice" communication (user -> core service message)
        1. Core service back channel messages Alice to begin with Proxy Settings and a target (signed by cs INTERNAL_PRIVATE)
        // comms now use proxy settings signed in header
        2. Alice -> (Proxy) -> Trent: Alice, Malice
        3. Trent -> (Proxy) -> Alice: S(T){Pub_m, Malice}
        4. Alice -> Malice: E(M){Nonce_A, Alice}
        (OPT) 5. Malice -> Trent: Malice, Alice
        6. Trent -> Malice: S(T){Pub_a, Alice}
        (OPT) 7. Malice -> Alice: E(A){Nonce_A, Nonce_M}
        8. Alice -> Malice: E(M){Nonce_M}
        (OPT) 9. Malice -> (Proxy) -> Alice: E(N_a/N_m){<CONTROLLED BY USER>}
    */


    let addr = "0.0.0.0:5001";
    println!("Starting TRENT");

    let service_secrets = TrentServiceSecretState::new();

    loop {
        gotham::start(addr, trent_router(service_secrets.clone()))
    }
}

