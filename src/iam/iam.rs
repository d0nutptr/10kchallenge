#[macro_use]
extern crate gotham_derive;

use std::env;
use shared_lib::{RateLimitState, ServiceKeyState, InternalServiceMiddleware, RateLimitMiddleware, X_INTERNAL_AUTH_SECRET, PubKeyResponse};
use rand::rngs::OsRng;
use gotham::router::Router;
use gotham::pipeline::set::{new_pipeline_set, finalize_pipeline_set};
use gotham::pipeline::new_pipeline;
use gotham::middleware::state::StateMiddleware;
use gotham::router::builder::{build_router, DrawRoutes, DefineSingleRoute};
use crate::pubkey_reporting::{report_pubkey_alice, report_pubkey_bob, challenge_get_public_key};
use gotham::helpers::http::response::{create_empty_response, create_response};
use hyper::{StatusCode, Response, Body};
use gotham::state::State;
use crate::iam_state::IAMState;
use rsa::{RSAPublicKey, BigUint, RSAPrivateKey};

mod iam_state;
mod pubkey_reporting;

const ADDR_CHALLENGE: &str = "ADDR_CHALLENGE";
const CHALLENGE_INTERNAL_SECRET: &str = "CHALLENGE_INTERNAL_SECRET";

fn main() {
    let addr = "0.0.0.0:1338";

    println!("Starting IAM Service");

    let challenge_service_address = match env::var(ADDR_CHALLENGE) {
        Ok(addr) => addr,
        _ => {
            panic!("{} not set", ADDR_CHALLENGE)
        }
    };

    let mut csprng = OsRng{};

    let private_key = RSAPrivateKey::new(&mut csprng, 2048).unwrap();
    let public_key = private_key.to_public_key();
    let serivce_key_state = ServiceKeyState::new(public_key, private_key);

    let internal_auth_secret = match env::var(CHALLENGE_INTERNAL_SECRET) {
        Ok(val) => val,
        _ => panic!("You dumbass... you forgot to set the {} environment variable", CHALLENGE_INTERNAL_SECRET)
    };

    // FETCH CHALLENGE PUBLIC KEY
    let challenge_service_public_key = match fetch_challenge_public_key(internal_auth_secret.clone(), challenge_service_address) {
        Some(key) => key,
        None => panic!("Failed to fetch the challenge service public key for future signed messages.")
    };

    let rate_limit_state = RateLimitState::new();
    let iam_state = IAMState::new(challenge_service_public_key);

    println!("IAM Service Started");

    loop {
        println!("Starting gotham...");
        gotham::start(addr, iam_router(serivce_key_state.clone(), iam_state.clone(), internal_auth_secret.clone(), rate_limit_state.clone()))
    }
}

fn iam_router(service_key_state: ServiceKeyState, iam_state: IAMState, internal_service_secret: String, rate_limit_state: RateLimitState) -> Router {
    let pipelines = new_pipeline_set();

    let (pipelines, internal_pipeline) = pipelines.add(
        new_pipeline()
            .add(StateMiddleware::new(service_key_state.clone()))
            .add(StateMiddleware::new(iam_state.clone()))
            .add(InternalServiceMiddleware::new(internal_service_secret, true))
            .build()
    );

    let (pipelines, iam_pipeline) = pipelines.add(
        new_pipeline()
            .add(RateLimitMiddleware::new(rate_limit_state.clone()))
            .add(StateMiddleware::new(service_key_state.clone()))
            .add(StateMiddleware::new(iam_state.clone()))
            .build()
    );

    let pipeline_set = finalize_pipeline_set(pipelines);

    let internal_chain = (internal_pipeline, ());
    let iam_chain = (iam_pipeline, ());

    build_router(iam_chain, pipeline_set, |route| {
        route.get("/").to(index);

        route.scope("/challenge", |route| {
            route.post("/get_public_key").to(challenge_get_public_key)
        });

        route.with_pipeline_chain(internal_chain, |route| {
            route.scope("/__internal", |route| {
                route.scope("/report_pubkey", |route| {
                    route.post("/alice").to(report_pubkey_alice);
                    route.post("/bob").to(report_pubkey_bob);
                });
            });
        });
    })
}

fn index(state: State) -> (State, Response<Body>) {
    let response = create_response(
        &state,
        StatusCode::OK,
        mime::APPLICATION_OCTET_STREAM,
        Body::from("\u{01F41D} buzz off.")
    );

    (state, response)
}

fn fetch_challenge_public_key(internal_auth_secret: String, challenge_address: String) -> Option<RSAPublicKey> {
    let client = reqwest::blocking::Client::new();

    let mut response = client.get(&format!("{}/__internal/fetch_pubkey", challenge_address))
        .header(X_INTERNAL_AUTH_SECRET, internal_auth_secret)
        .send()
        .unwrap();

    let pubkey_response: PubKeyResponse = match response.json::<PubKeyResponse>() {
        Ok(result) => result,
        _ => return None
    };

    RSAPublicKey::new(BigUint::from_bytes_le(&pubkey_response.n), BigUint::from_bytes_le(&pubkey_response.e)).ok()
}
