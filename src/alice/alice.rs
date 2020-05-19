use std::env;
use shared_lib::{RateLimitState, ServiceKeyState, X_INTERNAL_AUTH_SECRET, InternalServiceMiddleware, RateLimitMiddleware, fetch_challenge_public_key, report_service_public_key, Participant, InfraState, ChallengeState, ChallengeStateTrackerMiddleware, StateTrackerState, get_current_state};
use gotham::router::Router;
use gotham::pipeline::set::{new_pipeline_set, finalize_pipeline_set};
use gotham::pipeline::new_pipeline;
use gotham::middleware::state::StateMiddleware;
use gotham::router::builder::{build_router, DrawRoutes, DefineSingleRoute};
use rand::rngs::OsRng;
use gotham::state::State;
use hyper::{Response, Body, StatusCode};
use gotham::helpers::http::response::create_response;
use rsa::{RSAPrivateKey, RSAPublicKey};
use std::sync::{Mutex, Arc};
use std::collections::HashMap;

mod initiate_auth_protocol;
mod nonce_verification;

const ADDR_CHALLENGE: &str = "ADDR_CHALLENGE";
const ADDR_IAM: &str = "ADDR_IAM";
const ADDR_BOB: &str = "ADDR_BOB";
const CHALLENGE_INTERNAL_SECRET: &str = "CHALLENGE_INTERNAL_SECRET";

fn main() {
    let addr = "0.0.0.0:1339";

    println!("Starting ALICE Service");

    let challenge_service_address = match env::var(ADDR_CHALLENGE) {
        Ok(addr) => addr,
        _ => panic!("{} not set", ADDR_CHALLENGE)
    };

    let iam_service_address = match env::var(ADDR_IAM) {
        Ok(addr) => addr,
        _ => panic!("{} not set", ADDR_IAM)
    };

    let _ = match env::var(ADDR_BOB) {
        Ok(addr) => addr,
        _ => panic!("{} not set", ADDR_BOB)
    };

    let internal_service_secret = match env::var(CHALLENGE_INTERNAL_SECRET) {
        Ok(val) => val,
        _ => panic!("You dumbass... you forgot to set the {} environment variable", CHALLENGE_INTERNAL_SECRET)
    };

    let mut csprng = OsRng{};
    let private_key = RSAPrivateKey::new(&mut csprng, 2048).unwrap();
    let public_key = private_key.to_public_key();
    let service_key_state = ServiceKeyState::new(public_key, private_key);

    let rate_limit_state = RateLimitState::new();

    // FETCH CHALLENGE PUBLIC KEY
    let challenge_service_public_key = match fetch_challenge_public_key(&internal_service_secret, challenge_service_address) {
        Some(key) => key,
        None => panic!("Failed to fetch the challenge service public key for future signed messages.")
    };

    let iam_service_public_key = match report_service_public_key(
        &internal_service_secret,
        &iam_service_address,
        Participant::ALICE,
        service_key_state.pub_key.clone()) {
        Some(pub_key) => pub_key,
        None => panic!("Failed to report our public key and fetch the iam public key")
    };

    let challenge_state: StateTrackerState<AliceStates> = StateTrackerState::new("Alice".to_string(), challenge_service_public_key.clone());

    let infra_state = InfraState::new(challenge_service_public_key, iam_service_public_key);

    println!("Alice service started");

    loop {
        println!("Gotham service started...");
        gotham::start(addr, alice_router(
            internal_service_secret.clone(),
            challenge_state.clone(),
            service_key_state.clone(),
            infra_state.clone(),
            rate_limit_state.clone()));
    }
}

fn alice_router(internal_service_secret: String, challenge_state: StateTrackerState<AliceStates>, service_key_state: ServiceKeyState, infra_state: InfraState, rate_limit_state: RateLimitState) -> Router {
    let pipelines = new_pipeline_set();

    let (pipelines, internal_pipeline) = pipelines.add(
        new_pipeline()
            .add(InternalServiceMiddleware::new(internal_service_secret, true))
            .add(StateMiddleware::new(service_key_state.clone()))
            .add(ChallengeStateTrackerMiddleware::new(challenge_state.clone()))
            .add(StateMiddleware::new(infra_state.clone()))
            .build()
    );

    let (pipelines, alice_pipeline) = pipelines.add(
        new_pipeline()
            //.add(RateLimitMiddleware::new(rate_limit_state.clone()))
            .add(ChallengeStateTrackerMiddleware::new(challenge_state.clone()))
            .add(StateMiddleware::new(service_key_state.clone()))
            .add(StateMiddleware::new(infra_state.clone()))
            .build()
    );

    let pipeline_set = finalize_pipeline_set(pipelines);

    let internal_chain = (internal_pipeline, ());
    let iam_chain = (alice_pipeline, ());

    build_router(iam_chain, pipeline_set, |route| {
        route.get("/").to(index);

        route.scope("/challenge", |route| {
            route.post("/verify_nonce").to(nonce_verification::verify_nonce);
        });

        route.with_pipeline_chain(internal_chain, |route| {
            route.scope("/__internal", |route| {
                // todo: do the thing, kronk
                route.post("initiate_auth_protocol").to(initiate_auth_protocol::initiate_auth_protocol);
            });
        });
    })
}

fn index(state: State) -> (State, Response<Body>) {
    let response = create_response(
        &state,
        StatusCode::OK,
        mime::APPLICATION_OCTET_STREAM,
        Body::from("buzz off.")
    );

    (state, response)
}

#[derive(Clone, PartialEq)]
pub enum AliceStates {
    INITIAL,
    AWAITING_NONCE {
        party_public_key: RSAPublicKey,
        party: Participant,
        nonce_a: String,
    },
    DONE
}

impl ChallengeState for AliceStates {
    fn default_state() -> Self {
        AliceStates::INITIAL
    }
}

pub fn apply_state_gate_alice(state: &State, ideal_state: AliceStates) -> Result<(String, String, Arc<Mutex<HashMap<String, AliceStates>>>, AliceStates), ()> {
    let (state_id, state_sig, state_map, current_state) = get_current_state::<AliceStates>(state);

    match (&current_state, ideal_state) {
        (AliceStates::INITIAL, AliceStates::INITIAL)
        | (AliceStates::DONE, AliceStates::DONE)
        | (AliceStates::AWAITING_NONCE { .. }, AliceStates::AWAITING_NONCE { .. }) => {
            Ok((state_id, state_sig, state_map, current_state))
        },
        _ => Err(())
    }
}