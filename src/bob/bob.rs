use std::env;
use rsa::{RSAPrivateKey, RSAPublicKey};
use shared_lib::{ServiceKeyState, RateLimitState, fetch_challenge_public_key, report_service_public_key, Participant, StateTrackerState, InfraState, InternalServiceMiddleware, ChallengeStateTrackerMiddleware, RateLimitMiddleware, ChallengeState};
use gotham::pipeline::set::{new_pipeline_set, finalize_pipeline_set};
use gotham::pipeline::new_pipeline;
use gotham::middleware::state::StateMiddleware;
use gotham::router::builder::{build_router, DrawRoutes, DefineSingleRoute};
use gotham::helpers::http::response::create_empty_response;
use gotham::state::State;
use hyper::{Response, Body, StatusCode};
use rand::rngs::OsRng;
use gotham::router::Router;

mod receive_nonce;

const ADDR_CHALLENGE: &str = "ADDR_CHALLENGE";
const ADDR_IAM: &str = "ADDR_IAM";
const ADDR_BOB: &str = "ADDR_BOB";
const CHALLENGE_INTERNAL_SECRET: &str = "CHALLENGE_INTERNAL_SECRET";

fn main() {
    let addr = "0.0.0.0:1340";

    println!("Starting BOB Service");

    let challenge_service_address = match env::var(ADDR_CHALLENGE) {
        Ok(addr) => addr,
        _ => panic!("{} not set", ADDR_CHALLENGE)
    };

    let iam_service_address = match env::var(ADDR_IAM) {
        Ok(addr) => addr,
        _ => panic!("{} not set", ADDR_IAM)
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
        Participant::BOB,
        service_key_state.pub_key.clone()) {
        Some(pub_key) => pub_key,
        None => panic!("Failed to report our public key and fetch the iam public key")
    };

    let challenge_state: StateTrackerState<BobStates> = StateTrackerState::new("Bob".to_string(), challenge_service_public_key.clone());

    let infra_state = InfraState::new(challenge_service_public_key, iam_service_public_key);

    println!("Bob service started");

    loop {
        println!("Gotham service started...");
        gotham::start(addr, bob_router(
            internal_service_secret.clone(),
            challenge_state.clone(),
            service_key_state.clone(),
            infra_state.clone(),
            rate_limit_state.clone()));
    }
}

fn bob_router(internal_service_secret: String, challenge_state: StateTrackerState<BobStates>, service_key_state: ServiceKeyState, infra_state: InfraState, rate_limit_state: RateLimitState) -> Router {
    let pipelines = new_pipeline_set();

    let (pipelines, alice_pipeline) = pipelines.add(
        new_pipeline()
            .add(RateLimitMiddleware::new(rate_limit_state.clone()))
            .add(ChallengeStateTrackerMiddleware::new(challenge_state.clone()))
            .add(StateMiddleware::new(service_key_state.clone()))
            .add(StateMiddleware::new(infra_state.clone()))
            .build()
    );

    let pipeline_set = finalize_pipeline_set(pipelines);

    let iam_chain = (alice_pipeline, ());

    build_router(iam_chain, pipeline_set, |route| {
        route.get("/").to(index);

        route.scope("/challenge", |route| {
            route.post("/receive_nonce").to(index)
        });
    })
}

fn index(state: State) -> (State, Response<Body>) {
    let response = create_empty_response(&state, StatusCode::OK);

    (state, response)
}

#[derive(Clone)]
pub enum BobStates {
    INITIAL,
    AWAITING_NONCE {
        party_public_key: RSAPublicKey,
        party: Participant,
        nonce_a: String,
        nonce_b: String,
    },
    DONE
}

impl ChallengeState for BobStates {
    fn default_state() -> Self {
        BobStates::INITIAL
    }
}