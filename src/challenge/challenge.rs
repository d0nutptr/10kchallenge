#[macro_use]
extern crate gotham_derive;

use std::env;
use std::env::var;
use gotham::router::Router;

use shared_lib::*;
use gotham::pipeline::single::single_pipeline;
use gotham::pipeline::new_pipeline;
use gotham::router::builder::{build_router, DrawRoutes, DefineSingleRoute};
use gotham::state::State;
use hyper::{Response, Body, StatusCode};
use gotham::helpers::http::response::create_response;
use std::pin::Pin;
use gotham::handler::HandlerFuture;
use futures::FutureExt;
use futures::future::ok;
use gotham::pipeline::set::{new_pipeline_set, finalize_pipeline_set};
use gotham::middleware::state::StateMiddleware;

use rand::rngs::OsRng;
use crate::pubkey_reporting::fetch_pubkey;
use shared_lib::ServiceKeyState;
use rsa::{RSAPrivateKey, PublicKey};
use gotham::handler::assets::FileOptions;

mod start_challenge;
mod pubkey_reporting;

const ADDR_ALICE: &str = "ADDR_ALICE";
const CHALLENGE_INTERNAL_SECRET: &str = "CHALLENGE_INTERNAL_SECRET";

fn main() {
    let addr = "0.0.0.0:1337";

    println!("Starting Challenge Service");

    let _ = match env::var(ADDR_ALICE) {
        Ok(addr) => addr,
        _ => {
            panic!("ADDR_ALICE not set")
        }
    };

    let mut csprng = OsRng{};

    let private_key = RSAPrivateKey::new(&mut csprng, 2048).unwrap();
    let public_key = private_key.to_public_key();
    let service_key_state = ServiceKeyState::new(public_key, private_key);

    let internal_service_secret = match env::var(CHALLENGE_INTERNAL_SECRET) {
        Ok(val) => val,
        _ => panic!("You dumbass... you forgot to set the {} environment variable", CHALLENGE_INTERNAL_SECRET)
    };

    let rate_limit_state = RateLimitState::new();

    println!("Challenge Service Started");

    loop {
        println!("Starting gotham...");
        gotham::start(addr, challenge_router(service_key_state.clone(), internal_service_secret.clone(), rate_limit_state.clone()))
    }
}

/// Defines the routes that the challenge site will have
fn challenge_router(service_key_state: ServiceKeyState, internal_service_secret: String, rate_limit_state: RateLimitState) -> Router {
    let pipelines = new_pipeline_set();

    let (pipelines, internal_pipeline) = pipelines.add(
        new_pipeline()
            .add(InternalServiceMiddleware::new(internal_service_secret.clone(), true))
            .add(StateMiddleware::new(service_key_state.clone()))
            .build()
    );

    let (pipelines, challenge_pipeline) = pipelines.add(
        new_pipeline()
            .add(InternalServiceMiddleware::new(internal_service_secret, false))
            .add(RateLimitMiddleware::new(rate_limit_state.clone()))
            .add(StateMiddleware::new(service_key_state.clone()))
            .build()
    );

    let pipeline_set = finalize_pipeline_set(pipelines);

    let internal_chain = (internal_pipeline, ());
    let challenge_chain = (challenge_pipeline, ());

    build_router(challenge_chain, pipeline_set, |route| {
        route.get("/").to_file("assets/index.html");
        route.get("/robots.txt").to_file("assets/robots.txt");
        route.get("/favicon.ico").to_file("assets/favicon.ico");
        route.get("/static/*").to_dir(FileOptions::from("assets/static/").build());
        route.post("/start_challenge").to(start_challenge::start_challenge);

        route.with_pipeline_chain(internal_chain, |route| {
            route.scope("/__internal", |route| {
                route.get("/fetch_pubkey").to(fetch_pubkey);
            });
        });
    })
}

fn index(mut state: State) -> (State, Response<Body>) {
    // todo: Load the challenge homepage
    let response = create_response(
        &state,
        StatusCode::OK,
        mime::TEXT_PLAIN,
        Body::from("hello, world.")
    );

    (state, response)
}