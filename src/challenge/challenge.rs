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

mod start_challenge;

fn main() {
    let addr = "0.0.0.0:1337";

    println!("Starting Challenge Service");

    /*
    let iam_address = match env::var("IAM_ADDR") {
        Ok(addr) => addr,
        _ => {
            panic!("IAM_ADDR not set");
        }
    };

    let alice_address = match env::var("ALICE_ADDR") {
        Ok(addr) => addr,
        _ => {
            panic!("ALICE_ADDR not set")
        }
    };
     */
    let rate_limit_state = RateLimitState::new();

    loop {
        gotham::start(addr, challenge_router(rate_limit_state.clone()))
    }
}

/// Defines the routes that the challenge site will have
fn challenge_router(rate_limit_state: RateLimitState) -> Router {
    let (chain, pipelines) = single_pipeline(new_pipeline().add(RateLimitMiddleware::new(rate_limit_state)).build());

    build_router(chain, pipelines, |route| {
        route.get("/").to(index);
        route.post("/start_challenge").to(start_challenge::start_challenge)
    })
}

fn index(mut state: State) -> (State, Response<Body>) {
    let response = create_response(
        &state,
        StatusCode::OK,
        mime::TEXT_PLAIN,
        Body::from("hello, world.")
    );

    (state, response)
}
