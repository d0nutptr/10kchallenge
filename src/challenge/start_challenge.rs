use futures::FutureExt;
use gotham::state::State;
use std::pin::Pin;
use gotham::handler::HandlerFuture;
use serde::{Serialize, Deserialize};
use shared_lib::{AsyncHandlerResponse, return_json, extract_json, return_generic_error};

pub fn start_challenge(mut state: State) -> Pin<Box<HandlerFuture>> {
    async fn start_challenge_impl(mut state: State) -> AsyncHandlerResponse {
        let challenge_request: StartChallengeRequest = match extract_json(&mut state).await {
            Some(challenge_request) => challenge_request,
            _ => {
                return Ok(return_generic_error(state));
            }
        };

        let response = return_json(&state, TestResponse{message: challenge_request.proxy_target});

        Ok((state, response))
    }

    start_challenge_impl(state).boxed()
}

#[derive(Serialize, Deserialize)]
pub struct StartChallengeRequest {
    pub target: ChallengeTarget,
    pub proxy_target: String
}

#[derive(Serialize, Deserialize)]
pub enum ChallengeTarget {
    Alice,
    Malice,
}

#[derive(Serialize, Deserialize)]
struct TestResponse {
    pub message: String,
}