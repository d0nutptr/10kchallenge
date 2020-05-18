use futures::FutureExt;
use gotham::state::{State, FromState};
use std::pin::Pin;
use gotham::handler::HandlerFuture;
use serde::{Serialize, Deserialize};
use shared_lib::{AsyncHandlerResponse, return_json, extract_json, return_generic_error, ChallengeInitiateRequest, create_async_http_client, X_PROXY_ADDR, X_INTERNAL_AUTH_SECRET, InternalServiceMiddleware, InternalServiceSecretState, generate_random_string, StateTrackerState, ServiceKeyState, X_PROTO_STATE_ID, X_PROTO_STATE_SIG, SmartRSAPrivateKey, B64Vec};
use reqwest::redirect::Policy;
use std::env;
use tokio::spawn;
use crate::ADDR_ALICE;
use gotham::hyper::StatusCode;
use gotham::helpers::http::response::create_empty_response;
use rsa::PaddingScheme;
use rsa::hash::Hashes;

pub fn start_challenge(mut state: State) -> Pin<Box<HandlerFuture>> {
    async fn start_challenge_impl(mut state: State) -> AsyncHandlerResponse {
        let challenge_request: ChallengeInitiateRequest = match extract_json(&mut state).await {
            Some(challenge_request) => challenge_request,
            _ => return Ok(return_generic_error(state))
        };

        let state_tracker_state = ServiceKeyState::borrow_from(&state);

        let alice_addr = match env::var(ADDR_ALICE) {
            Ok(addr) => addr,
            _ => {
                panic!("ADDR_ALICE not set")
            }
        };

        let secret_state = InternalServiceSecretState::borrow_from(&state);
        let internal_auth_secret = secret_state.get_secret_as_b64();

        let state_id = generate_random_string(32);
        let state_id_signature = match state_tracker_state.priv_key.smart_sign(state_id.as_bytes().to_vec()) {
            Some(signature) => signature.b64_encode(),
            None => return Ok(return_generic_error(state))
        };

        spawn(async move {
            let client = match create_async_http_client(None) {
                Some(client) => client,
                None => return
            };

            let alice_addr = alice_addr.clone();

            let response = client.post(&format!("{}/__internal/initiate_auth_protocol", &alice_addr))
                .header(X_INTERNAL_AUTH_SECRET, internal_auth_secret)
                .header(X_PROTO_STATE_ID, state_id)
                .header(X_PROTO_STATE_SIG, state_id_signature)
                .body(serde_json::to_string(&challenge_request).unwrap())
                .send().await;

            println!("hi {}", response.unwrap().text().await.unwrap());
        });

        let response = create_empty_response(&state, StatusCode::OK);

        Ok((state, response))
    }

    start_challenge_impl(state).boxed()
}

#[derive(Serialize, Deserialize)]
struct TestResponse {
    pub message: String,
}