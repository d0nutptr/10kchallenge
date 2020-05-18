use gotham::handler::HandlerFuture;
use std::pin::Pin;
use gotham::state::{State, FromState};
use shared_lib::{AsyncHandlerResponse, ChallengeState, StateTrackerState, return_json, ServiceKeyState, PubKeyResponse};
use futures::FutureExt;
use gotham::helpers::http::response::create_response;
use hyper::{StatusCode, Body, Response};
use serde::{Serialize, Deserialize};
use rsa::PublicKey;

pub fn fetch_pubkey(mut state: State) -> (State, Response<Body>) {
    // 1. get the pubkey state out
    // 2. get the bytes of the pubkey
    // 3. base64 that stuff
    // 4. serialize pubkeyresponse
    // 5. ???
    // 6. profit

    let pubkey_state = ServiceKeyState::borrow_from(&state);

    let pubkey_response = PubKeyResponse {
        n: pubkey_state.pub_key.n().to_bytes_le(),
        e: pubkey_state.pub_key.e().to_bytes_le()
    };

    let response = return_json(&state, pubkey_response);

    (state, response)
}
