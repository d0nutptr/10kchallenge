use hyper::{Body, Response};
use gotham::state::{State, FromState};
use std::future::Future;
use serde::Serialize;
use hyper::StatusCode;
use hyper::body::to_bytes;
use gotham::helpers::http::response::create_response;
use futures::{TryFutureExt, FutureExt};

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
        Body::from("An error occurred")
    );

    (state, response)
}