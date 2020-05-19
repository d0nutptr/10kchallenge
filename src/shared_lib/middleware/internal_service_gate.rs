use gotham::middleware::{Middleware, NewMiddleware};
use hyper::{Response, Body, HeaderMap};
use std::pin::Pin;
use gotham::hyper::StatusCode;
use gotham::state::{State, FromState};
use gotham::handler::{HandlerError, HandlerFuture};
use futures::Future;
use gotham::helpers::http::response::create_response;
use futures::future::ok;
use crate::time_safe_comparison;

pub const X_INTERNAL_AUTH_SECRET: &str = "X-INTERNAL-AUTH-SECRET";

#[derive(Clone, NewMiddleware)]
pub struct InternalServiceMiddleware {
    internal_service_state: InternalServiceSecretState,
    enforce_secret: bool,
}

#[derive(Clone, StateData)]
pub struct InternalServiceSecretState {
    pub internal_service_secret: Vec<u8>
}

impl InternalServiceSecretState {
    pub fn new(secret: String) -> Self {
        match base64::decode(secret) {
            Ok(internal_service_secret) => {
                Self {
                    internal_service_secret
                }
            },
            Err(_) => panic!("Failed to decode internal service secret.")
        }
    }

    pub fn get_secret_as_b64(&self) -> String {
        base64::encode(&self.internal_service_secret)
    }
}

impl InternalServiceMiddleware {
    pub fn new(internal_service_secret: String, enforce_secret: bool) -> Self {

        let state = InternalServiceSecretState::new(internal_service_secret);

        Self {
            internal_service_state: state,
            enforce_secret
        }
    }
}

impl Middleware for InternalServiceMiddleware {
    fn call<Chain>(self, mut state: State, chain: Chain) -> Pin<Box<HandlerFuture>> where
        Chain: FnOnce(State) -> Pin<Box<HandlerFuture>> + Send + 'static,
        Self: Sized {
        /*
            1. check and fetch the internal secret header
                1. if missing, return unauthorized
            2. validate secret using time-safe comparison
                1. fail - unauthorized
         */

        if self.enforce_secret {
            let header_result = HeaderMap::borrow_from(&state).get(X_INTERNAL_AUTH_SECRET);
            let base64_decode_result = header_result.map(|value| {
                base64::decode(value.to_str().unwrap_or("").to_string())
            });

            let internal_auth_secret_value = match base64_decode_result {
                Some(Ok(internal_auth_secret_value)) => internal_auth_secret_value,
                _ => {
                    let mut response = create_response(
                        &state,
                        StatusCode::UNAUTHORIZED,
                        mime::APPLICATION_OCTET_STREAM,
                        Body::from(
                            format!("{} is used for services to talk directly to each other. This is not a part of the challenge (but feel free to poke at it)",
                                    X_INTERNAL_AUTH_SECRET)));


                    return Box::pin(ok((state, response)));
                },
            };

            if !time_safe_comparison(self.internal_service_state.internal_service_secret.clone(), internal_auth_secret_value) {
                let mut response = create_response(
                    &state,
                    StatusCode::UNAUTHORIZED,
                    mime::APPLICATION_OCTET_STREAM,
                    Body::from(
                        format!("{} is used for services to talk directly to each other. This is not a part of the challenge (but feel free to poke at it)",
                                X_INTERNAL_AUTH_SECRET)));

                return Box::pin(ok((state, response)));
            }
        }

        state.put(self.internal_service_state.clone());

        chain(state)
    }
}