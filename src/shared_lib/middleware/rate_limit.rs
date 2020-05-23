use gotham::middleware::{Middleware, NewMiddleware};
use hyper::{Response, Body, StatusCode};
use std::pin::Pin;
use gotham::state::{State, StateData, FromState};
use gotham::handler::{HandlerError, HandlerFuture};
use gotham::hyper::header::HeaderMap;
use futures::{Future, FutureExt, TryFutureExt};
use crate::AsyncHandlerResponse;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use gotham::helpers::http::response::{create_response, create_empty_response};
use futures::future::ok;
use hyper::header::HeaderValue;

const LIMIT_PER_TIME_BUCKET: u64 = 250;
const SECONDS_PER_TIME_BUCKET: u64 = 600;
const X_FORWARDED_FOR: &str = "X-Forwarded-For";
const X_REQUESTS_REMAINING: &str = "X-Requests-Remaining";

#[derive(Clone, NewMiddleware)]
pub struct RateLimitMiddleware {
    state: RateLimitState
}

impl RateLimitMiddleware {
    pub fn new(state: RateLimitState) -> Self {
        Self {
            state
        }
    }
}

#[derive(Clone, StateData)]
pub struct RateLimitState {
    internal_state: Arc<Mutex<HashMap<String, RateLimitStateInstance>>>
}

impl RateLimitState {
    pub fn new() -> Self {
        Self {
            internal_state: Arc::new(Mutex::new(HashMap::new()))
        }
    }

    fn record_request(&mut self, remote_addr: &String) {
        let mut internal_state = self.internal_state.lock().unwrap();
        let time_bucket = RateLimitState::get_time_bucket();

        match internal_state.get_mut(remote_addr) {
            Some(state_instance) => {
                if state_instance.time_bucket == time_bucket {
                    // add 1
                    state_instance.req_count += 1;
                } else {
                    // reset to 1 and set the new time
                    state_instance.req_count = 1;
                    state_instance.time_bucket = time_bucket;
                }
            },
            _ => {
                internal_state.insert(remote_addr.clone(), RateLimitStateInstance {
                    req_count: 1,
                    time_bucket
                });
            }
        }
    }

    fn get_remaining_requests_available(&mut self, remote_addr: &String) -> u64 {
        let mut internal_state = self.internal_state.lock().unwrap();
        let time_bucket = RateLimitState::get_time_bucket();

        match internal_state.get(remote_addr) {
            Some(state_instance) => {
                if state_instance.time_bucket == time_bucket {
                    // we have a current record of interaction so we should return the remaining requests
                    std::cmp::max( LIMIT_PER_TIME_BUCKET.checked_sub(state_instance.req_count).unwrap_or(0), 0)
                } else {
                    // we've left the old time bucket so we reset requests
                    LIMIT_PER_TIME_BUCKET
                }
            },
            // no record of this IP hitting us exists so it has a new bucket's worth of requests
            _ => LIMIT_PER_TIME_BUCKET
        }
    }

    /// get the time bucket based on time since the Unix Epoch and the SECONDS_PER_TIME_BUCKET constant
    fn get_time_bucket() -> u64 {
        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() / SECONDS_PER_TIME_BUCKET
    }
}

struct RateLimitStateInstance {
    req_count: u64,
    time_bucket: u64
}

impl Middleware for RateLimitMiddleware {
    fn call<Chain>(self, mut state: State, chain: Chain) -> Pin<Box<HandlerFuture>> where
        Chain: FnOnce(State) -> Pin<Box<HandlerFuture>> + Send + 'static,
        Self: Sized {
        let mut rate_limit_state = self.state;

        let remote_addr = match HeaderMap::borrow_from(&state).get(X_FORWARDED_FOR) {
            Some(remote_addr) => remote_addr.to_str().unwrap().to_string(),
            None => {
                let mut response = create_response(
                    &state,
                    StatusCode::TOO_MANY_REQUESTS,
                    mime::APPLICATION_OCTET_STREAM,
                    Body::from("Too many requests."));


                return Box::pin(ok((state, response)));
            },
        };

        rate_limit_state.record_request(&remote_addr);

        let remaining_requests = rate_limit_state.get_remaining_requests_available(&remote_addr);

        // pack the state away just in case we need it later in the chain
        state.put(rate_limit_state);

        let mut result = if remaining_requests > 0 {
            chain(state)
        } else {
            let response = create_response(
                &state,
                StatusCode::TOO_MANY_REQUESTS,
                mime::APPLICATION_OCTET_STREAM,
                Body::from("Too many requests."));

            Box::pin(ok((state, response)))
        };

        let response = result.and_then(move |(state, mut response)| {
            response.headers_mut().insert(X_REQUESTS_REMAINING, HeaderValue::from_str(&remaining_requests.to_string()).unwrap());

            ok((state, response))
        });

        response.boxed()
    }
}