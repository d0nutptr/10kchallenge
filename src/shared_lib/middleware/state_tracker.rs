use gotham::middleware::{Middleware, NewMiddleware};
use hyper::{Response, Body, StatusCode, HeaderMap};
use std::pin::Pin;
use gotham::state::{State, FromState};
use gotham::handler::{HandlerError, HandlerFuture};
use futures::Future;
use std::sync::{Mutex, Arc};
use std::collections::HashMap;
use gotham::helpers::http::response::create_response;
use futures::future::ok;
use rsa::{RSAPublicKey, PublicKey, PaddingScheme};
use rsa::hash::Hashes;
use crate::SmartRSAPublicKey;

pub const X_PROTO_STATE_ID: &str = "X-PROTO-STATE-ID";
pub const X_PROTO_STATE_SIG: &str = "X-PROTO-STATE-SIG";

#[derive(Clone, NewMiddleware)]
pub struct ChallengeStateTrackerMiddleware<S>
where
    S: ChallengeState + 'static
{
    state: StateTrackerState<S>
}

impl<S> ChallengeStateTrackerMiddleware<S>
where
    S: ChallengeState + 'static
{
    pub fn new(state: StateTrackerState<S>) -> Self {
        Self {
            state
        }
    }
}

#[derive(Clone, StateData)]
pub struct StateTrackerState<S>
where
    S: ChallengeState + 'static
{
    state_name: String,
    pub internal_states: Arc<Mutex<HashMap<String, S>>>,
    current_state_id: Option<String>,
    current_state_signature: Option<String>,
    challenge_service_pubkey: RSAPublicKey,
}

impl<S> StateTrackerState<S>
where
    S: ChallengeState + 'static
{
    pub fn new(state_name: String, challenge_service_pubkey: RSAPublicKey) -> Self {
        Self {
            state_name,
            internal_states: Arc::new(Mutex::new(HashMap::new())),
            current_state_id: None,
            current_state_signature: None,
            challenge_service_pubkey,
        }
    }

    pub fn get_current_state_id(&self) -> String {
        self.current_state_id.clone().unwrap()
    }

    pub fn get_current_state_signature(&self) -> String {
        self.current_state_signature.clone().unwrap()
    }

}

pub trait ChallengeState: Send + Clone + PartialEq {
    fn default_state() -> Self;
}

impl<S> Middleware for ChallengeStateTrackerMiddleware<S>
where
    S: ChallengeState + 'static
{
    fn call<Chain>(self, mut state: State, chain: Chain) -> Pin<Box<HandlerFuture>> where
        Chain: FnOnce(State) -> Pin<Box<HandlerFuture>> + Send + 'static,
        Self: Sized {
        /*
            1. If no public key is set, 503 + message to tell d0nut he fucked something up (pub key missing)
            2. Get proto state id and sig headers
                1. missing, 503 + message that this is for stateful tracking in this protocol
            3. validate sig
                1. failed, 503 + message that this is for stateful tracking in this protocol
            4. set state id
            5. add to the current request the state
         */

        let mut request_state = self.state.clone();

        // get proto state id and sig header
        let state_id = match HeaderMap::borrow_from(&state).get(X_PROTO_STATE_ID) {
            Some(state_id) => state_id.to_str().unwrap_or("").to_string(),
            None => {
                let mut response = create_response(
                    &state,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    mime::APPLICATION_OCTET_STREAM,
                    Body::from(format!("{} and {} are used for stateful tracking in this protocol. They are required for requests to be processed.", X_PROTO_STATE_ID, X_PROTO_STATE_SIG)));


                return Box::pin(ok((state, response)));
            },
        };

        // get proto state id and sig header
        let state_sig = match HeaderMap::borrow_from(&state).get(X_PROTO_STATE_SIG) {
            Some(state_sig) => state_sig.to_str().unwrap_or("").to_string(),
            None => {
                let mut response = create_response(
                    &state,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    mime::APPLICATION_OCTET_STREAM,
                    Body::from(format!("{} and {} are used for stateful tracking in this protocol. They are required for requests to be processed.", X_PROTO_STATE_ID, X_PROTO_STATE_SIG)));

                return Box::pin(ok((state, response)));
            },
        };

        let state_id_bytes = state_id.clone().into_bytes();
        let state_signature = match base64::decode(state_sig.clone()) {
            Ok(signature) =>  signature,
            _ => {
                let mut response = create_response(
                    &state,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    mime::APPLICATION_OCTET_STREAM,
                    Body::from(format!("{} and {} are used for stateful tracking in this protocol. They are required for requests to be processed.", X_PROTO_STATE_ID, X_PROTO_STATE_SIG)));

                return Box::pin(ok((state, response)));
            }
        };

        // validate the signature
        if ! self.state.challenge_service_pubkey.smart_verify(state_id_bytes.clone(), state_signature.clone()) {
            let mut response = create_response(
                &state,
                StatusCode::INTERNAL_SERVER_ERROR,
                mime::APPLICATION_OCTET_STREAM,
                Body::from(format!("{} and {} are used for stateful tracking in this protocol. They are required for requests to be processed and the signature must be valid.", X_PROTO_STATE_ID, X_PROTO_STATE_SIG)));

            return Box::pin(ok((state, response)));
        }

        {
            let mut state_map = request_state.internal_states.lock().unwrap();

            // is this request id doesn't yet exist, make it the default state
            if !state_map.contains_key(&state_id) {
                state_map.insert(state_id.clone(), S::default_state());
            }
        }

        request_state.current_state_id = Some(state_id);
        request_state.current_state_signature = Some(state_sig);

        state.put(request_state);

        chain(state)
    }
}