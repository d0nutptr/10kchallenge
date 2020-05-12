use gotham::middleware::{Middleware, NewMiddleware};
use hyper::{Response, Body, StatusCode, HeaderMap};
use std::pin::Pin;
use gotham::state::{State, FromState};
use gotham::handler::{HandlerError, HandlerFuture};
use futures::Future;
use std::sync::{Mutex, Arc};
use std::collections::HashMap;
use ed25519_dalek::{PublicKey, Signature};
use gotham::helpers::http::response::create_response;
use futures::future::ok;

const X_PROTO_STATE_ID: &str = "X-PROTO-STATE-ID";
const X_PROTO_STATE_SIG: &str = "X-PROTO-STATE-SIG";

#[derive(Clone, NewMiddleware)]
pub struct ChallengeStateTrackerMiddleware<S>
where
    S: ChallengeState + 'static
{
    state: StateTrackerState<S>
}

#[derive(Clone, StateData)]
pub struct StateTrackerState<S>
where
    S: ChallengeState + 'static
{
    state_name: String,
    internal_states: Arc<Mutex<HashMap<String, S>>>,
    challenge_service_pubkey: Arc<Mutex<Option<PublicKey>>>,
    current_state_id: Option<String>,
    current_state_signature: Option<String>
}

pub trait ChallengeState: Send + Clone {
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

        let challenge_pubkey = match request_state.challenge_service_pubkey.lock().unwrap().clone() {
            Some(pubkey) => pubkey,
            None => {
                // no pub key; error and tell d0nut he fucked up
                let mut response = create_response(
                    &state,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    mime::APPLICATION_OCTET_STREAM,
                    Body::from(format!("Oops... d0nut fucked up. Please tell https://twitter.com/d0nutptr that '{}' is missing the challenge public key :(", request_state.state_name)));


                return Box::pin(ok((state, response)));
            }
        };

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
        let state_signature = match base64::decode(state_sig.clone()).map(|state_bytes| Signature::from_bytes(&state_bytes)) {
            Ok(Ok(signature)) =>  signature,
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
        if challenge_pubkey.verify(&state_id_bytes, &state_signature).is_err() {
            let mut response = create_response(
                &state,
                StatusCode::INTERNAL_SERVER_ERROR,
                mime::APPLICATION_OCTET_STREAM,
                Body::from(format!("{} and {} are used for stateful tracking in this protocol. They are required for requests to be processed and the signature must be valid.", X_PROTO_STATE_ID, X_PROTO_STATE_SIG)));

            return Box::pin(ok((state, response)));
        }

        request_state.current_state_id = Some(state_id);
        request_state.current_state_signature = Some(state_sig);

        state.put(request_state);

        chain(state)
    }
}