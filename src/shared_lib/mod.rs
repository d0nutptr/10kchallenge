#[macro_use]
extern crate gotham_derive;

use gotham::state::State;
use hyper::{Body, Response};
use gotham::handler::HandlerError;

mod middleware;
mod utils;

pub use middleware::{RateLimitMiddleware, RateLimitState};
pub use utils::{return_json, extract_json, return_generic_error};

pub type AsyncHandlerResponse = Result<(State, Response<Body>), (State, HandlerError)>;