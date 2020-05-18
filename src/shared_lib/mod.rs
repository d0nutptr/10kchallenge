#[macro_use]
extern crate gotham_derive;

#[macro_use]
extern crate serde_derive;

use gotham::state::State;
use hyper::{Body, Response};
use gotham::handler::HandlerError;

mod middleware;
mod models;
mod utils;
mod proxy;

pub use proxy::X_PROXY_ADDR;
pub use middleware::*;
pub use models::*;
pub use utils::*;

pub type AsyncHandlerResponse = Result<(State, Response<Body>), (State, HandlerError)>;