use gotham::middleware::Middleware;
use hyper::{Response, Body};
use std::pin::Pin;
use gotham::state::State;
use gotham::handler::{HandlerError, HandlerFuture};
use futures::Future;
use serde::de::DeserializeOwned;
use serde::Serialize;
use rsa::{RSAPublicKey, RSAPrivateKey, PaddingScheme};
use rsa::hash::Hashes;
use crate::utils::SmartRSAPrivateKey;

#[derive(Clone, StateData)]
pub struct ServiceKeyState {
    pub pub_key: RSAPublicKey,
    pub priv_key: RSAPrivateKey
}

impl ServiceKeyState {
    pub fn new(pub_key: RSAPublicKey, priv_key: RSAPrivateKey) -> Self {
        Self {
            pub_key,
            priv_key
        }
    }

    pub fn sign_message<T>(&self, obj: &T) -> Option<Vec<u8>>
        where
            T: Serialize + DeserializeOwned {
        match serde_json::to_string(obj) {
            Ok(serialize_obj) => {
                self.priv_key.smart_sign(serialize_obj.into_bytes())
            },
            _ => None
        }
    }

    pub fn sign_string(&self, message: &str) -> Vec<u8> {
        self.priv_key.sign(PaddingScheme::OAEP, Some(&Hashes::SHA2_256), &message.as_bytes()).unwrap()
    }
}