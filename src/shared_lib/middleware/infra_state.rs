use std::sync::{Arc, Mutex};
use rsa::RSAPublicKey;

#[derive(Clone, StateData)]
pub struct InfraState {
    pub iam_pub_key: Arc<Mutex<Option<RSAPublicKey>>>,
    pub challenge_pub_key: Arc<Mutex<Option<RSAPublicKey>>>
}

impl InfraState {
    pub fn new(challenge_pub_key: RSAPublicKey, iam_pub_key: RSAPublicKey) -> Self {
        Self {
            iam_pub_key: Arc::new(Mutex::new(Some(iam_pub_key))),
            challenge_pub_key: Arc::new(Mutex::new(Some(challenge_pub_key)))
        }
    }
}