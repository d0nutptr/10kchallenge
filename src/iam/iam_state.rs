use std::sync::{Arc, Mutex};
use rsa::RSAPublicKey;

#[derive(Clone, StateData)]
pub struct IAMState {
    pub alice_pub_key: Arc<Mutex<Option<RSAPublicKey>>>,
    pub bob_pub_key: Arc<Mutex<Option<RSAPublicKey>>>,
    pub challenge_pub_key: Arc<Mutex<Option<RSAPublicKey>>>
}

impl IAMState {
    pub fn new(challenge_pub_key: RSAPublicKey) -> Self {
        Self {
            alice_pub_key: Arc::new(Mutex::new(None)),
            bob_pub_key: Arc::new(Mutex::new(None)),
            challenge_pub_key: Arc::new(Mutex::new(Some(challenge_pub_key)))
        }
    }
}

pub enum ServiceIdentity {
    ALICE,
    BOB
}