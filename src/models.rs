use serde::{Serialize, Deserialize};
use gotham::state::StateData;
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use std::sync::{Mutex, Arc};
use std::collections::HashMap;

#[derive(Clone, StateData)]
pub struct TrentServiceSecretState {
    pub service_keypair: Arc<Mutex<Keypair>>,
    pub internal_keypair: Arc<Mutex<Keypair>>,
    pub client_pub_keys: Arc<Mutex<HashMap<String, String>>>
}

impl TrentServiceSecretState {
    pub fn new() -> Self {
        let mut csprng = OsRng {};

        Self {
            service_keypair: Arc::new(Mutex::new(Keypair::generate(&mut csprng))),
            internal_keypair: Arc::new(Mutex::new(Keypair::generate(&mut csprng))),
            client_pub_keys: Arc::new(Mutex::new(HashMap::new()))
        }
    }
}

pub mod internal {
    use serde::{Serialize, Deserialize};

    #[derive(Serialize, Deserialize)]
    pub struct InternalServicePubKeyReportingRequest {
        pub pub_key: String
    }

    #[derive(Serialize, Deserialize)]
    pub struct InternalServicePubKeyResponse {
        pub pub_key: String
    }
}

#[derive(Serialize, Deserialize)]
pub struct GetPubKeyRequest {
    pub client: String,
    pub remote: String
}

#[derive(Serialize, Deserialize)]
pub struct TrentPubKeyResponse {
    pub pub_key: String
}