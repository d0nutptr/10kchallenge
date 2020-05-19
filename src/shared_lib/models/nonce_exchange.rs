use serde::{Serialize, Deserialize};
use crate::Participant;

#[derive(Serialize, Deserialize)]
pub struct AliceNoncePayloadInner {
    pub nonce_a: String,
    pub party: Participant
}

#[derive(Serialize, Deserialize)]
pub struct AliceNoncePayload {
    pub enc_payload: String
}

#[derive(Serialize, Deserialize)]
pub struct BobNoncePayloadInner {
    pub nonce_a: String,
    pub nonce_b: String
}

#[derive(Serialize, Deserialize)]
pub struct BobNoncePayload {
    pub enc_payload: String
}

#[derive(Serialize, Deserialize)]
pub struct AliceAckPayloadInner {
    pub nonce_b: String
}

#[derive(Serialize, Deserialize)]
pub struct AliceAckPayload {
    pub enc_payload: String
}

#[derive(Serialize, Deserialize)]
pub struct BobSecretMessage {
    pub ciphertext: String,
    pub nonce: String
}