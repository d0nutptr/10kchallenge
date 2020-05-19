use serde::{Serialize, Deserialize};
use crate::{X_INTERNAL_AUTH_SECRET, B64String};
use rsa::{RSAPublicKey, BigUint, PublicKey};

#[derive(Serialize, Deserialize)]
pub struct PubKeyResponse {
    pub n: Vec<u8>,
    pub e: Vec<u8>
}

#[derive(Serialize, Deserialize)]
pub struct PubKeyReport {
    pub n: Vec<u8>,
    pub e: Vec<u8>
}

#[derive(Serialize, Deserialize)]
pub struct PublicKeyInquiry {
    pub inquiring_party: Participant,
    pub subject: Participant
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub enum Participant {
    ALICE,
    BOB,
    EVE
}

#[derive(Serialize, Deserialize)]
pub struct IAMPublicKeyReport {
    pub payload: IAMPublicKeyReportSecure,
    pub signature: String
}

impl IAMPublicKeyReport {
    pub fn get_public_key(&self) -> Option<RSAPublicKey> {
        RSAPublicKey::new(
            BigUint::from_bytes_le(&self.payload.n.b64_tolerant_decode()),
            BigUint::from_bytes_le(&self.payload.e.b64_tolerant_decode())).ok()
    }
}

#[derive(Serialize, Deserialize)]
pub struct IAMPublicKeyReportSecure {
    pub n: String,
    pub e: String,
    pub subject: Participant
}

pub fn fetch_challenge_public_key(internal_auth_secret: &str, challenge_address: String) -> Option<RSAPublicKey> {
    let client = reqwest::blocking::Client::new();

    let mut response = client.get(&format!("{}/__internal/fetch_pubkey", challenge_address))
        .header(X_INTERNAL_AUTH_SECRET, internal_auth_secret)
        .send()
        .unwrap();

    let pubkey_response: PubKeyResponse = match response.json::<PubKeyResponse>() {
        Ok(result) => result,
        _ => return None
    };

    RSAPublicKey::new(BigUint::from_bytes_le(&pubkey_response.n), BigUint::from_bytes_le(&pubkey_response.e)).ok()
}

pub fn report_service_public_key(internal_auth_secret: &str, iam_address: &str, participant: Participant, pubkey: RSAPublicKey) -> Option<RSAPublicKey> {
    let client = reqwest::blocking::Client::new();

    let suffix = match participant {
        Participant::ALICE => String::from("alice"),
        Participant::BOB => String::from("bob"),
        _ => String::from("")
    };

    let pubkey_report = PubKeyReport {
        n: pubkey.n().to_bytes_le(),
        e: pubkey.e().to_bytes_le()
    };

    let payload = serde_json::to_string(&pubkey_report).unwrap();

    let mut response = client.post(&format!("{}/__internal/report_pubkey/{}", iam_address, suffix))
        .header(X_INTERNAL_AUTH_SECRET, internal_auth_secret)
        .body(payload)
        .send()
        .unwrap();

    let pubkey_response: PubKeyResponse = match response.json::<PubKeyResponse>() {
        Ok(result) => result,
        _ => return None
    };

    RSAPublicKey::new(BigUint::from_bytes_le(&pubkey_response.n), BigUint::from_bytes_le(&pubkey_response.e)).ok()
}
