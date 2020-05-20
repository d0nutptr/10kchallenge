use std::io;
use shared_lib::{B64String, AliceNoncePayloadInner, SmartRSAPrivateKey, eve_key, AliceNoncePayload, SmartRSAPublicKey, B64Vec, AliceAckPayloadInner, AliceAckPayload};
use rsa::{RSAPrivateKey, BigUint, RSAPublicKey};
use sha2::digest::generic_array::GenericArray;
use chacha20poly1305::XChaCha20Poly1305;
use aead::{Aead, NewAead};

const RSA_CONST_E: &str = "AQAB";

// Most solutions may use python. This is where you'd want to look
// https://github.com/pyca/cryptography/blob/master/src/cryptography/hazmat/primitives/asymmetric/rsa.py#L225
fn main() {
    let eve_private_key = eve_key().1;
    let alice_public_key = get_alice_public_key();
    let bob_public_key = get_bob_public_key();

    // ALICE -> EVE (nonce_a, Alice)
    let alice_eve_nonce_payload = match decrypt_alice_eve_exchange(&eve_private_key) {
        Some(payload) => payload,
        None => panic!("Failed to decrypt payload")
    };

    // EVE(Alice) -> BOB (nonce_a, Alice)
    let fake_alice_bob_nonce_payload = AliceNoncePayload {
        enc_payload: encrypt_nonce_inner_with_key(&alice_eve_nonce_payload, &bob_public_key)
    };

    println!("SEND THIS TO BOB\n{}", serde_json::to_string(&fake_alice_bob_nonce_payload).unwrap());

    let alice_eve_ack_payload = match decrypt_alice_eve_ack(&eve_private_key) {
        Some(payload) => payload,
        None => panic!("Failed to decrypt payload")
    };

    let fake_alice_bob_ack_payload = AliceAckPayload {
        enc_payload: encrypt_ack_inner_with_key(&alice_eve_ack_payload, &bob_public_key)
    };

    println!("SEND THIS TO BOB\n{}", serde_json::to_string(&fake_alice_bob_ack_payload).unwrap());

    let plaintext_message = decrypt_secret_message(alice_eve_nonce_payload.nonce_a.clone(), alice_eve_ack_payload.nonce_b.clone());

    println!("SECRET MESSAGE: {}", plaintext_message);
}

fn decrypt_secret_message(nonce_a: String, nonce_b: String) -> String {
    fn _create_encryption_key(nonce_a: String, nonce_b: String) -> Vec<u8> {
        let nonce_a_bytes = nonce_a.b64_tolerant_decode();
        let nonce_b_bytes = nonce_b.b64_tolerant_decode();

        nonce_a_bytes.into_iter().zip(nonce_b_bytes)
            .map(|(left_byte, right_byte)| {
                left_byte ^ right_byte
            }).collect()
    }

    fn _decrypt_secret_message(ciphertext: Vec<u8>, nonce: Vec<u8>, nonce_a: String, nonce_b: String) -> String {
        let enc_key = _create_encryption_key(nonce_a, nonce_b);
        let encryption_key = GenericArray::clone_from_slice(&enc_key);
        let aead = XChaCha20Poly1305::new(encryption_key);
        let nonce = GenericArray::clone_from_slice(&nonce);

        String::from_utf8(aead.decrypt(&nonce, ciphertext.as_ref()).expect("FAILED ENCRYPTION")).unwrap()
    }

    let ciphertext = prompt_and_read("Ciphertext").b64_tolerant_decode();
    let enc_nonce = prompt_and_read("Nonce").b64_tolerant_decode();

    _decrypt_secret_message(ciphertext, enc_nonce, nonce_a, nonce_b)
}

fn encrypt_ack_inner_with_key(ack_inner: &AliceAckPayloadInner, key: &RSAPublicKey) -> String {
    key.smart_encrypt(serde_json::to_string(ack_inner).unwrap().into_bytes())
        .unwrap()
        .b64_encode()
}

fn decrypt_alice_eve_ack(eve_private_key: &RSAPrivateKey) -> Option<AliceAckPayloadInner> {
    let enc_payload = prompt_and_read("Alice->Eve(enc_payload)").b64_tolerant_decode();

    match eve_private_key.smart_decrypt(enc_payload).map(|output| serde_json::from_slice::<AliceAckPayloadInner>(&output)) {
        Some(output) => output.ok(),
        _ => None
    }
}

fn encrypt_nonce_inner_with_key(nonce_inner: &AliceNoncePayloadInner, key: &RSAPublicKey) -> String {
    key.smart_encrypt(serde_json::to_string(nonce_inner).unwrap().into_bytes())
        .unwrap()
        .b64_encode()
}

fn decrypt_alice_eve_exchange(eve_private_key: &RSAPrivateKey) -> Option<AliceNoncePayloadInner> {
    let enc_payload = prompt_and_read("Alice->Eve(enc_payload)").b64_tolerant_decode();

    match eve_private_key.smart_decrypt(enc_payload).map(|output| serde_json::from_slice::<AliceNoncePayloadInner>(&output)) {
        Some(output) => output.ok(),
        _ => None
    }
}

fn get_bob_public_key() -> RSAPublicKey {
    let bob_n = BigUint::from_bytes_le((&prompt_and_read("BOB(n)").b64_tolerant_decode()));
    let bob_e = BigUint::from_bytes_le((&RSA_CONST_E.to_string().b64_tolerant_decode()));

    RSAPublicKey::new(bob_n, bob_e).unwrap()
}

fn get_alice_public_key() -> RSAPublicKey {
    let alice_n = BigUint::from_bytes_le((&prompt_and_read("ALICE(n)").b64_tolerant_decode()));
    let alice_e = BigUint::from_bytes_le((&RSA_CONST_E.to_string().b64_tolerant_decode()));

    RSAPublicKey::new(alice_n, alice_e).unwrap()
}

fn prompt_and_read(prompt: &str) -> String {
    println!("{}: ", prompt);

    let mut value = String::new();
    io::stdin().read_line(&mut value);

    value
}