use rsa::{RSAPublicKey, BigUint, RSAPrivateKey};

pub const EVE_KEY_N: &str = "Q5y0/sUgJD1W/KlAgQF6Fhv3d+JpU/Udq9ZgoCPuZRJrxj+KQsvMRgfZDfzNJunxvTe2AZYWBN0NbFTUEcx5S7YqKAnNZjxI7kKKG9j2EnlHwtHUknPQy5YAAlmSRkvZ8vmu2PZeb721IEgi3KZGLb10fJGfdSuNkj4cLTbzaToc9CJcZ88Tt8fZuxOWUtPiXu3STN2K6BrKFsGCFIQTLExyqJyVFEMVOyg/savJsDQ//iBjwG8qcU/8jCteYVKsDSmPEDUwBEYAIKde2L8Cte35SLowEusLnql2zSeL759m0B3RKhZqiF88wBX4Ho48/S6tuAzkL3lOuay4LK1k4A==";
pub const EVE_KEY_E: &str = "AQAB";
pub const EVE_KEY_D: &str = "Wdwyy3NQIuKj7sW4DBdWgHVrRpD+KxwBJT++ejMqJlPjeMP5m0H3Am2YRCMUvQe7T2uVUxCOL+/c1QAU3k7Qvd2yU/n6MXdT8jZ4FkCOnAQ38GUJ7Ltw9eGN/jqUhgXioA8EzyJVCj8c6sLlq8cApEZIDi0S3f0QG+S4cOi2l+1w1GdGlpdugBoVDI8p43kiNb+IUWaaP8xOCCvBNor5RAAMmnxR3k1t/osz++zbPC81qpwNUv46utejDeP7f8pjBiDWne+S+WbEoftPgOAPXO8097e+AJRlzaC/NnAPIr1YquZVTs7dJCxWNcm6hEwSC6s3o9K/Od2MSzu+rjKSgg==";
pub const EVE_PRIME_1: &str = "b1jpIh3IApJ6k18u65SRWOwNftqJcoMOwtrNbS9nIKpaOZEeSuUtnJn72qGiHCVfJgT/eJwzui9iK+lAmmp3GQSk/EbsKR4XmMxWNctv5bWqFWqI2Twp8lEVH43SlcxmpdZCxHxXxWASL3ap6J4JeOVbm3lXWmTZ5cSVKwMJyfM=";
pub const EVE_PRIME_2: &str = "bdv9MxrpbD54LjoYZTyAvNjITNVnE2RM4dceb/nvi64OwCk3SMBbzMNHtcEfY2vkWhJVRem12L7Pct51/OePIe6PdI4fwy78EQBEq1EoQrdgkN40WfmctU4r533hZX80CFISl3/YiLmMRtoZv5vCK988zYaUfwxLlHJhwr3nous=";

pub fn eve_key() -> (RSAPublicKey, RSAPrivateKey) {
    let n = BigUint::from_bytes_le(&base64::decode(EVE_KEY_N).unwrap());
    let e = BigUint::from_bytes_le(&base64::decode(EVE_KEY_E).unwrap());
    let d = BigUint::from_bytes_le(&base64::decode(EVE_KEY_D).unwrap());
    let p1 = BigUint::from_bytes_le(&base64::decode(EVE_PRIME_1).unwrap());
    let p2 = BigUint::from_bytes_le(&base64::decode(EVE_PRIME_2).unwrap());

    let private_key = RSAPrivateKey::from_components(n, e, d, vec![p1, p2]);
    let public_key = private_key.to_public_key();

    (public_key, private_key)
}