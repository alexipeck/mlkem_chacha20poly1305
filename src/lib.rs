pub mod error;

use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    ChaCha20Poly1305,
};
use error::Error;
use pqcrypto_mlkem::{
    mlkem1024::{Ciphertext, PublicKey, SecretKey},
    mlkem1024_decapsulate as decapsulate, mlkem1024_encapsulate as encapsulate,
    mlkem1024_keypair as keypair,
};
use pqcrypto_traits::kem::SharedSecret;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, error::Error>;

#[derive(Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub kem_ciphertext: Ciphertext,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

pub struct KeyPair {
    pub public: PublicKey,
    pub secret: SecretKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let (public, secret) = keypair();
        KeyPair { public, secret }
    }
}

pub fn encrypt(public_key: &PublicKey, plaintext: &[u8]) -> Result<EncryptedMessage> {
    let (shared_secret, kem_ciphertext) = encapsulate(public_key);
    let key = GenericArray::from_slice(shared_secret.as_bytes());
    let cipher = ChaCha20Poly1305::new(key);
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let nonce_ga = GenericArray::from_slice(&nonce);
    let ciphertext = cipher
        .encrypt(nonce_ga, plaintext)
        .map_err(|_| Error::AEAD)?;
    Ok(EncryptedMessage {
        kem_ciphertext,
        nonce,
        ciphertext,
    })
}

pub fn decrypt(secret_key: &SecretKey, encrypted: &EncryptedMessage) -> Result<Vec<u8>> {
    let shared_secret = decapsulate(&encrypted.kem_ciphertext, secret_key);
    let key = GenericArray::from_slice(shared_secret.as_bytes());
    let cipher = ChaCha20Poly1305::new(key);
    let nonce_ga = GenericArray::from_slice(&encrypted.nonce);
    let plaintext = cipher
        .decrypt(nonce_ga, encrypted.ciphertext.as_ref())
        .map_err(|_| Error::AEAD)?;
    Ok(plaintext)
}
