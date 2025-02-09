use std::time::Instant;

use mlkem_chacha20poly1305_example::{decrypt, encrypt, error::Error, KeyPair};
use pqcrypto_mlkem::mlkem1024::{public_key_bytes, secret_key_bytes};

fn main() -> Result<(), Error> {
    let keypair = KeyPair::generate();
    println!(
        "public_key_size: {}, private_key_size: {}",
        public_key_bytes(),
        secret_key_bytes()
    );
    let message = b"Hello, quantum secure world!";
    let now = Instant::now();
    let mut encrypted_message = encrypt(&keypair.public, message)?;
    println!("{}ns", now.elapsed().as_nanos());

    //message serialization for transport
    let bincode_serialized = bincode::serialize(&encrypted_message).unwrap();
    println!(
        "bincode serialized length in bytes: {}",
        bincode_serialized.len()
    );
    let json_serialized = serde_json::to_string(&encrypted_message).unwrap();
    println!(
        "json serialized length in bytes: {}",
        json_serialized.as_bytes().len()
    );

    //decryption will succeed
    {
        let now = Instant::now();
        let decrypted = decrypt(&keypair.secret, &encrypted_message)?;
        println!("{}ns", now.elapsed().as_nanos());
        assert_eq!(message, decrypted.as_slice());
        println!("{}", String::from_utf8(decrypted).unwrap());
    }
    //decryption will fail
    {
        encrypted_message.ciphertext[5] = 0;
        let result = decrypt(&keypair.secret, &encrypted_message);
        assert!(result.is_err());
    }

    Ok(())
}
