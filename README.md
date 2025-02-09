# mlkem_chacha20poly1305_example

A Rust example demonstrating hybrid encryption using **ML-KEM (Kyber-1024 equivalent)** for post-quantum key encapsulation and **ChaCha20-Poly1305** for authenticated encryption. It also includes optional message serialization for transport.

## Features
- Generates a quantum-secure key pair using **ML-KEM-1024**.
- Encrypts messages using **ChaCha20-Poly1305** with a key derived from the encapsulated shared secret.
- Supports message serialization with **Bincode** and **JSON** (for demonstration).
- Demonstrates encryption, decryption, and failure scenarios.

## Dependencies
- [`pqcrypto-mlkem`](https://crates.io/crates/pqcrypto-mlkem)
- [`chacha20poly1305`](https://crates.io/crates/chacha20poly1305)
- [`rand`](https://crates.io/crates/rand)
- [`aead`](https://crates.io/crates/aead)
- [`serde`](https://crates.io/crates/serde) – Serialization framework.
- [`thiserror`](https://crates.io/crates/thiserror) – Error handling.
- [`serde_json`](https://crates.io/crates/serde_json) – JSON serialization.
- [`bincode`](https://crates.io/crates/bincode) – Binary serialization.

## Usage

### Running the Example
```sh
cargo run --release
