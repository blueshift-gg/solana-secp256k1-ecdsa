# Solana Secp256k1 ECDSA

A `no_std` compatible ECDSA implementation for the Secp256k1 curve, designed for use within the Solana ecosystem.

## Overview

This library provides a lightweight implementation of ECDSA signatures using the Secp256k1 curve. It's designed to be compatible with `no_std` environments, making it suitable for embedded systems, WebAssembly modules, and other constrained environments without standard library support.

## Features

- **no_std compatible**: Works in environments without the Rust standard library
- **Signature creation**: Generate ECDSA signatures with various methods:
  - RFC6979 deterministic nonce generation
  - Custom ephemeral key (k) support
  - Pre-hashed message support
- **Signature verification**: Verify ECDSA signatures against public keys
- **Signature normalization**: Handles signature malleability with optional s-value normalization (low-S)
- **Minimal dependencies**: Built on top of `solana_secp256k1` primitives

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
solana-secp256k1-ecdsa = "0.1.0"
```

### Creating Signatures

Enable the `sign` feature flag to use signature creation functionality:

```toml
[dependencies]
solana-secp256k1-ecdsa = { version = "0.1.0", features = ["sign"] }
```

#### Basic Signing

```rust
use solana_secp256k1_ecdsa::{Secp256k1EcdsaSignature, hash::Sha256};

// Your message and private key
let message = b"Hello, Solana!";
let private_key: [u8; 32] = [/* your private key */];

// Sign the message
let signature = Secp256k1EcdsaSignature::sign::<Sha256>(message, &private_key)?;
```

#### Signing with a Custom Ephemeral Key

```rust
use solana_secp256k1_ecdsa::{Secp256k1EcdsaSignature, hash::Sha256};

// Your message, ephemeral key, and private key
let message = b"Hello, Solana!";
let ephemeral_key: [u8; 32] = [/* your ephemeral key */];
let private_key: [u8; 32] = [/* your private key */];

// Sign with custom k
let signature = Secp256k1EcdsaSignature::sign_with_k::<Sha256>(
    message, 
    &ephemeral_key, 
    &private_key
)?;
```

### Verifying Signatures

```rust
use solana_secp256k1_ecdsa::{Secp256k1EcdsaSignature, hash::Sha256};
use solana_secp256k1::Pubkey;

// Your message, signature, and public key
let message = b"Hello, Solana!";
let signature: Secp256k1EcdsaSignature = /* your signature */;
let public_key: Pubkey = /* your public key */;

// Verify the signature
signature.verify::<Sha256, _>(message, public_key)?;
```

## Security Notes

- When using `sign_with_k`, ensure your ephemeral key is truly random and never reused. Reusing or using predictable ephemeral keys can compromise your private key.
- The library provides `normalize_s` to handle signature malleability concerns. This is important for blockchain applications where transaction malleability could be an issue.

## Hash Implementations

Implement the `Secp256k1EcdsaHash` trait for custom hash algorithms:

```rust
use solana_secp256k1_ecdsa::hash::Secp256k1EcdsaHash;

struct MyCustomHash;

impl Secp256k1EcdsaHash for MyCustomHash {
    fn hash(message: &[u8]) -> [u8; 32] {
        // Your custom hash implementation
    }
}
```

## Disclaimer
Use this library at your own risk.

## License

MIT