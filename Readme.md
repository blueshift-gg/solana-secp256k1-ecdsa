# Solana Secp256k1 ECDSA

[![CI](https://github.com/blueshift-gg/solana-secp256k1-ecdsa/actions/workflows/ci.yml/badge.svg)](https://github.com/blueshift-gg/solana-secp256k1-ecdsa/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/solana-secp256k1-ecdsa.svg)](https://crates.io/crates/solana-secp256k1-ecdsa)
[![docs.rs](https://docs.rs/solana-secp256k1-ecdsa/badge.svg)](https://docs.rs/solana-secp256k1-ecdsa)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/blueshift-gg/solana-secp256k1-ecdsa/blob/master/LICENSE)

A `no_std` compatible ECDSA implementation for the Secp256k1 curve, designed for use within the Solana ecosystem. Built on [`solana-secp256k1`](https://crates.io/crates/solana-secp256k1) primitives.

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
solana-secp256k1-ecdsa = "0.2.0"
```

### Creating Signatures

Enable the `sign` feature flag to use signature creation functionality:

```toml
[dependencies]
solana-secp256k1-ecdsa = { version = "0.2.0", features = ["sign"] }
```

#### Basic Signing

```rust
use solana_secp256k1_ecdsa::{Scalar, Secp256k1EcdsaSignature, hash::sha256::Sha256};

// Your message and private key
let message = b"Hello, Solana!";
let private_key = Scalar([/* your private key bytes */]);

// Sign the message
let signature = Secp256k1EcdsaSignature::sign::<Sha256>(message, &private_key)?;
```

#### Signing with a Custom Ephemeral Key

```rust
use solana_secp256k1_ecdsa::{Scalar, Secp256k1EcdsaSignature, hash::sha256::Sha256};

// Your message, ephemeral key, and private key
let message = b"Hello, Solana!";
let ephemeral_key = Scalar([/* your ephemeral key bytes */]);
let private_key = Scalar([/* your private key bytes */]);

// Sign with custom k
let signature = Secp256k1EcdsaSignature::sign_with_k::<Sha256>(
    message,
    &ephemeral_key,
    &private_key,
)?;
```

### Verifying Signatures

```rust
use solana_secp256k1_ecdsa::{
    Scalar, Secp256k1EcdsaSignature, UncompressedPoint, hash::sha256::Sha256,
};

// Your message, signature, and private key
let message = b"Hello, Solana!";
let signature: Secp256k1EcdsaSignature = /* your signature */;
let private_key = Scalar([/* your private key bytes */]);

// Derive the public key from the private key
let public_key = UncompressedPoint::try_from(private_key)?;

// Verify the signature
signature.verify::<Sha256, UncompressedPoint>(message, public_key)?;
```

## Static syscalls

If your target supports the Upstream BPF / sBPFv3 static-syscall ABI, enable the `static-syscalls` feature. The flag is forwarded to every dep in the stack (`solana-secp256k1`, `solana-rfc6979`, `solana-nostd-sha256`, `solana-nostd-keccak`) so the resulting `.so` calls each syscall directly via a murmur3-hashed fn-pointer transmute instead of an `extern "C"` PLT relocation.

```toml
[dependencies]
solana-secp256k1-ecdsa = { version = "0.2.0", features = ["static-syscalls"] }
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

Licensed under the [MIT License](https://github.com/blueshift-gg/solana-secp256k1-ecdsa/blob/master/LICENSE). The license includes the standard "as-is" warranty disclaimer — use at your own risk.