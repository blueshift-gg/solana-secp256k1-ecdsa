/// ### Secp256k1EcdsaHash
///
/// Defines a standard API for ECDSA hashing functions
pub trait Secp256k1EcdsaHash: Sized {
    fn hash(message: &[u8]) -> [u8; 32];
}

#[cfg(feature = "sha256")]
pub mod sha256;

#[cfg(feature = "sha256")]
pub mod sha256d;

#[cfg(feature = "keccak")]
pub mod keccak;

#[cfg(feature = "bsm")]
pub mod bsm;

#[cfg(feature = "esm")]
pub mod esm;
