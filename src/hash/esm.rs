use crate::*;

use solana_nostd_keccak::hashv;
pub struct ESM;

const MAGIC_BYTES: &[u8] = b"\x19Ethereum Signed Message:\n";

impl Secp256k1EcdsaHash for ESM {
    fn hash(message: &[u8]) -> [u8; 32] {
        let mut buffer = itoa::Buffer::new();
        let len_str = buffer.format(message.len());
        hashv(&[MAGIC_BYTES, len_str.as_bytes(), message])
    }
}