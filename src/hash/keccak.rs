use crate::*;

use solana_nostd_keccak::hashv;
pub struct Keccak;

impl Secp256k1EcdsaHash for Keccak {
    fn hash(message: &[u8]) -> [u8; 32] {
        hashv(&[message])
    }
}
