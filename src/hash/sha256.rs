use crate::*;

use solana_nostd_sha256::hashv;
pub struct Sha256;

impl Secp256k1EcdsaHash for Sha256 {
    fn hash(message: &[u8]) -> [u8; 32] {
        hashv(&[message])
    }
}
