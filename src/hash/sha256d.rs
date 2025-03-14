use crate::*;

use solana_nostd_sha256::hashv;
pub struct Sha256d;

impl Secp256k1EcdsaHash for Sha256d {
    fn hash(message: &[u8]) -> [u8; 32] {
        hashv(&[&hashv(&[message])])
    }
}
