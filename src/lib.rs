#![no_std]
pub mod errors;
pub mod hash;
#[cfg(test)]
mod tests;

use errors::Secp256k1EcdsaError;
use hash::Secp256k1EcdsaHash;
use solana_secp256k1::{Curve, Secp256k1Point};

pub const SECP256K1_ECDSA_SIGNATURE_LENGTH: usize = 64;

/// # Secp256k1EcdsaSignature
/// An ECDSA signature used for signature verification purposes.
#[derive(PartialEq, Debug)]
pub struct Secp256k1EcdsaSignature(pub [u8; SECP256K1_ECDSA_SIGNATURE_LENGTH]);

impl Secp256k1EcdsaSignature {
    pub fn r(&self) -> [u8; 32] {
        [
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6], self.0[7],
            self.0[8], self.0[9], self.0[10], self.0[11], self.0[12], self.0[13], self.0[14],
            self.0[15], self.0[16], self.0[17], self.0[18], self.0[19], self.0[20], self.0[21],
            self.0[22], self.0[23], self.0[24], self.0[25], self.0[26], self.0[27], self.0[28],
            self.0[29], self.0[30], self.0[31],
        ]
    }

    pub fn s(&self) -> [u8; 32] {
        [
            self.0[32], self.0[33], self.0[34], self.0[35], self.0[36], self.0[37], self.0[38],
            self.0[39], self.0[40], self.0[41], self.0[42], self.0[43], self.0[44], self.0[45],
            self.0[46], self.0[47], self.0[48], self.0[49], self.0[50], self.0[51], self.0[52],
            self.0[53], self.0[54], self.0[55], self.0[56], self.0[57], self.0[58], self.0[59],
            self.0[60], self.0[61], self.0[62], self.0[63],
        ]
    }
}

#[cfg(feature = "sign")]
impl Secp256k1EcdsaSignature {
    /// ### Sign with K
    /// Sign a message hashed with a valid implementation of the Secp256k1EcdsaHash trait and a defined ephemeral key.
    #[inline(always)]
    pub fn sign_with_k<H: Secp256k1EcdsaHash>(
        message: &[u8],
        k: &[u8; 32],
        privkey: &[u8; 32],
    ) -> Result<Secp256k1EcdsaSignature, Secp256k1EcdsaError> {
        let h = &H::hash(message);
        Self::sign_with_k_prehashed(h, k, privkey)
    }

    /// ### Sign with K
    /// Sign a message hashed with a valid implementation of the Secp256k1EcdsaHash trait and a defined ephemeral key.
    #[inline(always)]
    pub fn sign_with_k_prehashed(
        h: &[u8; 32],
        k: &[u8; 32],
        privkey: &[u8; 32],
    ) -> Result<Secp256k1EcdsaSignature, Secp256k1EcdsaError> {
        // Calculate our R
        let r = Curve::mul_g(k)
            .map_err(|_| Secp256k1EcdsaError::InvalidSecretKey)?
            .x();
        // Calculate k^-1
        let mod_inv_k = Curve::mod_inv_n(k).map_err(|_| Secp256k1EcdsaError::InvalidSecretKey)?;
        // Calculate s
        let p_mul_r_mod_n = Curve::mul_mod_n(&r, privkey); // Compute privkey * r mod n
        let sum = Curve::add_mod_n(h, &p_mul_r_mod_n); // Compute (h + privkey*r) mod n
        let s = Curve::mul_mod_n(&mod_inv_k, &sum); // Multiply by k⁻¹ mod n
                                                    // Assemble signature
        let mut sig = core::mem::MaybeUninit::<[u8; 64]>::uninit();
        unsafe {
            // Get mutable pointer to the uninitialized memory
            let sig_ptr = sig.as_mut_ptr();

            // Write r to the first 32 bytes (0..32)
            core::ptr::copy_nonoverlapping(r.as_ptr(), sig_ptr as *mut u8, 32);

            // Write s to the last 32 bytes (32..64)
            core::ptr::copy_nonoverlapping(s.as_ptr(), (sig_ptr as *mut u8).add(32), 32);

            // Return the initialized memory as a Secp256k1EcdsaSignature
            Ok(Secp256k1EcdsaSignature(sig.assume_init()))
        }
    }

    /// ### Sign
    /// Sign a signature with a standard RFC6979 deterministic nonce.
    pub fn sign<H: Secp256k1EcdsaHash>(
        message: &[u8],
        privkey: &[u8; 32],
    ) -> Result<Secp256k1EcdsaSignature, Secp256k1EcdsaError> {
        let h = H::hash(message);
        let k = &solana_rfc6979::rfc6979_generate(privkey, &Curve::N, &h);
        Self::sign_with_k::<H>(message, k, privkey)
    }

    #[inline(always)]
    pub fn normalize_s(&self) -> Self {
        let s = self.s();
        if s.cmp(&Curve::N_DIV_2) == core::cmp::Ordering::Greater {
            // Compute the negated s (n - s) once.
            let neg_s = Curve::negate_n(&s);
            let mut sig = core::mem::MaybeUninit::<[u8; 64]>::uninit();
            unsafe {
                // Get mutable pointer to the uninitialized memory
                let sig_ptr = sig.as_mut_ptr();

                // Write r to the first 32 bytes (0..32)
                core::ptr::copy_nonoverlapping(self.r().as_ptr(), sig_ptr as *mut u8, 32);

                // Write s to the last 32 bytes (32..64)
                core::ptr::copy_nonoverlapping(neg_s.as_ptr(), (sig_ptr as *mut u8).add(32), 32);

                // Return the initialized memory as a Secp256k1EcdsaSignature
                Secp256k1EcdsaSignature(sig.assume_init())
            }
        } else {
            Secp256k1EcdsaSignature(self.0)
        }
    }
}

impl Secp256k1EcdsaSignature {
    /// ### Verify
    /// Verify a signature against a valid implementation of the trait Secp256k1EcdsaHash.
    pub fn verify<H: Secp256k1EcdsaHash, T: Secp256k1Point>(
        &self,
        message: &[u8],
        pubkey: T,
    ) -> Result<(), Secp256k1EcdsaError> {
        // calculate message hash
        let h = H::hash(message);
        // s1 = s^-1 % N
        let s1 = Curve::mod_inv_n(&self.s()).map_err(|_| Secp256k1EcdsaError::InvalidSignature)?;
        // R' = (h * s1) * G + (r * s1) * pubKey
        let r_mul_s1 = Curve::mul_mod_n(&self.r(), &s1);
        // ecmul pubkey by r*s1
        let point = Curve::ecmul::<T>(&pubkey, &r_mul_s1)
            .map_err(|_| Secp256k1EcdsaError::InvalidSignature)?;
        // Calculate h * s1
        let h_mul_s1 = Curve::mul_mod_n(&h, &s1);
        // Tweak our point by h*s1
        let recovered_point = point
            .tweak(h_mul_s1)
            .map_err(|_| Secp256k1EcdsaError::InvalidSignature)?;
        // Compare r to x coordinate of recovered point
        if self.r().ne(&recovered_point.x()) {
            return Err(Secp256k1EcdsaError::InvalidSignature);
        }
        Ok(())
    }
}
