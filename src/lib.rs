#![no_std]
pub mod hash;
#[cfg(test)]
mod tests;

pub use solana_secp256k1::{CompressedPoint, Scalar, Secp256k1, Secp256k1Point, UncompressedPoint};

use hash::Secp256k1EcdsaHash;
use solana_program_error::ProgramError;

pub const SECP256K1_ECDSA_SIGNATURE_LENGTH: usize = 64;

/// # Secp256k1EcdsaSignature
/// An ECDSA signature used for signature verification purposes.
#[derive(PartialEq, Debug)]
pub struct Secp256k1EcdsaSignature(pub [u8; SECP256K1_ECDSA_SIGNATURE_LENGTH]);

impl Secp256k1EcdsaSignature {
    pub fn r(&self) -> Scalar {
        Scalar([
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6], self.0[7],
            self.0[8], self.0[9], self.0[10], self.0[11], self.0[12], self.0[13], self.0[14],
            self.0[15], self.0[16], self.0[17], self.0[18], self.0[19], self.0[20], self.0[21],
            self.0[22], self.0[23], self.0[24], self.0[25], self.0[26], self.0[27], self.0[28],
            self.0[29], self.0[30], self.0[31],
        ])
    }

    pub fn s(&self) -> Scalar {
        Scalar([
            self.0[32], self.0[33], self.0[34], self.0[35], self.0[36], self.0[37], self.0[38],
            self.0[39], self.0[40], self.0[41], self.0[42], self.0[43], self.0[44], self.0[45],
            self.0[46], self.0[47], self.0[48], self.0[49], self.0[50], self.0[51], self.0[52],
            self.0[53], self.0[54], self.0[55], self.0[56], self.0[57], self.0[58], self.0[59],
            self.0[60], self.0[61], self.0[62], self.0[63],
        ])
    }
}

#[cfg(feature = "sign")]
impl Secp256k1EcdsaSignature {
    /// ### Sign with K
    /// Sign a message hashed with a valid implementation of the Secp256k1EcdsaHash trait and a defined ephemeral key.
    #[inline(always)]
    pub fn sign_with_k<H: Secp256k1EcdsaHash>(
        message: &[u8],
        k: &Scalar,
        privkey: &Scalar,
    ) -> Result<Secp256k1EcdsaSignature, ProgramError> {
        let h = Scalar(H::hash(message));
        Self::sign_with_k_prehashed(&h, k, privkey)
    }

    /// ### Sign with K
    /// Sign a message hashed with a valid implementation of the Secp256k1EcdsaHash trait and a defined ephemeral key.
    #[inline(always)]
    pub fn sign_with_k_prehashed(
        h: &Scalar,
        k: &Scalar,
        privkey: &Scalar,
    ) -> Result<Secp256k1EcdsaSignature, ProgramError> {
        // Calculate our R
        let r = Secp256k1::mul_g(&k.0)
            .map_err(|_| ProgramError::InvalidArgument)?
            .x();
        // Calculate k^-1
        let mod_inv_k = Secp256k1::mod_inv_n(&k.0).map_err(|_| ProgramError::InvalidArgument)?;
        // Calculate s
        let p_mul_r_mod_n = Secp256k1::mul_mod_n(&r, &privkey.0); // Compute privkey * r mod n
        let sum = Secp256k1::add_mod_n(&h.0, &p_mul_r_mod_n); // Compute (h + privkey*r) mod n
        let s = Secp256k1::mul_mod_n(&mod_inv_k, &sum); // Multiply by k⁻¹ mod n
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
        privkey: &Scalar,
    ) -> Result<Secp256k1EcdsaSignature, ProgramError> {
        let h = H::hash(message);
        let k = Scalar(solana_rfc6979::rfc6979_generate(
            &privkey.0,
            &Secp256k1::N,
            &h,
        ));
        Self::sign_with_k::<H>(message, &k, privkey)
    }

    #[inline(always)]
    pub fn normalize_s(&self) -> Self {
        let s = self.s();
        if s.0.cmp(&Secp256k1::N_DIV_2) == core::cmp::Ordering::Greater {
            // Compute the negated s (n - s) once.
            let neg_s = Secp256k1::negate_n(&s.0);
            let mut sig = core::mem::MaybeUninit::<[u8; 64]>::uninit();
            unsafe {
                // Get mutable pointer to the uninitialized memory
                let sig_ptr = sig.as_mut_ptr();

                // Write r to the first 32 bytes (0..32)
                core::ptr::copy_nonoverlapping(self.r().0.as_ptr(), sig_ptr as *mut u8, 32);

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
    ) -> Result<(), ProgramError> {
        // calculate message hash
        let h = H::hash(message);
        // s1 = s^-1 % N
        let s1 = Secp256k1::mod_inv_n(&self.s().0).map_err(|_| ProgramError::InvalidArgument)?;
        // R' = (h * s1) * G + (r * s1) * pubKey
        let r_mul_s1 = Secp256k1::mul_mod_n(&self.r().0, &s1);
        // ecmul pubkey by r*s1
        let point =
            Secp256k1::ecmul::<T>(&pubkey, &r_mul_s1).map_err(|_| ProgramError::InvalidArgument)?;
        // Calculate h * s1
        let h_mul_s1 = Secp256k1::mul_mod_n(&h, &s1);
        // Tweak our point by h*s1
        let recovered_point = point
            .tweak(h_mul_s1)
            .map_err(|_| ProgramError::InvalidArgument)?;
        // Compare r to x coordinate of recovered point
        if self.r().0.ne(&recovered_point.x()) {
            return Err(ProgramError::InvalidArgument);
        }
        Ok(())
    }
}
