#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Secp256k1EcdsaError {
    InvalidSecretKey = 1,
    InvalidPublicKey = 2,
    InvalidRecoveryId = 3,
    InvalidSignature = 4,
    InvalidNonce = 5,
    ArithmeticOverflow = 6,
}
