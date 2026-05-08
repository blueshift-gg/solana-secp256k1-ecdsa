#![cfg(all(feature = "sign", feature = "sha256"))]

use solana_secp256k1_ecdsa::{
    Scalar, Secp256k1EcdsaSignature, UncompressedPoint, hash::sha256::Sha256,
};
use svm_unit_test::svm_test;

const MESSAGE: &[u8] = b"Hello, Solana!";

const PRIVKEY: Scalar = Scalar([
    0xef, 0x23, 0x5a, 0xac, 0xf9, 0x0d, 0x9f, 0x4a, 0xad, 0xd8, 0xc9, 0x2e, 0x4b, 0x25, 0x62, 0xe1,
    0xd9, 0xeb, 0x97, 0xf0, 0xdf, 0x9b, 0xa3, 0xb5, 0x08, 0x25, 0x87, 0x39, 0xcb, 0x01, 0x3d, 0xb2,
]);

const K: Scalar = Scalar([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42,
]);

#[svm_test]
fn bench_sign() {
    let _ = Secp256k1EcdsaSignature::sign::<Sha256>(MESSAGE, &PRIVKEY);
}

#[svm_test]
fn bench_sign_with_k() {
    let _ = Secp256k1EcdsaSignature::sign_with_k::<Sha256>(MESSAGE, &K, &PRIVKEY);
}

#[svm_test]
fn bench_verify() {
    let signature = Secp256k1EcdsaSignature::sign::<Sha256>(MESSAGE, &PRIVKEY)
        .unwrap()
        .normalize_s();
    let pubkey = UncompressedPoint::try_from(PRIVKEY).unwrap();
    let _ = signature.verify::<Sha256, UncompressedPoint>(MESSAGE, pubkey);
}

#[svm_test]
fn bench_normalize_s() {
    let signature = Secp256k1EcdsaSignature::sign::<Sha256>(MESSAGE, &PRIVKEY).unwrap();
    let _ = signature.normalize_s();
}
