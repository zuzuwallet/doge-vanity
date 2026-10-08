// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! HASH160 and the Base58Check checksum.
//!
//! HASH160 is RIPEMD-160(SHA-256(data)), as Dogecoin P2PKH requires.
//! The checksum is the first 4 bytes of SHA-256(SHA-256(payload)).

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub(crate) fn ripemd160(data: &[u8]) -> [u8; 20] {
    let digest = Ripemd160::digest(data);
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest);
    out
}

pub(crate) fn hash160(data: &[u8]) -> [u8; 20] {
    ripemd160(&sha256(data))
}

pub(crate) fn checksum4(payload: &[u8]) -> [u8; 4] {
    let second = sha256(&sha256(payload));
    let mut out = [0u8; 4];
    out.copy_from_slice(&second[..4]);
    out
}

#[cfg(test)]
mod tests {
    use super::{hash160, ripemd160, sha256};

    #[test]
    fn sha256_of_empty_is_the_nist_vector() {
        assert_eq!(
            sha256(b""),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55
            ]
        );
    }

    #[test]
    fn ripemd160_of_abc_is_the_published_vector() {
        assert_eq!(
            ripemd160(b"abc"),
            [
                0x8e, 0xb2, 0x08, 0xf7, 0xe0, 0x5d, 0x98, 0x7a, 0x9b, 0x04, 0x4a, 0x8e, 0x98, 0xc6,
                0xb0, 0x87, 0xf1, 0x5a, 0x0b, 0xfc
            ]
        );
    }

    #[test]
    fn hash160_of_the_generator_is_the_published_bitcoin_hash() {
        let pubkey = hex_33("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        assert_eq!(
            hash160(&pubkey),
            hex_20("751e76e8199196d454941c45d1b3a323f1433bd6")
        );
    }

    fn hex_33(text: &str) -> [u8; 33] {
        let bytes = hex(text);
        bytes.try_into().unwrap()
    }

    fn hex_20(text: &str) -> [u8; 20] {
        let bytes = hex(text);
        bytes.try_into().unwrap()
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect()
    }
}
