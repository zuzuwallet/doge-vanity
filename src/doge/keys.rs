// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compressed secp256k1 keys and Dogecoin versioned payloads.
//!
//! The search uses libsecp256k1. `k256` is only used by the independent check.
//! `SecretKey::from_slice` rejects 0 and scalars at or above the curve order.
//! This crate does not reduce a candidate modulo the order.
//!
//! Public keys are compressed. An uncompressed encoding is not a generation
//! mode. Tests lock that the two encodings produce different addresses.

use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use zeroize::Zeroizing;

use crate::doge::base58::{base58_encode, base58check_encode};
use crate::doge::hash::{checksum4, hash160};
use crate::error::Error;

pub const PAYLOAD_LEN: usize = 25;
pub const BODY_LEN: usize = 21;
pub const MAX_ADDRESS_LEN: usize = 35;

/// One worker's libsecp256k1 context.
///
/// The `rand` feature stays off. `new` draws 32 bytes from `getrandom` and
/// passes them to `seeded_randomize` once. The seed buffer is wiped after the
/// call. The context keeps the blinding state. There is no timer reseed.
pub struct KeyEngine {
    secp: Secp256k1<secp256k1::SignOnly>,
}

/// Borrows the one `SecretKey` and overwrites it on drop.
///
/// `SecretKey` is `Copy`, so a wrapper that owned another `SecretKey` would
/// copy the scalar and leave the first value in place. This guard only holds
/// a reference. `non_secure_erase` writes `[1u8; 32]`, not zeros. Compiler
/// copies, registers, and copies inside public-key generation can remain.
struct EraseGuard<'a>(&'a mut SecretKey);

impl Drop for EraseGuard<'_> {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Public {
    pub key: [u8; 33],
    pub hash160: [u8; 20],
}

impl KeyEngine {
    pub fn new() -> Result<Self, Error> {
        let mut secp = Secp256k1::signing_only();
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(seed.as_mut_slice()).map_err(|_| Error::Rng)?;
        secp.seeded_randomize(&seed);
        Ok(Self { secp })
    }

    pub fn public_of(&self, key: &[u8]) -> Result<Public, Error> {
        let mut secret = SecretKey::from_slice(key).map_err(|_| Error::InvalidKey)?;
        let guard = EraseGuard(&mut secret);
        let public = PublicKey::from_secret_key(&self.secp, guard.0);
        drop(guard);
        let compressed = public.serialize();
        if compressed[0] != 0x02 && compressed[0] != 0x03 {
            return Err(Error::InvalidKey);
        }
        Ok(Public {
            key: compressed,
            hash160: hash160(&compressed),
        })
    }

    /// Add a BIP32 tweak. `InvalidKey` means the child is not usable.
    pub(crate) fn add_tweak_bytes(
        &self,
        key: &[u8],
        tweak: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, Error> {
        let tweak: &[u8; 32] = tweak.try_into().map_err(|_| Error::InvalidKey)?;
        let mut scalar = Scalar::from_be_bytes(*tweak).map_err(|_| Error::InvalidKey)?;
        let mut parent = SecretKey::from_slice(key).map_err(|_| Error::InvalidKey)?;
        let tweaked = {
            let guard = EraseGuard(&mut parent);
            let result = guard.0.add_tweak(&scalar);
            scalar.non_secure_erase();
            result
        };
        let mut child = tweaked.map_err(|_| Error::InvalidKey)?;
        let out = Zeroizing::new(child.secret_bytes());
        child.non_secure_erase();
        Ok(out)
    }

    pub(crate) fn sign_digest(&self, key: &[u8; 32], digest: &[u8; 32]) -> Result<[u8; 64], Error> {
        let mut secret = SecretKey::from_slice(key).map_err(|_| Error::InvalidKey)?;
        let guard = EraseGuard(&mut secret);
        let message = secp256k1::Message::from_digest(*digest);
        let signature = self.secp.sign_ecdsa(&message, guard.0);
        drop(guard);
        Ok(signature.serialize_compact())
    }
}

/// 256 bits from the OS CSPRNG. BIP39 entropy is not a secp256k1 scalar.
pub fn random_entropy_32() -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut entropy = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(entropy.as_mut_slice()).map_err(|_| Error::Rng)?;
    Ok(entropy)
}

/// Draw one uniform valid scalar. Rejected draws are not returned.
pub fn random_scalar() -> Result<Zeroizing<[u8; 32]>, Error> {
    for _ in 0..1024 {
        let mut key = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(key.as_mut_slice()).map_err(|_| Error::Rng)?;
        let mut secret = match SecretKey::from_slice(key.as_slice()) {
            Ok(secret) => secret,
            Err(_) => continue,
        };
        secret.non_secure_erase();
        return Ok(key);
    }
    Err(Error::Rng)
}

pub fn payload_for_hash(version: u8, hash: &[u8; 20]) -> [u8; PAYLOAD_LEN] {
    let mut body = [0u8; BODY_LEN];
    body[0] = version;
    body[1..].copy_from_slice(hash);
    finish_payload(&body)
}

pub fn finish_payload(body: &[u8; BODY_LEN]) -> [u8; PAYLOAD_LEN] {
    let sum = checksum4(body);
    let mut payload = [0u8; PAYLOAD_LEN];
    payload[..BODY_LEN].copy_from_slice(body);
    payload[BODY_LEN..].copy_from_slice(&sum);
    payload
}

/// Base58 of the 25-byte payload. The checksum is already inside `payload`.
pub fn encode_payload(payload: &[u8; PAYLOAD_LEN]) -> String {
    base58_encode(payload)
}

/// Reference encoding: version || hash, then Base58Check.
pub fn address_from_hash(version: u8, hash: &[u8; 20]) -> String {
    let mut body = [0u8; BODY_LEN];
    body[0] = version;
    body[1..].copy_from_slice(hash);
    base58check_encode(&body)
}

#[cfg(test)]
mod tests {
    use super::{address_from_hash, KeyEngine};
    use crate::doge::network::Network;

    #[test]
    fn generator_key_matches_the_dogecoin_mainnet_address() {
        let mut key = [0u8; 32];
        key[31] = 1;
        let public = KeyEngine::new().unwrap().public_of(&key).unwrap();
        assert_eq!(
            public.key,
            hex33("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        );
        assert_eq!(
            public.hash160,
            hex20("751e76e8199196d454941c45d1b3a323f1433bd6")
        );
        assert_eq!(
            address_from_hash(Network::Mainnet.p2pkh_version(), &public.hash160),
            "DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE"
        );
        assert_eq!(
            address_from_hash(0x00, &public.hash160),
            "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
        );
        assert_eq!(
            address_from_hash(0x30, &public.hash160),
            "LVuDpNCSSj6pQ7t9Pv6d6sUkLKoqDEVUnJ"
        );
        assert_eq!(
            address_from_hash(Network::Testnet.p2pkh_version(), &public.hash160),
            "nesRpRaAbTDmZHwmzBkLd2AtF7Z9L9z5S2"
        );
    }

    #[test]
    fn two_times_the_generator_is_the_sec2_point() {
        let mut key = [0u8; 32];
        key[31] = 2;
        let public = KeyEngine::new().unwrap().public_of(&key).unwrap();
        assert_eq!(
            public.key,
            hex33("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
        );
    }

    #[test]
    fn zero_and_the_curve_order_are_rejected() {
        let engine = KeyEngine::new().unwrap();
        assert!(engine.public_of(&[0u8; 32]).is_err());
        let order = hex32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        assert!(engine.public_of(&order).is_err());
        let below = hex32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140");
        assert!(engine.public_of(&below).is_ok());
    }

    fn hex33(text: &str) -> [u8; 33] {
        hex(text).try_into().unwrap()
    }

    fn hex32(text: &str) -> [u8; 32] {
        hex(text).try_into().unwrap()
    }

    fn hex20(text: &str) -> [u8; 20] {
        hex(text).try_into().unwrap()
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect()
    }
}
