// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Independent Dogecoin address derivation.
//!
//! `k256` derives the compressed secp256k1 point. `bitcoin_hashes` computes
//! HASH160 and the checksum. `bs58` encodes the 25 bytes with its check
//! feature off. None of those steps call this crate's Base58Check, `sha2`,
//! `ripemd`, or libsecp256k1.
//!
//! `k256::SecretKey` zeroizes its scalar on drop. Compiler, register, and
//! internal temporary copies can remain. The caller's buffer is the one this
//! crate wipes.
//!
//! Dogecoin Core and libdogecoin are not linked. This is a second Rust stack,
//! not those projects.

use bitcoin_hashes::{Ripemd160, Sha256};
use k256::elliptic_curve::sec1::ToEncodedPoint;

use crate::doge::network::Network;
use crate::doge::script::{multisig_redeem, p2pkh_redeem};
use crate::error::Error;

/// Compressed SEC1 public key from `k256`.
pub fn k256_compressed(key: &[u8; 32]) -> Result<[u8; 33], Error> {
    let secret = k256::SecretKey::from_slice(key).map_err(|_| Error::VerificationFailed)?;
    let point = secret.public_key().to_encoded_point(true);
    let bytes = point.as_bytes();
    if bytes.len() != 33 || (bytes[0] != 0x02 && bytes[0] != 0x03) {
        return Err(Error::VerificationFailed);
    }
    let mut public_key = [0u8; 33];
    public_key.copy_from_slice(bytes);
    drop(secret);
    Ok(public_key)
}

/// RIPEMD-160(SHA-256(data)) from `bitcoin_hashes`.
pub fn bitcoin_hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::hash(data);
    let ripe = Ripemd160::hash(sha.as_byte_array());
    *ripe.as_byte_array()
}

fn bitcoin_checksum4(data: &[u8]) -> [u8; 4] {
    let first = Sha256::hash(data);
    let second = Sha256::hash(first.as_byte_array());
    let mut out = [0u8; 4];
    out.copy_from_slice(&second.as_byte_array()[..4]);
    out
}

/// Versioned Base58Check from the independent hash and checksum.
pub fn independent_address(version: u8, hash: &[u8; 20]) -> String {
    let mut body = [0u8; 21];
    body[0] = version;
    body[1..].copy_from_slice(hash);
    let sum = bitcoin_checksum4(&body);
    let mut full = [0u8; 25];
    full[..21].copy_from_slice(&body);
    full[21..].copy_from_slice(&sum);
    bs58::encode(full).into_string()
}

pub fn independent_p2pkh(
    network: Network,
    key: &[u8; 32],
) -> Result<([u8; 33], [u8; 20], String), Error> {
    let public_key = k256_compressed(key)?;
    let hash = bitcoin_hash160(&public_key);
    let address = independent_address(network.p2pkh_version(), &hash);
    Ok((public_key, hash, address))
}

pub fn independent_p2sh_from_key(
    network: Network,
    key: &[u8; 32],
) -> Result<(Vec<u8>, String), Error> {
    let public_key = k256_compressed(key)?;
    let hash = bitcoin_hash160(&public_key);
    let script = p2pkh_redeem(&hash).to_vec();
    let script_hash = bitcoin_hash160(&script);
    let address = independent_address(network.p2sh_version(), &script_hash);
    Ok((script, address))
}

pub struct IndependentMultisig {
    pub public_keys: Vec<[u8; 33]>,
    pub redeem: Vec<u8>,
    pub address: String,
}

pub fn independent_multisig(
    network: Network,
    threshold: u8,
    keys: &[[u8; 32]],
) -> Result<IndependentMultisig, Error> {
    let mut publics = Vec::with_capacity(keys.len());
    for key in keys {
        publics.push(k256_compressed(key)?);
    }
    let script = multisig_redeem(threshold, &publics).map_err(|_| Error::VerificationFailed)?;
    let script_hash = bitcoin_hash160(&script);
    let address = independent_address(network.p2sh_version(), &script_hash);
    Ok(IndependentMultisig {
        public_keys: publics,
        redeem: script,
        address,
    })
}

pub(crate) fn independent_wif(network: Network, key: &[u8; 32]) -> String {
    let mut body = [0u8; 34];
    body[0] = network.wif_version();
    body[1..33].copy_from_slice(key);
    body[33] = 0x01;
    let sum = bitcoin_checksum4(&body);
    let mut full = [0u8; 38];
    full[..34].copy_from_slice(&body);
    full[34..].copy_from_slice(&sum);
    bs58::encode(full).into_string()
}

#[cfg(test)]
mod tests {
    use super::{independent_address, independent_p2pkh, independent_wif};
    use crate::doge::network::Network;

    #[test]
    fn empty_sha256_matches_the_fips_vector_through_bitcoin_hashes() {
        use bitcoin_hashes::sha256;
        let digest = sha256::Hash::hash(b"");
        assert_eq!(
            digest.as_byte_array(),
            &[
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55
            ]
        );
    }

    #[test]
    fn generator_address_matches_the_search_stack_without_calling_it() {
        let mut key = [0u8; 32];
        key[31] = 1;
        let (_public, hash, address) = independent_p2pkh(Network::Mainnet, &key).unwrap();
        assert_eq!(hex_of(&hash), "751e76e8199196d454941c45d1b3a323f1433bd6");
        assert_eq!(address, "DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE");
        assert_eq!(
            independent_address(0x00, &hash),
            "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
        );
        assert_ne!(
            independent_wif(Network::Mainnet, &key),
            independent_wif(Network::Testnet, &key)
        );
        assert!(independent_wif(Network::Mainnet, &key).starts_with('Q'));
    }

    fn hex_of(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::new();
        for byte in bytes {
            out.push(DIGITS[(byte >> 4) as usize] as char);
            out.push(DIGITS[(byte & 0x0f) as usize] as char);
        }
        out
    }
}
