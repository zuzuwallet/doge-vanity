// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Dogecoin BIP32 / BIP39 / BIP44.
//!
//! There is one BIP32 implementation. Published vectors lock the path math.
//! The independent address check re-derives the final public key from the
//! child scalar with `k256` and `bitcoin_hashes`. It does not reimplement
//! CKD. Dogecoin Core 1.14 has no BIP39 import, and a gap limit of 20 does
//! not scan a high child index.
//!
//! Mainnet receive path: `m/44'/3'/account'/0/index`. Testnet coin type is 1.
//! The index stays in `0 .. 2^31`. It is never hardened, and change stays 0.
//! The BIP39 passphrase is empty. That is the interoperability default, not a
//! secret supplied on the command line. The HMAC key is the BIP32 string
//! `Bitcoin seed`.

use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::{Zeroize, Zeroizing};

use crate::doge::hash::hash160;
use crate::doge::keys::{address_from_hash, KeyEngine};
use crate::doge::network::Network;
use crate::error::Error;

pub const HARDENED: u32 = 0x8000_0000;
pub const GAP_LIMIT: u32 = 20;

#[derive(Clone)]
pub struct HdNode {
    pub depth: u8,
    pub child_number: u32,
    pub parent_fingerprint: [u8; 4],
    chain_code: Zeroizing<[u8; 32]>,
    key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for HdNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HdNode")
            .field("depth", &self.depth)
            .field("child_number", &self.child_number)
            .field("key", &"[redacted]")
            .field("chain_code", &"[redacted]")
            .finish()
    }
}

impl HdNode {
    pub fn key_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    pub(crate) fn from_private(
        key: Zeroizing<[u8; 32]>,
        chain_code: Zeroizing<[u8; 32]>,
        depth: u8,
    ) -> Self {
        Self {
            depth,
            child_number: 0,
            parent_fingerprint: [0; 4],
            chain_code,
            key,
        }
    }
}

pub fn master_from_seed(seed: &[u8]) -> Result<HdNode, Error> {
    if !(16..=64).contains(&seed.len()) {
        return Err(Error::Index);
    }
    let mut mac = hmac_sha512(b"Bitcoin seed", seed)?;
    let mut key = Zeroizing::new([0u8; 32]);
    let mut chain = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&mac[..32]);
    chain.copy_from_slice(&mac[32..]);
    mac.zeroize();
    // The master key must be a valid scalar. BIP32 rejects IL >= n or 0.
    let engine = KeyEngine::new()?;
    engine.public_of(key.as_slice())?;
    Ok(HdNode {
        depth: 0,
        child_number: 0,
        parent_fingerprint: [0; 4],
        chain_code: chain,
        key,
    })
}

pub fn derive_index(engine: &KeyEngine, parent: &HdNode, index: u32) -> Result<HdNode, Error> {
    let mut data = Zeroizing::new(Vec::with_capacity(37));
    if index >= HARDENED {
        data.push(0x00);
        data.extend_from_slice(parent.key.as_slice());
    } else {
        let public = engine.public_of(parent.key.as_slice())?;
        data.extend_from_slice(&public.key);
    }
    data.extend_from_slice(&index.to_be_bytes());
    let mut mac = hmac_sha512(parent.chain_code.as_slice(), &data)?;
    let mut tweak = Zeroizing::new([0u8; 32]);
    let mut chain = Zeroizing::new([0u8; 32]);
    tweak.copy_from_slice(&mac[..32]);
    chain.copy_from_slice(&mac[32..]);
    mac.zeroize();
    let child_key = engine.add_tweak_bytes(parent.key.as_slice(), tweak.as_slice())?;
    let public = engine.public_of(parent.key.as_slice())?;
    let ripe = hash160(&public.key);
    let mut fingerprint = [0u8; 4];
    fingerprint.copy_from_slice(&ripe[..4]);
    let depth = parent.depth.checked_add(1).ok_or(Error::Index)?;
    Ok(HdNode {
        depth,
        child_number: index,
        parent_fingerprint: fingerprint,
        chain_code: chain,
        key: child_key,
    })
}

pub fn receive_steps(network: Network, account: u32, index: u32) -> Result<[u32; 5], Error> {
    if account >= HARDENED || index >= HARDENED {
        return Err(Error::Index);
    }
    Ok([
        44 | HARDENED,
        network.coin_type() | HARDENED,
        account | HARDENED,
        0,
        index,
    ])
}

pub fn format_path(steps: &[u32]) -> String {
    let mut out = String::from("m");
    for step in steps {
        if step & HARDENED == 0 {
            out.push_str(&format!("/{step}"));
        } else {
            out.push_str(&format!("/{}'", step & !HARDENED));
        }
    }
    out
}

pub fn derive_path(engine: &KeyEngine, master: &HdNode, steps: &[u32]) -> Result<HdNode, Error> {
    let mut node = master.clone();
    for step in steps {
        node = derive_index(engine, &node, *step)?;
    }
    Ok(node)
}

pub fn receive_address(
    engine: &KeyEngine,
    seed: &[u8],
    network: Network,
    account: u32,
    index: u32,
) -> Result<(HdNode, String), Error> {
    let master = master_from_seed(seed)?;
    let steps = receive_steps(network, account, index)?;
    let child = derive_path(engine, &master, &steps)?;
    let public = engine.public_of(child.key_bytes())?;
    let address = address_from_hash(network.p2pkh_version(), &public.hash160);
    Ok((child, address))
}

/// Addresses a gap-limited scanner would see. The caller compares a high index
/// against this list. This does not claim a wallet will find that index.
pub fn scan_gap(
    engine: &KeyEngine,
    seed: &[u8],
    network: Network,
    account: u32,
    limit: u32,
) -> Result<Vec<String>, Error> {
    let mut found = Vec::with_capacity(limit as usize);
    for index in 0..limit {
        let (_, address) = receive_address(engine, seed, network, account, index)?;
        found.push(address);
    }
    Ok(found)
}

pub fn mnemonic_from_entropy(entropy: &[u8; 32]) -> Result<Zeroizing<String>, Error> {
    let mnemonic = bip39::Mnemonic::from_entropy(entropy).map_err(|_| Error::Index)?;
    let phrase = Zeroizing::new(mnemonic.to_string());
    Ok(phrase)
}

pub fn seed_from_entropy(entropy: &[u8]) -> Result<Zeroizing<[u8; 64]>, Error> {
    let entropy: &[u8; 32] = entropy.try_into().map_err(|_| Error::Index)?;
    let mnemonic = bip39::Mnemonic::from_entropy(entropy).map_err(|_| Error::Index)?;
    // Empty BIP39 passphrase. Callers do not pass a secret passphrase here.
    let seed = mnemonic.to_seed("");
    Ok(Zeroizing::new(seed))
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> Result<Zeroizing<[u8; 64]>, Error> {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).map_err(|_| Error::Index)?;
    mac.update(data);
    let mut bytes = mac.finalize().into_bytes();
    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(&bytes);
    bytes.zeroize();
    Ok(out)
}

/// Extended public key. The chain code is part of a public BIP32 node.
pub fn encode_xpub(network: Network, node: &HdNode, engine: &KeyEngine) -> Result<String, Error> {
    let public = engine.public_of(node.key_bytes())?;
    let mut body = Vec::with_capacity(78);
    body.extend_from_slice(&network.bip32_public());
    body.push(node.depth);
    body.extend_from_slice(&node.parent_fingerprint);
    body.extend_from_slice(&node.child_number.to_be_bytes());
    body.extend_from_slice(node.chain_code());
    body.extend_from_slice(&public.key);
    Ok(crate::doge::base58::base58check_encode(&body))
}

#[cfg(test)]
mod tests {
    use super::{
        encode_xpub, format_path, master_from_seed, receive_address, receive_steps, scan_gap,
        seed_from_entropy, HARDENED,
    };
    use crate::doge::keys::KeyEngine;
    use crate::doge::network::Network;

    #[test]
    fn bip32_vector_1_master_matches_the_published_bytes() {
        let seed = hex("000102030405060708090a0b0c0d0e0f");
        let master = master_from_seed(&seed).unwrap();
        assert_eq!(
            master.key_bytes(),
            &hex32("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")
        );
        assert_eq!(
            master.chain_code(),
            &hex32("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508")
        );
    }

    #[test]
    fn libdogecoin_account_node_matches_the_published_dgub() {
        let seed = hex("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4");
        let engine = KeyEngine::new().unwrap();
        let master = master_from_seed(&seed).unwrap();
        let steps = [44 | HARDENED, 3 | HARDENED, HARDENED];
        let node = super::derive_path(&engine, &master, &steps).unwrap();
        let dgub = encode_xpub(Network::Mainnet, &node, &engine).unwrap();
        assert_eq!(
            dgub,
            "dgub8rUhDtD3YFGZTUphBfpBbzvFxSMKQXYLzg87Me2ta78r2SdVLmypBUkkxrrn9RTnchsyiJSkHZyLWxD13ibBiXtuFWktBoDaGaZjQUBLNLs"
        );
        assert!(dgub.starts_with("dgub"));
    }

    #[test]
    fn all_zoo_entropy_matches_libdogecoin_address_and_gap_limit() {
        let entropy = [0xffu8; 32];
        let phrase = super::mnemonic_from_entropy(&entropy).unwrap();
        assert_eq!(
            phrase.as_str(),
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"
        );
        let seed = seed_from_entropy(&entropy).unwrap();
        let engine = KeyEngine::new().unwrap();
        let (_, address) =
            receive_address(&engine, seed.as_slice(), Network::Mainnet, 0, 0).unwrap();
        assert_eq!(address, "DTdKu8YgcxoXyjFCDtCeKimaZzsK27rcwT");
        let steps = receive_steps(Network::Mainnet, 0, 0).unwrap();
        assert_eq!(format_path(&steps), "m/44'/3'/0'/0/0");
        assert_eq!(
            format_path(&receive_steps(Network::Testnet, 0, 1).unwrap()),
            "m/44'/1'/0'/0/1"
        );
        let (_, high) =
            receive_address(&engine, seed.as_slice(), Network::Mainnet, 0, 100).unwrap();
        let scanned = scan_gap(&engine, seed.as_slice(), Network::Mainnet, 0, 20).unwrap();
        assert_eq!(scanned.len(), 20);
        assert!(!scanned.contains(&high));
        assert!(receive_steps(Network::Mainnet, 0, HARDENED).is_err());
    }

    fn hex32(text: &str) -> [u8; 32] {
        hex(text).try_into().unwrap()
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect()
    }
}
