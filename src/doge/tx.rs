// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! One offline legacy SIGHASH_ALL fixture.
//!
//! This is not a broadcast transaction and it does not contact a node. It
//! signs a synthetic preimage with libsecp256k1 and checks that signature with
//! `k256`. Dogecoin Core 1.14 uses the legacy Bitcoin sighash for these
//! scripts.

use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};

use crate::doge::hash::sha256;
use crate::doge::keys::KeyEngine;
use crate::doge::script::p2pkh_redeem;
use crate::error::Error;

pub fn sign_and_verify_fixture(
    engine: &KeyEngine,
    key: &[u8; 32],
    hash160: &[u8; 20],
) -> Result<(), Error> {
    let script = p2pkh_redeem(hash160);
    let digest = legacy_sighash(&script);
    let compact = engine.sign_digest(key, &digest)?;
    let public = engine.public_of(key)?;
    let verifying =
        VerifyingKey::from_sec1_bytes(&public.key).map_err(|_| Error::VerificationFailed)?;
    let signature = Signature::from_slice(&compact).map_err(|_| Error::VerificationFailed)?;
    verifying
        .verify_prehash(&digest, &signature)
        .map_err(|_| Error::VerificationFailed)?;
    Ok(())
}

fn legacy_sighash(script_code: &[u8]) -> [u8; 32] {
    let mut raw = Vec::with_capacity(128);
    raw.extend_from_slice(&1u32.to_le_bytes());
    raw.push(1);
    raw.extend_from_slice(&[0u8; 32]);
    raw.extend_from_slice(&0u32.to_le_bytes());
    raw.push(script_code.len() as u8);
    raw.extend_from_slice(script_code);
    raw.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    raw.push(1);
    raw.extend_from_slice(&1u64.to_le_bytes());
    raw.push(script_code.len() as u8);
    raw.extend_from_slice(script_code);
    raw.extend_from_slice(&0u32.to_le_bytes());
    raw.extend_from_slice(&1u32.to_le_bytes());
    sha256(&sha256(&raw))
}
