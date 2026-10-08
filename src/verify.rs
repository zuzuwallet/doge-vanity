// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Rebuild a winning address from the secret with two stacks.
//!
//! The search stack is libsecp256k1, `sha2`, `ripemd`, and this crate's
//! Base58Check. The independent stack is `k256`, `bitcoin_hashes`, and `bs58`.
//! HD path math is the single BIP32 implementation, then the child scalar goes
//! through both address stacks. A mismatch is fatal.

use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::doge::keys::{address_from_hash, KeyEngine};
use crate::doge::script::{multisig_redeem, p2pkh_redeem};
use crate::doge::{
    format_path, receive_address, receive_steps, seed_from_entropy, AddressKind, SearchMode,
};
use crate::error::Error;
use crate::independent::{independent_multisig, independent_p2pkh, independent_p2sh_from_key};
use crate::wallet::WalletMaterial;

pub fn confirm_material(material: &WalletMaterial, address: &str) -> Result<(), Error> {
    let outcome = catch_unwind(AssertUnwindSafe(|| confirm_inner(material, address)));
    match outcome {
        Ok(result) => result,
        Err(_) => Err(Error::VerificationFailed),
    }
}

fn confirm_inner(material: &WalletMaterial, address: &str) -> Result<(), Error> {
    if material.network().name().is_empty() || address.is_empty() {
        return Err(Error::VerificationFailed);
    }
    match (material.kind(), material.mode()) {
        (AddressKind::P2pkh, SearchMode::HdIndex) => confirm_hd(material, address),
        (AddressKind::P2pkh, SearchMode::Independent) => confirm_p2pkh(material, address),
        (AddressKind::P2sh, SearchMode::Independent) => confirm_p2sh(material, address),
        (AddressKind::Multisig, SearchMode::Independent) => confirm_multisig(material, address),
        _ => Err(Error::VerificationFailed),
    }
}

fn confirm_p2pkh(material: &WalletMaterial, address: &str) -> Result<(), Error> {
    let key = material.sole_key()?;
    let engine = KeyEngine::new()?;
    let public = engine
        .public_of(key)
        .map_err(|_| Error::VerificationFailed)?;
    let ours = address_from_hash(material.network().p2pkh_version(), &public.hash160);
    let (independent_public, hash, independent) = independent_p2pkh(material.network(), key)?;
    if ours != address
        || independent != address
        || independent_public != public.key
        || hash != public.hash160
    {
        return Err(Error::VerificationFailed);
    }
    if !material.redeem().is_empty() || !material.path().is_empty() {
        return Err(Error::VerificationFailed);
    }
    Ok(())
}

fn confirm_p2sh(material: &WalletMaterial, address: &str) -> Result<(), Error> {
    let key = material.sole_key()?;
    let engine = KeyEngine::new()?;
    let public = engine
        .public_of(key)
        .map_err(|_| Error::VerificationFailed)?;
    let script = p2pkh_redeem(&public.hash160);
    let ours = address_from_hash(
        material.network().p2sh_version(),
        &crate::doge::hash::hash160(&script),
    );
    let (independent_script, independent) = independent_p2sh_from_key(material.network(), key)?;
    if ours != address
        || independent != address
        || independent_script.as_slice() != script.as_slice()
    {
        return Err(Error::VerificationFailed);
    }
    if material.redeem() != script.as_slice() {
        return Err(Error::VerificationFailed);
    }
    Ok(())
}

fn confirm_multisig(material: &WalletMaterial, address: &str) -> Result<(), Error> {
    let engine = KeyEngine::new()?;
    let mut publics = Vec::with_capacity(material.keys().len());
    for key in material.keys() {
        publics.push(
            engine
                .public_of(key)
                .map_err(|_| Error::VerificationFailed)?
                .key,
        );
    }
    let script =
        multisig_redeem(material.threshold(), &publics).map_err(|_| Error::VerificationFailed)?;
    let ours = address_from_hash(
        material.network().p2sh_version(),
        &crate::doge::hash::hash160(&script),
    );
    let independent_parts =
        independent_multisig(material.network(), material.threshold(), material.keys())?;
    if ours != address || independent_parts.address != address || independent_parts.redeem != script
    {
        return Err(Error::VerificationFailed);
    }
    if material.redeem() != script.as_slice() {
        return Err(Error::VerificationFailed);
    }
    if material.participants() as usize != material.keys().len() {
        return Err(Error::VerificationFailed);
    }
    Ok(())
}

fn confirm_hd(material: &WalletMaterial, address: &str) -> Result<(), Error> {
    let seed = seed_from_entropy(material.entropy())?;
    let engine = KeyEngine::new()?;
    let (child, ours) = receive_address(
        &engine,
        seed.as_slice(),
        material.network(),
        material.account(),
        material.index(),
    )
    .map_err(|_| Error::VerificationFailed)?;
    let steps = receive_steps(material.network(), material.account(), material.index())
        .map_err(|_| Error::VerificationFailed)?;
    let path = format_path(&steps);
    if path != material.path() || ours != address {
        return Err(Error::VerificationFailed);
    }
    let public = engine
        .public_of(child.key_bytes())
        .map_err(|_| Error::VerificationFailed)?;
    let (_pk, _hash, independent) = independent_p2pkh(material.network(), child.key_bytes())?;
    if independent != address || (public.key[0] != 0x02 && public.key[0] != 0x03) {
        return Err(Error::VerificationFailed);
    }
    let again = address_from_hash(material.network().p2pkh_version(), &public.hash160);
    if again != address {
        return Err(Error::VerificationFailed);
    }
    Ok(())
}
