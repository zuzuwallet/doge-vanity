// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Offline Dogecoin vanity address generator.
//!
//! The search path is libsecp256k1, `sha2`, `ripemd`, and this crate's
//! Base58Check. The independent check uses `k256`, `bitcoin_hashes`, and
//! `bs58` with the check feature off. HD derivation is one BIP32
//! implementation. The child scalar is then checked by both address stacks.
//!
//! This crate does not create P2WPKH, P2WSH, bech32, or Taproot addresses.
//! Dogecoin Core 1.14 leaves SegWit timed out, and ordinary Dogecoin wallets
//! do not spend those outputs.

#![forbid(unsafe_code)]

pub mod doge;
pub mod error;
mod hexutil;
pub mod independent;
pub mod search;
pub mod secret;
pub mod self_test;
pub mod verify;
pub mod wallet;

pub use doge::{
    address_from_hash, analyze, check_policy, decode_wif, encode_wif, group_digits, inspect,
    payload_for_hash, random_scalar, require_searchable, scan_gap, seed_from_entropy, AddressKind,
    Analysis, Class, KeyEngine, Network, Public, SearchMode, CONFIRMATION_THRESHOLD, GAP_LIMIT,
    HARDENED,
};
pub use error::Error;
pub use search::{
    counter_would_overflow, measure_miss_rate, search, validate_threads, SearchHit, SearchRequest,
    COUNTER_HEADROOM, MAX_THREADS,
};
pub use secret::{SecretBytes, SecretString};
pub use self_test::run_self_tests;
pub use verify::confirm_material;
pub use wallet::{
    check_new_passphrase, check_passphrase, export_wallet_text, open_and_verify,
    write_encrypted_wallet, KdfParams, OpenedWallet, WalletMaterial, MIN_NEW_PASSPHRASE_CHARS,
};
