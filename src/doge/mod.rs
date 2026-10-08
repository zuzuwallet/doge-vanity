// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Dogecoin address derivation.
//!
//! The search path is libsecp256k1, `sha2`, `ripemd`, and this crate's
//! Base58Check. The independent check does not use those encoders. P2WPKH,
//! P2WSH, bech32, and Taproot are not implemented: current Dogecoin consensus
//! does not use them for ordinary wallet addresses.

pub(crate) mod base58;
pub(crate) mod hash;
pub(crate) mod hd;
mod inspect;
pub(crate) mod keys;
pub(crate) mod network;
mod prefix;
pub(crate) mod script;
pub(crate) mod tx;
mod uint;
pub(crate) mod wif;

pub use inspect::inspect;

pub use hd::{format_path, receive_steps, scan_gap, seed_from_entropy, GAP_LIMIT, HARDENED};
pub use keys::{address_from_hash, payload_for_hash, random_scalar, KeyEngine, Public};
pub use network::{AddressKind, Network, SearchMode};
pub(crate) use prefix::optimized_matches_text;
pub(crate) use prefix::SEARCH_COUNTER_HEADROOM;
pub use prefix::{
    analyze, group_digits, require_searchable, Analysis, Class, CONFIRMATION_THRESHOLD,
};
pub use script::check_policy;
pub use wif::{decode_wif, encode_wif};

pub(crate) use hd::{
    derive_index, derive_path, encode_xpub, master_from_seed, mnemonic_from_entropy,
    receive_address, HdNode,
};
pub(crate) use wif::reject_uncompressed_scalar_one;

pub(crate) use tx::sign_and_verify_fixture;
