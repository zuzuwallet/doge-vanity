// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Address inspection. The first character is not treated as proof.

use crate::doge::base58::base58check_decode;
use crate::doge::network::Network;
use crate::hexutil;

pub fn inspect(address: &str) -> String {
    let leading: String = address.chars().take(5).collect();
    let mut out = String::new();
    out.push_str("Dogecoin Address Inspector\n\n");
    out.push_str("Encoding:\nBase58Check\n\n");
    out.push_str("Leading characters:\n");
    out.push_str(&leading);
    out.push_str("\n\n");

    let payload = match base58check_decode(address) {
        Ok(payload) => payload,
        Err(crate::error::Error::Checksum) => {
            out.push_str("Network:\nUnknown\n\nType:\nUnknown\n\nVersion:\nUnknown\n\nPayload:\nUnknown\n\nChecksum:\nFAIL\n\nValid:\nNO\n");
            out.push_str("The first character was not used to decide the type.\n");
            return out;
        }
        Err(_) => {
            out.push_str("Network:\nUnknown\n\nType:\nUnknown\n\nVersion:\nUnknown\n\nPayload:\nUnknown\n\nChecksum:\nFAIL\n\nValid:\nNO\n");
            out.push_str("The text is not canonical Base58.\n");
            return out;
        }
    };
    if payload.len() != 21 {
        out.push_str("Network:\nUnknown\n\nType:\nUnknown\n\nChecksum:\nPASS\n\nValid:\nNO\n");
        out.push_str("The payload length is not a Dogecoin P2PKH or P2SH address.\n");
        return out;
    }
    let version = payload[0];
    let hash = &payload[1..];
    let (network, kind, note) = match version {
        0x1e => (Some(Network::Mainnet), Some("P2PKH"), ""),
        0x16 => (Some(Network::Mainnet), Some("P2SH"), ""),
        0x71 => (Some(Network::Testnet), Some("P2PKH"), ""),
        0xc4 => (
            Some(Network::Testnet),
            Some("P2SH"),
            "Version 0xc4 is also Bitcoin testnet P2SH. This tool labels it Dogecoin testnet.\n",
        ),
        _ => (None, None, ""),
    };
    match network {
        Some(network) => {
            out.push_str("Network:\n");
            out.push_str(network.label());
            out.push('\n');
        }
        None => out.push_str("Network:\nUnknown\n"),
    }
    out.push('\n');
    match kind {
        Some(kind) => {
            out.push_str("Type:\n");
            out.push_str(kind);
            out.push('\n');
        }
        None => out.push_str("Type:\nUnknown\n"),
    }
    out.push('\n');
    out.push_str(&format!("Version:\n0x{version:02x}\n\n"));
    out.push_str("Payload:\n");
    out.push_str(&hexutil::encode_lower(hash));
    out.push_str("\n\nChecksum:\nPASS\n\n");
    if kind.is_some() {
        out.push_str("Valid:\nYES\n");
    } else {
        out.push_str("Valid:\nNO\n");
    }
    if !note.is_empty() {
        out.push('\n');
        out.push_str(note);
    }
    if kind == Some("P2SH") {
        out.push_str("P2SH covers both a standard redeem script and multisig. The address alone does not show which.\n");
    }
    out
}
