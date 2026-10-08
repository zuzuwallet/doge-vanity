// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Standard Dogecoin scripts.
//!
//! P2SH vanity uses a normal compressed P2PKH redeem script. Multisig uses
//! `OP_m <compressed keys> OP_n OP_CHECKMULTISIG` with BIP67 key order.
//! No extra nonce, `OP_DROP`, or nonstandard tail is added.
//!
//! Dogecoin Core 1.14.9 `AreInputsStandard` does not recursively require the
//! redeem script to pass `IsStandard`. It rejects a P2SH input whose sigop
//! count exceeds `MAX_P2SH_SIGOPS` (15). Bare multisig standardness is a
//! separate rule (n must be 1..=3) and this crate never emits a bare output.

use crate::error::Error;

pub const MAX_MULTISIG_KEYS: usize = 15;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKMULTISIG: u8 = 0xae;
const OP_DUP: u8 = 0x76;
const OP_HASH160: u8 = 0xa9;
const OP_EQUALVERIFY: u8 = 0x88;

pub fn check_policy(threshold: u8, participants: u8) -> Result<(), Error> {
    let participants = usize::from(participants);
    if threshold == 0 || participants == 0 || usize::from(threshold) > participants {
        return Err(Error::Policy);
    }
    if participants > MAX_MULTISIG_KEYS {
        return Err(Error::Policy);
    }
    Ok(())
}

/// `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG`.
pub fn p2pkh_redeem(hash: &[u8; 20]) -> [u8; 25] {
    let mut out = [0u8; 25];
    out[0] = OP_DUP;
    out[1] = OP_HASH160;
    out[2] = 20;
    out[3..23].copy_from_slice(hash);
    out[23] = OP_EQUALVERIFY;
    out[24] = OP_CHECKSIG;
    out
}

/// Standard multisig redeem script. Keys are sorted by raw compressed bytes.
pub fn multisig_redeem(threshold: u8, keys: &[[u8; 33]]) -> Result<Vec<u8>, Error> {
    let participants = u8::try_from(keys.len()).map_err(|_| Error::Policy)?;
    check_policy(threshold, participants)?;
    let mut ordered = keys.to_vec();
    ordered.sort();
    for pair in ordered.windows(2) {
        if pair[0] == pair[1] {
            return Err(Error::Policy);
        }
    }
    let mut script = Vec::with_capacity(1 + ordered.len() * 34 + 2);
    script.push(op_small(threshold)?);
    for key in &ordered {
        if key[0] != 0x02 && key[0] != 0x03 {
            return Err(Error::Policy);
        }
        script.push(33);
        script.extend_from_slice(key);
    }
    script.push(op_small(participants)?);
    script.push(OP_CHECKMULTISIG);
    Ok(script)
}

fn op_small(value: u8) -> Result<u8, Error> {
    if (1..=16).contains(&value) {
        Ok(0x50 + value)
    } else {
        Err(Error::Policy)
    }
}

#[cfg(test)]
mod tests {
    use super::{check_policy, multisig_redeem, p2pkh_redeem};

    #[test]
    fn p2pkh_redeem_is_the_standard_25_byte_script() {
        let mut hash = [0u8; 20];
        hash[0] = 0x75;
        let script = p2pkh_redeem(&hash);
        assert_eq!(script.len(), 25);
        assert_eq!(&script[..3], &[0x76, 0xa9, 0x14]);
        assert_eq!(&script[23..], &[0x88, 0xac]);
        assert_eq!(&script[3..23], &hash);
    }

    #[test]
    fn multisig_sorts_keys_and_keeps_the_threshold() {
        let mut low = [0u8; 33];
        let mut high = [0u8; 33];
        low[0] = 0x03;
        high[0] = 0x03;
        low[1] = 1;
        high[1] = 2;
        let script = multisig_redeem(2, &[high, low]).unwrap();
        assert_eq!(script[0], 0x52);
        assert_eq!(script[1], 33);
        assert_eq!(&script[2..35], &low);
        assert_eq!(script[35], 33);
        assert_eq!(&script[36..69], &high);
        assert_eq!(script[69], 0x52);
        assert_eq!(script[70], 0xae);
        assert!(check_policy(3, 5).is_ok());
        assert!(check_policy(2, 2).is_ok());
        assert!(check_policy(0, 2).is_err());
        assert!(check_policy(3, 2).is_err());
        assert!(check_policy(2, 16).is_err());
        assert!(multisig_redeem(1, &[low, low]).is_err());
    }
}
