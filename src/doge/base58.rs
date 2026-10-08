// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Dogecoin Base58 and Base58Check.
//!
//! The alphabet is Bitcoin's, which Dogecoin Core uses. `0`, `O`, `I`, and `l`
//! are not characters. The checksum is the first four bytes of double SHA-256.
//! Encode and decode working buffers are wiped. Public address text is an
//! ordinary `String`. WIF text is wrapped by the caller. Decode returns
//! `Zeroizing` because the same functions also decode a WIF.

use zeroize::Zeroizing;

use crate::doge::hash::checksum4;
use crate::error::Error;

pub(crate) const ALPHABET: &[u8; 58] =
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub(crate) fn alphabet_index(byte: u8) -> Option<u8> {
    ALPHABET
        .iter()
        .position(|candidate| *candidate == byte)
        .map(|index| index as u8)
}

pub(crate) fn base58_encode(bytes: &[u8]) -> String {
    let mut work = Zeroizing::new(bytes.to_vec());
    let mut digits = Zeroizing::new(Vec::with_capacity(bytes.len() * 138 / 100 + 2));
    while work.iter().any(|byte| *byte != 0) {
        let remainder = divmod58(&mut work);
        digits.push(ALPHABET[remainder as usize]);
    }
    for _ in bytes.iter().take_while(|byte| **byte == 0) {
        digits.push(b'1');
    }
    digits.reverse();
    String::from_utf8(digits.to_vec()).expect("base58 alphabet is ASCII")
}

pub(crate) fn base58check_encode(payload: &[u8]) -> String {
    let mut raw = Zeroizing::new(Vec::with_capacity(payload.len() + 4));
    raw.extend_from_slice(payload);
    raw.extend_from_slice(&checksum4(payload));
    base58_encode(&raw)
}

pub(crate) fn base58_decode(text: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut zeros = 0usize;
    let bytes = text.as_bytes();
    while zeros < bytes.len() && bytes[zeros] == b'1' {
        zeros += 1;
    }
    // Little-endian. `value[0]` is the least significant byte.
    let mut value = Zeroizing::new(vec![0u8; text.len()]);
    let mut length = 0usize;
    for byte in &bytes[zeros..] {
        let digit = alphabet_index(*byte).ok_or(Error::Base58)? as u16;
        let mut carry = digit;
        for slot in value.iter_mut().take(length) {
            let acc = u16::from(*slot) * 58 + carry;
            *slot = (acc & 0xff) as u8;
            carry = acc >> 8;
        }
        while carry > 0 {
            if length >= value.len() {
                return Err(Error::Base58);
            }
            value[length] = (carry & 0xff) as u8;
            length += 1;
            carry >>= 8;
        }
    }
    let mut out = Zeroizing::new(Vec::with_capacity(zeros + length));
    out.extend(std::iter::repeat_n(0u8, zeros));
    for byte in value[..length].iter().rev() {
        out.push(*byte);
    }
    Ok(out)
}

pub(crate) fn base58check_decode(text: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    let raw = base58_decode(text)?;
    if raw.len() < 4 {
        return Err(Error::Checksum);
    }
    let split = raw.len() - 4;
    let (payload, checksum) = raw.split_at(split);
    let expected = checksum4(payload);
    let mut diff = 0u8;
    for (left, right) in expected.iter().zip(checksum.iter()) {
        diff |= left ^ right;
    }
    if diff != 0 {
        return Err(Error::Checksum);
    }
    // Canonical text rejects a second encoding of the same bytes.
    // The re-encoded string can be a WIF, so it is wiped after the compare.
    let canonical = Zeroizing::new(base58_encode(&raw));
    if canonical.as_str() != text {
        return Err(Error::Base58);
    }
    let mut payload_out = Zeroizing::new(Vec::with_capacity(payload.len()));
    payload_out.extend_from_slice(payload);
    Ok(payload_out)
}

fn divmod58(bytes: &mut [u8]) -> u8 {
    let mut remainder = 0u16;
    for byte in bytes.iter_mut() {
        let acc = remainder * 256 + u16::from(*byte);
        *byte = (acc / 58) as u8;
        remainder = acc % 58;
    }
    remainder as u8
}

#[cfg(test)]
mod tests {
    use super::{alphabet_index, base58check_decode, base58check_encode};

    #[test]
    fn alphabet_rejects_the_excluded_characters() {
        for byte in *b"0OIl" {
            assert!(alphabet_index(byte).is_none());
        }
        assert_eq!(alphabet_index(b'Z'), Some(32));
        assert_eq!(alphabet_index(b'1'), Some(0));
        assert_eq!(alphabet_index(b'z'), Some(57));
    }

    #[test]
    fn empty_payload_checksum_round_trips() {
        let text = base58check_encode(&[]);
        assert!(base58check_decode(&text).unwrap().is_empty());
    }
}
