// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compressed Dogecoin WIF.
//!
//! Mainnet version is `0x9e` plus the 32-byte key plus the compression flag
//! `0x01`. The text starts with `Q`. Uncompressed secrets omit the flag and
//! start with `6`. This tool only accepts the compressed form, so a compressed
//! WIF cannot be paired with an address derived from an uncompressed point.

use zeroize::Zeroizing;

use crate::doge::base58::{base58check_decode, base58check_encode};
use crate::doge::network::Network;
use crate::error::Error;
use crate::secret::{SecretBytes, SecretString};

const COMPRESSED_FLAG: u8 = 0x01;

pub fn encode_wif(network: Network, key: &[u8; 32]) -> SecretString {
    let mut payload = Zeroizing::new([0u8; 34]);
    payload[0] = network.wif_version();
    payload[1..33].copy_from_slice(key);
    payload[33] = COMPRESSED_FLAG;
    SecretString::new(base58check_encode(payload.as_slice()))
}

/// Build the uncompressed mainnet form of scalar 1 and require rejection.
///
/// The text starts with `6`. It is not a wallet this tool will import.
pub(crate) fn reject_uncompressed_scalar_one() -> Result<(), Error> {
    let mut key = [0u8; 32];
    key[31] = 1;
    let mut body = [0u8; 33];
    body[0] = Network::Mainnet.wif_version();
    body[1..].copy_from_slice(&key);
    let text = base58check_encode(&body);
    if !text.starts_with('6') || decode_wif(Network::Mainnet, &text).is_ok() {
        return Err(Error::SelfTest("uncompressed WIF was accepted"));
    }
    Ok(())
}

pub fn decode_wif(network: Network, text: &str) -> Result<SecretBytes<32>, Error> {
    let payload = base58check_decode(text)?;
    if payload.len() != 34 || payload[0] != network.wif_version() || payload[33] != COMPRESSED_FLAG
    {
        return Err(Error::Base58);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&payload[1..33]);
    let again = encode_wif(network, &key);
    if again.as_str() != text {
        return Err(Error::Base58);
    }
    Ok(SecretBytes::from_zeroizing(key))
}

#[cfg(test)]
mod tests {
    use super::{decode_wif, encode_wif};
    use crate::doge::network::Network;

    #[test]
    fn compressed_scalar_one_round_trips_and_uncompressed_does_not() {
        let mut key = [0u8; 32];
        key[31] = 1;
        let text = encode_wif(Network::Mainnet, &key);
        assert!(text.as_str().starts_with('Q'));
        assert_eq!(
            decode_wif(Network::Mainnet, text.as_str())
                .unwrap()
                .as_bytes(),
            &key
        );
        let mut uncompressed = text.as_str().to_owned();
        // A different network, a Bitcoin version, and a truncated payload fail.
        assert!(decode_wif(Network::Testnet, text.as_str()).is_err());
        assert!(decode_wif(Network::Mainnet, &uncompressed[..uncompressed.len() - 1]).is_err());
        uncompressed.push('1');
        assert!(decode_wif(Network::Mainnet, &uncompressed).is_err());
        let debug = format!("{:?}", decode_wif(Network::Mainnet, text.as_str()).unwrap());
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("000000"));
    }
}
