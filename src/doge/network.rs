// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Dogecoin network parameters.
//!
//! Checked against Dogecoin Core 1.14.9 `chainparams.cpp`
//! (`e0a1c157791544e818c901bd9341896965afbf9d`) and libdogecoin
//! `b4a79c34fbd95090494b0aa0c006d1b8f0de8e15` `chainparams.c`. Core master
//! `47a303a449999314abcf83bd1fc7e77dd4540fcd` uses the same Base58 versions.
//!
//! Regtest is omitted. Its public-key version `0x6f` and secret version `0xef`
//! are the Bitcoin testnet bytes. This crate will not emit them.
//!
//! There is no SegWit or Taproot parameter here. Core sets
//! `DEPLOYMENT_SEGWIT.nTimeout = 0` on mainnet and testnet, and it has no
//! Taproot deployment.

use crate::error::Error;

/// A Dogecoin network this tool will label explicitly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    pub fn parse(text: &str) -> Result<Self, Error> {
        match text {
            "mainnet" => Ok(Self::Mainnet),
            "testnet" => Ok(Self::Testnet),
            _ => Err(Error::prefix(
                "network must be mainnet or testnet; regtest is not supported",
            )),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Mainnet => "Mainnet",
            Self::Testnet => "Testnet",
        }
    }

    /// `base58Prefixes[PUBKEY_ADDRESS]`.
    pub fn p2pkh_version(self) -> u8 {
        match self {
            Self::Mainnet => 0x1e,
            Self::Testnet => 0x71,
        }
    }

    /// `base58Prefixes[SCRIPT_ADDRESS]`.
    pub fn p2sh_version(self) -> u8 {
        match self {
            Self::Mainnet => 0x16,
            Self::Testnet => 0xc4,
        }
    }

    /// `base58Prefixes[SECRET_KEY]`. Compressed WIF appends `0x01`.
    pub fn wif_version(self) -> u8 {
        match self {
            Self::Mainnet => 0x9e,
            Self::Testnet => 0xf1,
        }
    }

    /// `base58Prefixes[EXT_PUBLIC_KEY]`. Mainnet text starts with `dgub`.
    pub fn bip32_public(self) -> [u8; 4] {
        match self {
            Self::Mainnet => [0x02, 0xfa, 0xca, 0xfd],
            Self::Testnet => [0x04, 0x35, 0x87, 0xcf],
        }
    }

    /// `base58Prefixes[EXT_SECRET_KEY]`. Mainnet text starts with `dgpv`.
    pub fn bip32_private(self) -> [u8; 4] {
        match self {
            Self::Mainnet => [0x02, 0xfa, 0xc3, 0x98],
            Self::Testnet => [0x04, 0x35, 0x83, 0x94],
        }
    }

    /// SLIP-44 coin type. Testnet uses coin type 1 for every coin, not 3.
    pub fn coin_type(self) -> u32 {
        match self {
            Self::Mainnet => 3,
            Self::Testnet => 1,
        }
    }

    pub(crate) fn tag(self) -> u8 {
        match self {
            Self::Mainnet => 1,
            Self::Testnet => 2,
        }
    }

    pub(crate) fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Mainnet),
            2 => Some(Self::Testnet),
            _ => None,
        }
    }
}

/// Address family. Multisig is P2SH with a standard multisig redeem script.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressKind {
    P2pkh,
    P2sh,
    Multisig,
}

impl AddressKind {
    pub fn parse(text: &str) -> Result<Self, Error> {
        match text {
            "p2pkh" => Ok(Self::P2pkh),
            "p2sh" => Ok(Self::P2sh),
            "multisig" => Ok(Self::Multisig),
            _ => Err(Error::prefix(
                "address type must be p2pkh, p2sh, or multisig",
            )),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::P2pkh => "p2pkh",
            Self::P2sh => "p2sh",
            Self::Multisig => "multisig",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::P2pkh => "P2PKH",
            Self::P2sh => "P2SH",
            Self::Multisig => "Multisig P2SH",
        }
    }

    pub fn version(self, network: Network) -> u8 {
        match self {
            Self::P2pkh => network.p2pkh_version(),
            Self::P2sh | Self::Multisig => network.p2sh_version(),
        }
    }

    /// P2PKH and the single-key P2SH engine use one new key per attempt.
    pub fn is_single_key(self) -> bool {
        matches!(self, Self::P2pkh | Self::P2sh)
    }
}

/// How candidates are produced. HD index mode is P2PKH only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SearchMode {
    Independent,
    HdIndex,
}

impl SearchMode {
    pub fn parse(text: &str) -> Result<Self, Error> {
        match text {
            "independent" => Ok(Self::Independent),
            "hd-index" => Ok(Self::HdIndex),
            _ => Err(Error::prefix("mode must be independent or hd-index")),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Independent => "independent",
            Self::HdIndex => "hd-index",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AddressKind, Network};

    #[test]
    fn constants_are_not_bitcoin_or_litecoin_mainnet() {
        let doge = Network::Mainnet;
        assert_eq!(doge.p2pkh_version(), 0x1e);
        assert_eq!(doge.p2sh_version(), 0x16);
        assert_eq!(doge.wif_version(), 0x9e);
        assert_eq!(doge.bip32_public(), [0x02, 0xfa, 0xca, 0xfd]);
        assert_eq!(doge.bip32_private(), [0x02, 0xfa, 0xc3, 0x98]);
        assert_eq!(doge.coin_type(), 3);
        assert_ne!(doge.p2pkh_version(), 0x00);
        assert_ne!(doge.p2pkh_version(), 0x30);
        assert_ne!(doge.p2sh_version(), 0x05);
        assert_ne!(doge.wif_version(), 0x80);
        assert_ne!(doge.wif_version(), 0xb0);
        assert_ne!(doge.p2pkh_version(), Network::Testnet.p2pkh_version());
        assert_ne!(doge.coin_type(), Network::Testnet.coin_type());
        assert_eq!(Network::Testnet.coin_type(), 1);
        assert_eq!(Network::Testnet.p2pkh_version(), 0x71);
        assert_eq!(Network::Testnet.p2sh_version(), 0xc4);
        assert_eq!(Network::Testnet.wif_version(), 0xf1);
        assert_eq!(AddressKind::Multisig.version(doge), 0x16);
        assert_ne!(doge.p2pkh_version(), 0x6f);
        assert_ne!(doge.wif_version(), 0xef);
    }
}
