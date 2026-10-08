// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Known-answer tests. A failure aborts before a reachable search starts.
//!
//! The generator scalar is the SEC 1 value 1. Its compressed point, HASH160,
//! Dogecoin P2PKH address, Bitcoin address, and Litecoin address are public.
//! The WIF text of that scalar is compared between the two stacks and is not
//! stored as a second copy in this file.

use crate::doge::hash::{hash160, ripemd160, sha256};
use crate::doge::script::{multisig_redeem, p2pkh_redeem};
use crate::doge::{
    address_from_hash, analyze, derive_path, encode_wif, encode_xpub, master_from_seed,
    mnemonic_from_entropy, receive_address, reject_uncompressed_scalar_one, seed_from_entropy,
    sign_and_verify_fixture, AddressKind, Class, KeyEngine, Network, HARDENED,
};
use crate::error::Error;
use crate::independent::{independent_p2pkh, independent_p2sh_from_key, independent_wif};
use crate::verify::confirm_material;
use crate::wallet::WalletMaterial;

const GENERATOR_PUBKEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const GENERATOR_HASH: &str = "751e76e8199196d454941c45d1b3a323f1433bd6";
const DOGE_ADDRESS: &str = "DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE";
const BITCOIN_ADDRESS: &str = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
const LITECOIN_ADDRESS: &str = "LVuDpNCSSj6pQ7t9Pv6d6sUkLKoqDEVUnJ";
const TESTNET_ADDRESS: &str = "nesRpRaAbTDmZHwmzBkLd2AtF7Z9L9z5S2";
const UNCOMPRESSED_ADDRESS: &str = "DJRU7MLhcPwCTNRZ4e8gJzDebtG1H5M7pc";
const UNCOMPRESSED_HASH: &str = "91b24bf9f5288532960ac687abb035127b1d28a5";
const P2SH_ADDRESS: &str = "ABAkrai6zU5KXkcbrBdtSo3Yee2saibFuM";
const TESTNET_P2SH: &str = "2NByiBUaEXrhmqAsg7BbLpcQSAQs1EDwt5w";
const TWO_G: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

const BIP32_SEED: &str = "000102030405060708090a0b0c0d0e0f";
const BIP32_SECRET: &str = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35";
const BIP32_CHAIN: &str = "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508";
const LIBDOGE_SEED: &str = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
const LIBDOGE_DGUB: &str = "dgub8rUhDtD3YFGZTUphBfpBbzvFxSMKQXYLzg87Me2ta78r2SdVLmypBUkkxrrn9RTnchsyiJSkHZyLWxD13ibBiXtuFWktBoDaGaZjQUBLNLs";
const ZOO_ADDRESS: &str = "DTdKu8YgcxoXyjFCDtCeKimaZzsK27rcwT";

pub fn run_self_tests() -> Result<(), Error> {
    check_hashes()?;
    check_generator()?;
    check_uncompressed_mismatch()?;
    check_p2sh()?;
    check_wif()?;
    check_hd()?;
    check_signature()?;
    check_prefixes()?;
    Ok(())
}

fn check_hashes() -> Result<(), Error> {
    let empty = sha256(b"");
    if empty
        != [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ]
    {
        return Err(Error::SelfTest("SHA-256 empty-string vector mismatch"));
    }
    let abc = ripemd160(b"abc");
    if abc
        != [
            0x8e, 0xb2, 0x08, 0xf7, 0xe0, 0x5d, 0x98, 0x7a, 0x9b, 0x04, 0x4a, 0x8e, 0x98, 0xc6,
            0xb0, 0x87, 0xf1, 0x5a, 0x0b, 0xfc,
        ]
    {
        return Err(Error::SelfTest("RIPEMD-160 abc vector mismatch"));
    }
    Ok(())
}

fn generator_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    key[31] = 1;
    key
}

fn check_generator() -> Result<(), Error> {
    let key = generator_key();
    let engine =
        KeyEngine::new().map_err(|_| Error::SelfTest("could not randomize libsecp256k1"))?;
    let public = engine
        .public_of(&key)
        .map_err(|_| Error::SelfTest("generator scalar was rejected"))?;
    if hex(&public.key) != GENERATOR_PUBKEY {
        return Err(Error::SelfTest("generator public key mismatch"));
    }
    if hex(&public.hash160) != GENERATOR_HASH {
        return Err(Error::SelfTest("generator HASH160 mismatch"));
    }
    let doge = address_from_hash(Network::Mainnet.p2pkh_version(), &public.hash160);
    let bitcoin = address_from_hash(0x00, &public.hash160);
    let litecoin = address_from_hash(0x30, &public.hash160);
    let testnet = address_from_hash(Network::Testnet.p2pkh_version(), &public.hash160);
    if doge != DOGE_ADDRESS
        || bitcoin != BITCOIN_ADDRESS
        || litecoin != LITECOIN_ADDRESS
        || testnet != TESTNET_ADDRESS
    {
        return Err(Error::SelfTest("generator address mismatch"));
    }
    if doge == bitcoin || doge == litecoin || doge == testnet || bitcoin == litecoin {
        return Err(Error::SelfTest("cross-chain addresses collided"));
    }
    let (independent_key, independent_hash, independent) =
        independent_p2pkh(Network::Mainnet, &key)?;
    if independent_key != public.key || independent_hash != public.hash160 || independent != doge {
        return Err(Error::SelfTest(
            "independent stack disagreed on the generator",
        ));
    }
    let material =
        WalletMaterial::p2pkh(Network::Mainnet, zeroize::Zeroizing::new(key), public.key);
    confirm_material(&material, DOGE_ADDRESS)?;
    if confirm_material(&material, UNCOMPRESSED_ADDRESS).is_ok() {
        return Err(Error::SelfTest(
            "compressed key was accepted for the uncompressed address",
        ));
    }
    let mut two = [0u8; 32];
    two[31] = 2;
    let point = engine
        .public_of(&two)
        .map_err(|_| Error::SelfTest("scalar 2 was rejected"))?;
    if hex(&point.key) != TWO_G {
        return Err(Error::SelfTest("2*G compressed point mismatch"));
    }
    Ok(())
}

fn check_uncompressed_mismatch() -> Result<(), Error> {
    let uncompressed: [u8; 65] = [
        0x04, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98, 0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc,
        0x0e, 0x11, 0x08, 0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0,
        0x8f, 0xfb, 0x10, 0xd4, 0xb8,
    ];
    let hash = hash160(&uncompressed);
    if hex(&hash) != UNCOMPRESSED_HASH {
        return Err(Error::SelfTest("uncompressed generator HASH160 mismatch"));
    }
    let address = address_from_hash(Network::Mainnet.p2pkh_version(), &hash);
    if address != UNCOMPRESSED_ADDRESS || address == DOGE_ADDRESS {
        return Err(Error::SelfTest(
            "uncompressed generator address did not stay distinct",
        ));
    }
    Ok(())
}

fn check_p2sh() -> Result<(), Error> {
    let key = generator_key();
    let engine =
        KeyEngine::new().map_err(|_| Error::SelfTest("could not randomize libsecp256k1"))?;
    let public = engine
        .public_of(&key)
        .map_err(|_| Error::SelfTest("generator scalar was rejected"))?;
    let script = p2pkh_redeem(&public.hash160);
    let address = address_from_hash(Network::Mainnet.p2sh_version(), &hash160(&script));
    let testnet = address_from_hash(Network::Testnet.p2sh_version(), &hash160(&script));
    if address != P2SH_ADDRESS || testnet != TESTNET_P2SH || address == testnet {
        return Err(Error::SelfTest("P2SH vector mismatch"));
    }
    let (independent_script, independent) = independent_p2sh_from_key(Network::Mainnet, &key)?;
    if independent != address || independent_script.as_slice() != script.as_slice() {
        return Err(Error::SelfTest("independent P2SH stack disagreed"));
    }
    let material = WalletMaterial::p2sh(
        Network::Mainnet,
        zeroize::Zeroizing::new(key),
        script.to_vec(),
        public.key,
    );
    confirm_material(&material, P2SH_ADDRESS)?;
    let mut second = [0u8; 32];
    second[31] = 2;
    let other = engine
        .public_of(&second)
        .map_err(|_| Error::SelfTest("scalar 2 was rejected"))?;
    let redeem = multisig_redeem(2, &[public.key, other.key])
        .map_err(|_| Error::SelfTest("2-of-2 redeem script was rejected"))?;
    let keys = zeroize::Zeroizing::new(vec![key, second]);
    let multi_address = address_from_hash(Network::Mainnet.p2sh_version(), &hash160(&redeem));
    let multi = WalletMaterial::multisig(Network::Mainnet, 2, keys, redeem);
    confirm_material(&multi, &multi_address)?;
    Ok(())
}

fn check_wif() -> Result<(), Error> {
    let key = generator_key();
    let text = encode_wif(Network::Mainnet, &key);
    if !text.as_str().starts_with('Q') {
        return Err(Error::SelfTest(
            "compressed mainnet WIF did not start with Q",
        ));
    }
    if independent_wif(Network::Mainnet, &key) != text.as_str() {
        return Err(Error::SelfTest("independent WIF disagreed"));
    }
    if crate::doge::decode_wif(Network::Testnet, text.as_str()).is_ok() {
        return Err(Error::SelfTest("mainnet WIF decoded as testnet"));
    }
    reject_uncompressed_scalar_one()?;
    Ok(())
}

fn check_hd() -> Result<(), Error> {
    let seed = parse_hex(BIP32_SEED)?;
    let master =
        master_from_seed(&seed).map_err(|_| Error::SelfTest("BIP32 master was rejected"))?;
    if hex(master.key_bytes()) != BIP32_SECRET || hex(master.chain_code()) != BIP32_CHAIN {
        return Err(Error::SelfTest("BIP32 vector 1 master mismatch"));
    }
    let lib_seed = parse_hex(LIBDOGE_SEED)?;
    let engine =
        KeyEngine::new().map_err(|_| Error::SelfTest("could not randomize libsecp256k1"))?;
    let lib_master = master_from_seed(&lib_seed)
        .map_err(|_| Error::SelfTest("libdogecoin seed was rejected"))?;
    let account = derive_path(
        &engine,
        &lib_master,
        &[44 | HARDENED, 3 | HARDENED, HARDENED],
    )
    .map_err(|_| Error::SelfTest("libdogecoin account path was rejected"))?;
    let dgub = encode_xpub(Network::Mainnet, &account, &engine)
        .map_err(|_| Error::SelfTest("dgub encoding failed"))?;
    if dgub != LIBDOGE_DGUB {
        return Err(Error::SelfTest("libdogecoin dgub mismatch"));
    }
    let entropy = [0xffu8; 32];
    let phrase = mnemonic_from_entropy(&entropy).map_err(|_| Error::SelfTest("mnemonic failed"))?;
    if !phrase.as_str().ends_with("zoo vote") {
        return Err(Error::SelfTest(
            "published all-ones entropy phrase mismatch",
        ));
    }
    let zoo_seed = seed_from_entropy(&entropy).map_err(|_| Error::SelfTest("seed failed"))?;
    let (child, address) = receive_address(&engine, zoo_seed.as_slice(), Network::Mainnet, 0, 0)
        .map_err(|_| Error::SelfTest("receive address failed"))?;
    if address != ZOO_ADDRESS {
        return Err(Error::SelfTest("libdogecoin zoo address mismatch"));
    }
    let child_public = engine
        .public_of(child.key_bytes())
        .map_err(|_| Error::SelfTest("child public key failed"))?;
    let material = WalletMaterial::hd(
        Network::Mainnet,
        zeroize::Zeroizing::new(entropy),
        0,
        0,
        "m/44'/3'/0'/0/0".to_owned(),
        child_public.key,
    );
    confirm_material(&material, ZOO_ADDRESS)?;
    Ok(())
}

fn check_signature() -> Result<(), Error> {
    let key = generator_key();
    let engine =
        KeyEngine::new().map_err(|_| Error::SelfTest("could not randomize libsecp256k1"))?;
    let public = engine
        .public_of(&key)
        .map_err(|_| Error::SelfTest("generator scalar was rejected"))?;
    sign_and_verify_fixture(&engine, &key, &public.hash160)
        .map_err(|_| Error::SelfTest("offline signature fixture failed"))?;
    Ok(())
}

fn check_prefixes() -> Result<(), Error> {
    let impossible = analyze(Network::Mainnet, AddressKind::P2pkh, "DZuZu")?;
    if impossible.class != Class::Impossible || impossible.expected.is_some() {
        return Err(Error::SelfTest("DZuZu was treated as reachable"));
    }
    let target = analyze(Network::Mainnet, AddressKind::P2pkh, "DAZuZu")?;
    if target.class != Class::Full
        || target.expected != Some(264_104_224)
        || target.median != Some(183_063_098)
        || target.needs_large_search_confirmation()
    {
        return Err(Error::SelfTest("DAZuZu difficulty changed"));
    }
    let p2sh = analyze(Network::Mainnet, AddressKind::P2sh, "AZuZu")?;
    if p2sh.class != Class::Impossible {
        return Err(Error::SelfTest("AZuZu was treated as reachable"));
    }
    let p2sh_ok = analyze(Network::Mainnet, AddressKind::P2sh, "A1ZuZu")?;
    if p2sh_ok.expected != Some(264_104_224) {
        return Err(Error::SelfTest("A1ZuZu difficulty changed"));
    }
    let rare = analyze(Network::Mainnet, AddressKind::P2pkh, "DAZuZuZ")?;
    if rare.class != Class::Full
        || rare.expected != Some(15_318_045_009)
        || !rare.needs_large_search_confirmation()
    {
        return Err(Error::SelfTest("DAZuZuZ difficulty changed"));
    }
    let rare_lines = rare.hd_lines();
    if !rare_lines.contains("13.08%")
        || !rare_lines.contains("not reachable within this mnemonic")
        || !rare.needs_hd_exhaust_confirmation()
    {
        return Err(Error::SelfTest("DAZuZuZ HD window changed"));
    }
    let target_lines = target.hd_lines();
    if !target_lines.contains("99.97%")
        || target_lines.contains("not reachable within this mnemonic")
        || target.needs_hd_exhaust_confirmation()
    {
        return Err(Error::SelfTest("DAZuZu HD window changed"));
    }
    if analyze(Network::Mainnet, AddressKind::P2pkh, "DOGE").is_ok() {
        return Err(Error::SelfTest("DOGE was accepted"));
    }
    Ok(())
}

fn parse_hex(text: &str) -> Result<Vec<u8>, Error> {
    if !text.len().is_multiple_of(2) {
        return Err(Error::SelfTest("hex vector has an odd length"));
    }
    (0..text.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&text[index..index + 2], 16)
                .map_err(|_| Error::SelfTest("hex vector is not hexadecimal"))
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}
