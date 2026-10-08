// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Encrypted wallet file.
//!
//! The secret is an Argon2id key (RFC 9106 section 4, second recommended
//! option: 64 MiB, t=3, p=4, version 0x13, 16-byte salt, 32-byte output) and
//! ChaCha20-Poly1305. Associated data binds the address, network, type, mode,
//! compression flag, threshold, participant count, redeem script, and
//! derivation path.
//!
//! The file is created with mode `0600` via `O_CREAT|O_EXCL` and `O_NOFOLLOW`
//! on read. `hard_link` publishes it only when the destination is still absent.
//! `confirm_material` runs before any ciphertext is written.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Block, Params, Version};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::doge::keys::KeyEngine;
use crate::doge::{
    encode_wif, format_path, mnemonic_from_entropy, receive_address, receive_steps,
    seed_from_entropy, AddressKind, Network, SearchMode,
};
use crate::error::Error;
use crate::hexutil;
use crate::secret::SecretString;
use crate::verify::confirm_material;

const FORMAT_VERSION: u32 = 1;
const KDF_NAME: &str = "argon2id";
const KDF_VERSION: u32 = 19;
const CIPHER_NAME: &str = "chacha20poly1305";
const AAD_PREFIX: &[u8] = b"doge-vanity-wallet-v1\0";
const MAX_WALLET_BYTES: u64 = 1_048_576;
const MAX_PLAINTEXT: usize = 4096;
const MAX_MEMORY_KIB: u32 = 1_048_576;
const MAX_ITERATIONS: u32 = 100;
const MAX_PARALLELISM: u32 = 16;
const TAG_LEN: usize = 16;
/// Linux `O_NOFOLLOW`. Do not follow a symlink.
const O_NOFOLLOW: i32 = 0x20000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfParams {
    pub const PRODUCTION: Self = Self {
        memory_kib: 65_536,
        iterations: 3,
        parallelism: 4,
    };

    pub fn is_production(self) -> bool {
        self == Self::PRODUCTION
    }

    pub(crate) fn within_caps(self) -> bool {
        self.iterations >= 1
            && self.iterations <= MAX_ITERATIONS
            && self.parallelism >= 1
            && self.parallelism <= MAX_PARALLELISM
            && self.memory_kib >= self.parallelism.saturating_mul(8)
            && self.memory_kib <= MAX_MEMORY_KIB
    }
}

/// Secret material for one wallet. `Debug` redacts keys and entropy.
pub struct WalletMaterial {
    network: Network,
    kind: AddressKind,
    mode: SearchMode,
    keys: Zeroizing<Vec<[u8; 32]>>,
    entropy: Zeroizing<[u8; 32]>,
    has_entropy: bool,
    account: u32,
    index: u32,
    threshold: u8,
    participants: u8,
    redeem: Vec<u8>,
    path: String,
    public_key: [u8; 33],
}

impl std::fmt::Debug for WalletMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletMaterial")
            .field("network", &self.network)
            .field("kind", &self.kind)
            .field("mode", &self.mode)
            .field("keys", &"[redacted]")
            .field("entropy", &"[redacted]")
            .field("path", &self.path)
            .field("threshold", &self.threshold)
            .field("participants", &self.participants)
            .finish()
    }
}

impl WalletMaterial {
    pub(crate) fn p2pkh(network: Network, key: Zeroizing<[u8; 32]>, public_key: [u8; 33]) -> Self {
        Self::single(network, AddressKind::P2pkh, key, Vec::new(), public_key)
    }

    pub(crate) fn p2sh(
        network: Network,
        key: Zeroizing<[u8; 32]>,
        redeem: Vec<u8>,
        public_key: [u8; 33],
    ) -> Self {
        Self::single(network, AddressKind::P2sh, key, redeem, public_key)
    }

    fn single(
        network: Network,
        kind: AddressKind,
        key: Zeroizing<[u8; 32]>,
        redeem: Vec<u8>,
        public_key: [u8; 33],
    ) -> Self {
        Self {
            network,
            kind,
            mode: SearchMode::Independent,
            keys: Zeroizing::new(vec![*key]),
            entropy: Zeroizing::new([0; 32]),
            has_entropy: false,
            account: 0,
            index: 0,
            threshold: 0,
            participants: 1,
            redeem,
            path: String::new(),
            public_key,
        }
    }

    pub(crate) fn multisig(
        network: Network,
        threshold: u8,
        keys: Zeroizing<Vec<[u8; 32]>>,
        redeem: Vec<u8>,
    ) -> Self {
        let participants = keys.len() as u8;
        Self {
            network,
            kind: AddressKind::Multisig,
            mode: SearchMode::Independent,
            keys,
            entropy: Zeroizing::new([0; 32]),
            has_entropy: false,
            account: 0,
            index: 0,
            threshold,
            participants,
            redeem,
            path: String::new(),
            public_key: [0; 33],
        }
    }

    pub(crate) fn hd(
        network: Network,
        entropy: Zeroizing<[u8; 32]>,
        account: u32,
        index: u32,
        path: String,
        public_key: [u8; 33],
    ) -> Self {
        Self {
            network,
            kind: AddressKind::P2pkh,
            mode: SearchMode::HdIndex,
            keys: Zeroizing::new(Vec::new()),
            entropy,
            has_entropy: true,
            account,
            index,
            threshold: 0,
            participants: 0,
            redeem: Vec::new(),
            path,
            public_key,
        }
    }

    pub fn network(&self) -> Network {
        self.network
    }
    pub fn kind(&self) -> AddressKind {
        self.kind
    }
    pub fn mode(&self) -> SearchMode {
        self.mode
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn redeem(&self) -> &[u8] {
        &self.redeem
    }
    pub fn threshold(&self) -> u8 {
        self.threshold
    }
    pub fn participants(&self) -> u8 {
        self.participants
    }
    pub fn account(&self) -> u32 {
        self.account
    }
    pub fn index(&self) -> u32 {
        self.index
    }
    pub fn public_key(&self) -> [u8; 33] {
        self.public_key
    }
    pub(crate) fn keys(&self) -> &[[u8; 32]] {
        &self.keys
    }
    pub(crate) fn entropy(&self) -> &[u8; 32] {
        &self.entropy
    }
    pub(crate) fn sole_key(&self) -> Result<&[u8; 32], Error> {
        if self.keys.len() == 1 {
            Ok(&self.keys[0])
        } else {
            Err(Error::VerificationFailed)
        }
    }
}

pub struct OpenedWallet {
    pub address: String,
    pub network: Network,
    pub kind: AddressKind,
    pub mode: SearchMode,
    pub path: String,
    pub redeem_hex: String,
    pub threshold: u8,
    pub participants: u8,
    pub public_key: [u8; 33],
    pub(crate) material: WalletMaterial,
}

impl std::fmt::Debug for OpenedWallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedWallet")
            .field("address", &self.address)
            .field("network", &self.network)
            .field("kind", &self.kind)
            .field("material", &self.material)
            .finish()
    }
}

pub const MIN_NEW_PASSPHRASE_CHARS: usize = 12;

pub fn check_passphrase(passphrase: &str) -> Result<(), Error> {
    if passphrase.is_empty() || passphrase.len() > 1024 {
        Err(Error::Passphrase)
    } else {
        Ok(())
    }
}

pub fn check_new_passphrase(passphrase: &str) -> Result<(), Error> {
    check_passphrase(passphrase)?;
    if passphrase.chars().count() < MIN_NEW_PASSPHRASE_CHARS {
        Err(Error::Passphrase)
    } else {
        Ok(())
    }
}

pub fn write_encrypted_wallet(
    path: &Path,
    passphrase: &str,
    material: &WalletMaterial,
    address: &str,
) -> Result<(), Error> {
    check_new_passphrase(passphrase)?;
    if path.exists() {
        return Err(Error::OutputExists);
    }
    write_encrypted_wallet_with_kdf(path, passphrase, material, address, &KdfParams::PRODUCTION)
}

pub(crate) fn write_encrypted_wallet_with_kdf(
    path: &Path,
    passphrase: &str,
    material: &WalletMaterial,
    address: &str,
    kdf: &KdfParams,
) -> Result<(), Error> {
    check_passphrase(passphrase)?;
    if !kdf.within_caps() {
        return Err(Error::WalletFormat);
    }
    if path.exists() {
        return Err(Error::OutputExists);
    }
    confirm_material(material, address)?;
    let meta = public_meta(material, address);
    let plaintext = encode_plaintext(material)?;
    let mut salt = Zeroizing::new([0u8; 16]);
    let mut nonce = Zeroizing::new([0u8; 12]);
    getrandom::getrandom(salt.as_mut_slice()).map_err(|_| Error::Rng)?;
    getrandom::getrandom(nonce.as_mut_slice()).map_err(|_| Error::Rng)?;
    let ciphertext = encrypt(passphrase, &plaintext, &meta, kdf, &salt, &nonce)?;
    let file = WalletFile {
        format_version: FORMAT_VERSION,
        network: meta.network,
        address_type: meta.kind,
        mode: meta.mode,
        public_address: meta.address,
        public_key_compression: "compressed".to_owned(),
        derivation_path: meta.path,
        threshold: u32::from(material.threshold),
        participants: u32::from(material.participants),
        redeem_script_hex: meta.redeem_hex,
        kdf: KDF_NAME.to_owned(),
        kdf_parameters: KdfFile {
            version: KDF_VERSION,
            memory_kib: kdf.memory_kib,
            iterations: kdf.iterations,
            parallelism: kdf.parallelism,
        },
        salt: STANDARD.encode(salt.as_slice()),
        cipher: CIPHER_NAME.to_owned(),
        nonce: STANDARD.encode(nonce.as_slice()),
        ciphertext: STANDARD.encode(&ciphertext),
    };
    let mut json = serde_json::to_string_pretty(&file).map_err(|_| Error::WalletFormat)?;
    json.push('\n');
    write_private_file(path, json.as_bytes())
}

pub fn export_wallet_text(opened: &OpenedWallet) -> Result<SecretString, Error> {
    export_text(&opened.material, &opened.address)
}

pub fn open_and_verify(path: &Path, passphrase: &str) -> Result<OpenedWallet, Error> {
    open_and_verify_inner(path, passphrase, true)
}

#[cfg(test)]
pub(crate) fn open_and_verify_with_kdf(
    path: &Path,
    passphrase: &str,
) -> Result<OpenedWallet, Error> {
    open_and_verify_inner(path, passphrase, false)
}

fn open_and_verify_inner(
    path: &Path,
    passphrase: &str,
    require_production: bool,
) -> Result<OpenedWallet, Error> {
    check_passphrase(passphrase)?;
    let file = read_wallet(path)?;
    if file.format_version != FORMAT_VERSION
        || file.kdf != KDF_NAME
        || file.cipher != CIPHER_NAME
        || file.kdf_parameters.version != KDF_VERSION
        || file.public_key_compression != "compressed"
    {
        return Err(Error::WalletFormat);
    }
    let kdf = KdfParams {
        memory_kib: file.kdf_parameters.memory_kib,
        iterations: file.kdf_parameters.iterations,
        parallelism: file.kdf_parameters.parallelism,
    };
    let accepted = if require_production {
        kdf.is_production()
    } else {
        kdf.within_caps()
    };
    if !accepted {
        return Err(Error::WalletFormat);
    }
    let meta = Meta {
        address: file.public_address.clone(),
        network: file.network.clone(),
        kind: file.address_type.clone(),
        mode: file.mode.clone(),
        path: file.derivation_path.clone(),
        redeem_hex: file.redeem_script_hex.clone(),
        threshold: file.threshold,
        participants: file.participants,
    };
    let salt = decode_len::<16>(&file.salt)?;
    let nonce = decode_len::<12>(&file.nonce)?;
    let ciphertext = STANDARD
        .decode(&file.ciphertext)
        .map_err(|_| Error::WalletFormat)?;
    if ciphertext.len() < TAG_LEN || ciphertext.len() > MAX_PLAINTEXT + TAG_LEN {
        return Err(Error::WalletFormat);
    }
    let plaintext = decrypt(passphrase, &ciphertext, &meta, &kdf, &salt, &nonce)?;
    let material = decode_plaintext(&plaintext, &meta)?;
    confirm_material(&material, &meta.address)?;
    Ok(OpenedWallet {
        address: meta.address,
        network: material.network(),
        kind: material.kind(),
        mode: material.mode(),
        path: material.path().to_owned(),
        redeem_hex: hexutil::encode_lower(material.redeem()),
        threshold: material.threshold(),
        participants: material.participants(),
        public_key: material.public_key(),
        material,
    })
}

pub(crate) fn export_text(material: &WalletMaterial, address: &str) -> Result<SecretString, Error> {
    confirm_material(material, address)?;
    let mut text = Zeroizing::new(String::new());
    match (material.kind(), material.mode()) {
        (AddressKind::P2pkh, SearchMode::Independent) => {
            let wif = encode_wif(material.network(), material.sole_key()?);
            text.push_str("WIF:\n");
            text.push_str(wif.as_str());
            text.push('\n');
        }
        (AddressKind::P2sh, SearchMode::Independent) => {
            let wif = encode_wif(material.network(), material.sole_key()?);
            text.push_str("WIF:\n");
            text.push_str(wif.as_str());
            text.push_str("\nRedeem script:\n");
            text.push_str(&hexutil::encode_lower(material.redeem()));
            text.push('\n');
        }
        (AddressKind::Multisig, SearchMode::Independent) => {
            text.push_str(&format!("Threshold:\n{}\n", material.threshold()));
            text.push_str(&format!("Participants:\n{}\n", material.participants()));
            text.push_str("Redeem script:\n");
            text.push_str(&hexutil::encode_lower(material.redeem()));
            text.push('\n');
            let engine = KeyEngine::new()?;
            let mut rows = Vec::new();
            for key in material.keys() {
                let public = engine
                    .public_of(key)
                    .map_err(|_| Error::VerificationFailed)?;
                rows.push((public.key, encode_wif(material.network(), key)));
            }
            rows.sort_by_key(|left| left.0);
            for (index, (_public, wif)) in rows.iter().enumerate() {
                text.push_str(&format!("WIF {}:\n{}\n", index + 1, wif.as_str()));
            }
        }
        (AddressKind::P2pkh, SearchMode::HdIndex) => {
            let phrase = mnemonic_from_entropy(material.entropy())?;
            let seed = seed_from_entropy(material.entropy())?;
            let engine = KeyEngine::new()?;
            let (child, derived) = receive_address(
                &engine,
                seed.as_slice(),
                material.network(),
                material.account(),
                material.index(),
            )?;
            if derived != address {
                return Err(Error::VerificationFailed);
            }
            let wif = encode_wif(material.network(), child.key_bytes());
            text.push_str("Mnemonic:\n");
            text.push_str(phrase.as_str());
            text.push_str("\nDerivation path:\n");
            text.push_str(material.path());
            text.push_str("\nChild WIF:\n");
            text.push_str(wif.as_str());
            text.push_str(
                "\nDogecoin Core 1.14 does not import BIP39. importprivkey of the child WIF spends this address only.\nA gap limit of 20 will not discover this index on its own.\n",
            );
        }
        _ => return Err(Error::VerificationFailed),
    }
    Ok(SecretString::from_zeroizing(text))
}

struct Meta {
    address: String,
    network: String,
    kind: String,
    mode: String,
    path: String,
    redeem_hex: String,
    threshold: u32,
    participants: u32,
}

fn public_meta(material: &WalletMaterial, address: &str) -> Meta {
    Meta {
        address: address.to_owned(),
        network: material.network().name().to_owned(),
        kind: material.kind().name().to_owned(),
        mode: material.mode().name().to_owned(),
        path: material.path().to_owned(),
        redeem_hex: hexutil::encode_lower(material.redeem()),
        threshold: u32::from(material.threshold()),
        participants: u32::from(material.participants()),
    }
}

fn encode_plaintext(material: &WalletMaterial) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut out = Vec::new();
    out.extend_from_slice(b"DV1");
    let kind_tag = match (material.kind(), material.mode()) {
        (AddressKind::P2pkh, SearchMode::Independent) => 1u8,
        (AddressKind::P2sh, SearchMode::Independent) => 2,
        (AddressKind::Multisig, SearchMode::Independent) => 3,
        (AddressKind::P2pkh, SearchMode::HdIndex) => 4,
        _ => return Err(Error::WalletFormat),
    };
    out.push(kind_tag);
    out.push(material.network().tag());
    match kind_tag {
        1 | 2 => {
            let key = material.sole_key()?;
            out.extend_from_slice(key);
            if kind_tag == 2 {
                push_bytes(&mut out, material.redeem())?;
            }
        }
        3 => {
            out.push(material.threshold());
            out.push(material.participants());
            for key in material.keys() {
                out.extend_from_slice(key);
            }
            push_bytes(&mut out, material.redeem())?;
        }
        4 => {
            if !material.has_entropy {
                return Err(Error::WalletFormat);
            }
            out.extend_from_slice(material.entropy());
            out.extend_from_slice(&material.account().to_be_bytes());
            out.extend_from_slice(&material.index().to_be_bytes());
        }
        _ => return Err(Error::WalletFormat),
    }
    if out.len() > MAX_PLAINTEXT {
        return Err(Error::WalletFormat);
    }
    Ok(Zeroizing::new(out))
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    let len = u16::try_from(bytes.len()).map_err(|_| Error::WalletFormat)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn decode_plaintext(bytes: &[u8], meta: &Meta) -> Result<WalletMaterial, Error> {
    if bytes.len() < 5 || &bytes[..3] != b"DV1" {
        return Err(Error::WalletFormat);
    }
    let kind_tag = bytes[3];
    let network = Network::from_tag(bytes[4]).ok_or(Error::WalletFormat)?;
    if network.name() != meta.network {
        return Err(Error::VerificationFailed);
    }
    let rest = &bytes[5..];
    let material = match kind_tag {
        1 => {
            let key = take_key(rest, 0)?;
            if rest.len() != 32 {
                return Err(Error::WalletFormat);
            }
            let public = KeyEngine::new()?
                .public_of(key.as_slice())
                .map_err(|_| Error::VerificationFailed)?;
            WalletMaterial::p2pkh(network, key, public.key)
        }
        2 => {
            if rest.len() < 34 {
                return Err(Error::WalletFormat);
            }
            let key = take_key(rest, 0)?;
            let script = take_blob(&rest[32..])?;
            if 32 + 2 + script.len() != rest.len() {
                return Err(Error::WalletFormat);
            }
            let public = KeyEngine::new()?
                .public_of(key.as_slice())
                .map_err(|_| Error::VerificationFailed)?;
            WalletMaterial::p2sh(network, key, script, public.key)
        }
        3 => decode_multisig(network, rest)?,
        4 => {
            if rest.len() != 40 {
                return Err(Error::WalletFormat);
            }
            let mut entropy = Zeroizing::new([0u8; 32]);
            entropy.copy_from_slice(&rest[..32]);
            let account =
                u32::from_be_bytes(rest[32..36].try_into().map_err(|_| Error::WalletFormat)?);
            let index =
                u32::from_be_bytes(rest[36..40].try_into().map_err(|_| Error::WalletFormat)?);
            let steps = receive_steps(network, account, index)?;
            let path = format_path(&steps);
            let seed = seed_from_entropy(entropy.as_slice())?;
            let engine = KeyEngine::new()?;
            let (child, _address) =
                receive_address(&engine, seed.as_slice(), network, account, index)?;
            let public = engine
                .public_of(child.key_bytes())
                .map_err(|_| Error::VerificationFailed)?;
            WalletMaterial::hd(network, entropy, account, index, path, public.key)
        }
        _ => return Err(Error::WalletFormat),
    };
    if material.kind().name() != meta.kind || material.mode().name() != meta.mode {
        return Err(Error::VerificationFailed);
    }
    if material.path() != meta.path || hexutil::encode_lower(material.redeem()) != meta.redeem_hex {
        return Err(Error::VerificationFailed);
    }
    if u32::from(material.threshold()) != meta.threshold
        || u32::from(material.participants()) != meta.participants
    {
        return Err(Error::VerificationFailed);
    }
    Ok(material)
}

fn decode_multisig(network: Network, rest: &[u8]) -> Result<WalletMaterial, Error> {
    if rest.len() < 2 {
        return Err(Error::WalletFormat);
    }
    let threshold = rest[0];
    let participants = rest[1];
    let key_bytes = usize::from(participants) * 32;
    if rest.len() < 2 + key_bytes + 2 {
        return Err(Error::WalletFormat);
    }
    let mut keys = Zeroizing::new(Vec::with_capacity(usize::from(participants)));
    for index in 0..usize::from(participants) {
        keys.push(*take_key(&rest[2..], index * 32)?);
    }
    let script = take_blob(&rest[2 + key_bytes..])?;
    if 2 + key_bytes + 2 + script.len() != rest.len() {
        return Err(Error::WalletFormat);
    }
    Ok(WalletMaterial::multisig(network, threshold, keys, script))
}

fn take_key(bytes: &[u8], offset: usize) -> Result<Zeroizing<[u8; 32]>, Error> {
    let end = offset.checked_add(32).ok_or(Error::WalletFormat)?;
    if end > bytes.len() {
        return Err(Error::WalletFormat);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&bytes[offset..end]);
    Ok(key)
}

fn take_blob(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if bytes.len() < 2 {
        return Err(Error::WalletFormat);
    }
    let len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    if bytes.len() != 2 + len {
        return Err(Error::WalletFormat);
    }
    Ok(bytes[2..].to_vec())
}

fn encrypt(
    passphrase: &str,
    plaintext: &[u8],
    meta: &Meta,
    kdf: &KdfParams,
    salt: &[u8; 16],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, Error> {
    let derived = derive_key(passphrase.as_bytes(), salt, kdf)?;
    let cipher =
        ChaCha20Poly1305::new_from_slice(derived.as_slice()).map_err(|_| Error::WalletFormat)?;
    let nonce = Nonce::from_slice(nonce.as_slice());
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad_bytes(meta),
            },
        )
        .map_err(|_| Error::Decrypt)
}

fn decrypt(
    passphrase: &str,
    ciphertext: &[u8],
    meta: &Meta,
    kdf: &KdfParams,
    salt: &[u8; 16],
    nonce: &[u8; 12],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let derived = derive_key(passphrase.as_bytes(), salt, kdf)?;
    let cipher =
        ChaCha20Poly1305::new_from_slice(derived.as_slice()).map_err(|_| Error::WalletFormat)?;
    let nonce = Nonce::from_slice(nonce.as_slice());
    let plain = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &aad_bytes(meta),
            },
        )
        .map_err(|_| Error::Decrypt)?;
    Ok(Zeroizing::new(plain))
}

fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    kdf: &KdfParams,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let params = Params::new(kdf.memory_kib, kdf.iterations, kdf.parallelism, Some(32))
        .map_err(|_| Error::WalletFormat)?;
    let block_count = params.block_count();
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut memory = Zeroizing::new(vec![Block::default(); block_count].into_boxed_slice());
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into_with_memory(passphrase, salt, key.as_mut(), &mut *memory)
        .map_err(|_| Error::WalletFormat)?;
    Ok(key)
}

fn aad_bytes(meta: &Meta) -> Vec<u8> {
    let threshold = meta.threshold.to_string();
    let participants = meta.participants.to_string();
    let mut out = Vec::new();
    out.extend_from_slice(AAD_PREFIX);
    for part in [
        meta.address.as_str(),
        meta.network.as_str(),
        meta.kind.as_str(),
        meta.mode.as_str(),
        "compressed",
        threshold.as_str(),
        participants.as_str(),
        meta.redeem_hex.as_str(),
        meta.path.as_str(),
    ] {
        out.extend_from_slice(part.as_bytes());
        out.push(0);
    }
    out
}

fn decode_len<const N: usize>(text: &str) -> Result<[u8; N], Error> {
    let bytes = STANDARD.decode(text).map_err(|_| Error::WalletFormat)?;
    if bytes.len() != N {
        return Err(Error::WalletFormat);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn read_wallet(path: &Path) -> Result<WalletFile, Error> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|err| map_wallet_open_error(path, err))?;
    let meta = file.metadata().map_err(|err| Error::io(path, err))?;
    if meta.len() > MAX_WALLET_BYTES || !meta.is_file() {
        return Err(Error::WalletFormat);
    }
    let mut text = String::new();
    Read::by_ref(&mut file)
        .take(MAX_WALLET_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|err| Error::io(path, err))?;
    if text.len() as u64 > MAX_WALLET_BYTES {
        return Err(Error::WalletFormat);
    }
    serde_json::from_str(&text).map_err(|_| Error::WalletFormat)
}

fn map_wallet_open_error(path: &Path, err: std::io::Error) -> Error {
    if err.raw_os_error() == Some(40) {
        Error::Io(format!(
            "{}: wallet path must be a regular file",
            path.display()
        ))
    } else {
        Error::io(path, err)
    }
}

fn write_private_file(dest: &Path, contents: &[u8]) -> Result<(), Error> {
    if dest.exists() {
        return Err(Error::OutputExists);
    }
    let parent = parent_dir(dest);
    if !parent.is_dir() {
        return Err(Error::OutputDir);
    }
    let file_name = dest.file_name().ok_or(Error::OutputDir)?;
    let mut suffix = [0u8; 8];
    getrandom::getrandom(&mut suffix).map_err(|_| Error::Rng)?;
    let tmp_path = parent.join(format!(
        ".{}.tmp.{}",
        file_name.to_string_lossy(),
        hexutil::encode_upper(&suffix)
    ));
    let mut guard = RemoveOnDrop {
        path: tmp_path.clone(),
        armed: true,
    };
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp_path)
        .map_err(|err| Error::io(&tmp_path, err))?;
    let mode = file
        .metadata()
        .map_err(|err| Error::io(&tmp_path, err))?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        return Err(Error::Io(format!(
            "{}: created file was not private",
            tmp_path.display()
        )));
    }
    file.write_all(contents)
        .map_err(|err| Error::io(&tmp_path, err))?;
    file.sync_all().map_err(|err| Error::io(&tmp_path, err))?;
    drop(file);
    match fs::hard_link(&tmp_path, dest) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(Error::OutputExists);
        }
        Err(err) => return Err(Error::io(dest, err)),
    }
    fs::remove_file(&tmp_path).map_err(|err| Error::io(&tmp_path, err))?;
    guard.armed = false;
    sync_directory(dest, parent)?;
    Ok(())
}

fn sync_directory(dest: &Path, parent: &Path) -> Result<(), Error> {
    let dir = File::open(parent).map_err(|err| {
        Error::Io(format!(
            "{}: wallet file was written, but opening its directory for sync failed: {err}. It may not survive a power loss.",
            dest.display()
        ))
    })?;
    dir.sync_all().map_err(|err| {
        Error::Io(format!(
            "{}: wallet file was written, but syncing its directory failed: {err}. It may not survive a power loss.",
            dest.display()
        ))
    })
}

fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

struct RemoveOnDrop {
    path: PathBuf,
    armed: bool,
}

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletFile {
    format_version: u32,
    network: String,
    address_type: String,
    mode: String,
    public_address: String,
    public_key_compression: String,
    derivation_path: String,
    threshold: u32,
    participants: u32,
    redeem_script_hex: String,
    kdf: String,
    kdf_parameters: KdfFile,
    salt: String,
    cipher: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KdfFile {
    version: u32,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        check_new_passphrase, open_and_verify, open_and_verify_with_kdf, write_encrypted_wallet,
        write_encrypted_wallet_with_kdf, KdfParams, WalletMaterial,
    };
    use crate::doge::keys::KeyEngine;
    use crate::doge::script::p2pkh_redeem;
    use crate::doge::{address_from_hash, Network};
    use crate::error::Error;

    fn scratch(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("doge-vanity-{label}-{nanos}"));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn sample() -> (WalletMaterial, String) {
        let mut key = zeroize::Zeroizing::new([0u8; 32]);
        key[31] = 9;
        let engine = KeyEngine::new().unwrap();
        let public = engine.public_of(key.as_slice()).unwrap();
        let address = address_from_hash(Network::Mainnet.p2pkh_version(), &public.hash160);
        let material = WalletMaterial::p2pkh(Network::Mainnet, key, public.key);
        (material, address)
    }

    #[test]
    fn cheap_round_trip_is_private_and_public_opener_rejects_it() {
        let dir = scratch("wallet");
        let path = dir.join("sample-wallet.json");
        let (material, address) = sample();
        let kdf = KdfParams {
            memory_kib: 32,
            iterations: 1,
            parallelism: 1,
        };
        write_encrypted_wallet_with_kdf(&path, "correct horse battery", &material, &address, &kdf)
            .unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & 0o077, 0);
        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains("0000000000000000000000000000000000000000000000000000000000000009"));
        let opened = open_and_verify_with_kdf(&path, "correct horse battery").unwrap();
        assert_eq!(opened.address, address);
        assert!(open_and_verify(&path, "correct horse battery").is_err());
        assert_eq!(
            write_encrypted_wallet(&path, "correct horse battery", &material, &address)
                .unwrap_err(),
            Error::OutputExists
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn short_passphrase_does_not_create_a_file() {
        let dir = scratch("short");
        let path = dir.join("nope-wallet.json");
        let (material, address) = sample();
        assert_eq!(
            write_encrypted_wallet(&path, "short", &material, &address).unwrap_err(),
            Error::Passphrase
        );
        assert!(!path.exists());
        assert!(check_new_passphrase("short").is_err());
        assert!(check_new_passphrase("  twelve chars").is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn symlink_is_rejected() {
        let dir = scratch("link");
        let real = dir.join("real-wallet.json");
        let link = dir.join("link-wallet.json");
        let (material, address) = sample();
        let kdf = KdfParams {
            memory_kib: 32,
            iterations: 1,
            parallelism: 1,
        };
        write_encrypted_wallet_with_kdf(&real, "correct horse battery", &material, &address, &kdf)
            .unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = open_and_verify_with_kdf(&link, "correct horse battery").unwrap_err();
        assert!(err.to_string().contains("regular file"), "{err}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn p2sh_script_is_bound_into_the_file() {
        let dir = scratch("p2sh");
        let path = dir.join("p2sh-wallet.json");
        let mut key = zeroize::Zeroizing::new([0u8; 32]);
        key[31] = 9;
        let engine = KeyEngine::new().unwrap();
        let public = engine.public_of(key.as_slice()).unwrap();
        let script = p2pkh_redeem(&public.hash160).to_vec();
        let address = address_from_hash(
            Network::Mainnet.p2sh_version(),
            &crate::doge::hash::hash160(&script),
        );
        let material = WalletMaterial::p2sh(Network::Mainnet, key, script, public.key);
        let kdf = KdfParams {
            memory_kib: 32,
            iterations: 1,
            parallelism: 1,
        };
        write_encrypted_wallet_with_kdf(&path, "correct horse battery", &material, &address, &kdf)
            .unwrap();
        let opened = open_and_verify_with_kdf(&path, "correct horse battery").unwrap();
        assert_eq!(opened.address, address);
        assert!(opened.address.starts_with('A') || opened.address.starts_with('9'));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn hd_restore_uses_the_recorded_index_and_gap_limit_misses_it() {
        let dir = scratch("hd");
        let path = dir.join("hd-wallet.json");
        let entropy = zeroize::Zeroizing::new([0xffu8; 32]);
        let seed = crate::doge::seed_from_entropy(entropy.as_slice()).unwrap();
        let engine = KeyEngine::new().unwrap();
        let (child, address) =
            crate::doge::receive_address(&engine, seed.as_slice(), Network::Mainnet, 0, 100)
                .unwrap();
        let public = engine.public_of(child.key_bytes()).unwrap();
        let material = WalletMaterial::hd(
            Network::Mainnet,
            entropy,
            0,
            100,
            "m/44'/3'/0'/0/100".to_owned(),
            public.key,
        );
        let kdf = KdfParams {
            memory_kib: 32,
            iterations: 1,
            parallelism: 1,
        };
        write_encrypted_wallet_with_kdf(&path, "correct horse battery", &material, &address, &kdf)
            .unwrap();
        drop(material);
        let opened = open_and_verify_with_kdf(&path, "correct horse battery").unwrap();
        assert_eq!(opened.address, address);
        assert_eq!(opened.path, "m/44'/3'/0'/0/100");
        assert_eq!(opened.material.index(), 100);
        let scanned =
            crate::doge::scan_gap(&engine, seed.as_slice(), Network::Mainnet, 0, 20).unwrap();
        assert!(!scanned.contains(&address));
        assert_eq!(scanned.len(), 20);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn multisig_restore_rebuilds_the_redeem_script() {
        let dir = scratch("multi");
        let path = dir.join("multi-wallet.json");
        let mut first = [0u8; 32];
        first[31] = 1;
        let mut second = [0u8; 32];
        second[31] = 2;
        let mut third = [0u8; 32];
        third[31] = 3;
        let engine = KeyEngine::new().unwrap();
        let keys = [
            engine.public_of(&first).unwrap().key,
            engine.public_of(&second).unwrap().key,
            engine.public_of(&third).unwrap().key,
        ];
        let script = crate::doge::script::multisig_redeem(2, &keys).unwrap();
        let address = address_from_hash(
            Network::Mainnet.p2sh_version(),
            &crate::doge::hash::hash160(&script),
        );
        let material = WalletMaterial::multisig(
            Network::Mainnet,
            2,
            zeroize::Zeroizing::new(vec![first, second, third]),
            script.clone(),
        );
        let kdf = KdfParams {
            memory_kib: 32,
            iterations: 1,
            parallelism: 1,
        };
        write_encrypted_wallet_with_kdf(&path, "correct horse battery", &material, &address, &kdf)
            .unwrap();
        drop(material);
        let opened = open_and_verify_with_kdf(&path, "correct horse battery").unwrap();
        assert_eq!(opened.address, address);
        assert_eq!(opened.threshold, 2);
        assert_eq!(opened.participants, 3);
        assert_eq!(opened.redeem_hex, crate::hexutil::encode_lower(&script));
        let rebuilt =
            crate::independent::independent_multisig(Network::Mainnet, 2, &[first, second, third])
                .unwrap();
        assert_eq!(rebuilt.redeem, script);
        assert_eq!(rebuilt.address, address);
        let _ = fs::remove_dir_all(&dir);
    }
}
