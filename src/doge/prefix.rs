// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Exact Base58 prefix ranges for Dogecoin version bytes.
//!
//! A Dogecoin address is the Base58 encoding of a 25-byte payload:
//! `version || HASH160 || checksum`. That payload is an integer in
//! `[version << 192, version << 192 + 2^192)`. The fixed version byte, not
//! `58^n`, decides which leading strings exist.
//!
//! Mainnet P2PKH (`0x1e`) is 34 characters from `D596YF…` through `DUUhXN…`.
//! `Z` is past the last reachable second character, so `DZuZu` is impossible.
//! Mainnet P2SH (`0x16`) runs from `9rSG…` through `AFms…`, so `AZuZu` is
//! impossible as well. Testnet P2SH (`0xc4`) is 35 characters, not 34.
//!
//! `expected` is `round(2^192 / overlap)`. It is not a proof that HASH160 is
//! uniform, and it is not a promise of wall-clock time. The 50% figure is
//! `round(expected * ln 2)`. The 90% and 99% figures are
//! `ceil(ln(1 - q) / ln(1 - overlap / 2^192))`.

use crate::doge::base58::{alphabet_index, base58_decode, base58_encode, ALPHABET};
use crate::doge::keys::{encode_payload, MAX_ADDRESS_LEN, PAYLOAD_LEN};
use crate::doge::network::{AddressKind, Network};
use crate::doge::uint::U256;
use crate::error::Error;

pub(crate) const SEARCH_COUNTER_HEADROOM: u64 = 1_048_576;
pub const CONFIRMATION_THRESHOLD: u64 = 1_000_000_000;

const ERR_EMPTY: &str = "prefix is empty";
const ERR_ALPHABET: &str = "prefix uses a character outside Base58 (0, O, I, and l are excluded)";
const ERR_LONG: &str = "prefix is longer than a Dogecoin address of this type";
const ERR_RANGE: &str = "prefix is too rare for the attempt counter";
const ERR_FULL: &str = "a full address is one payload and is not a search prefix";
const ERR_LENGTH: &str = "the version range does not have one Base58 length";

/// How the requested text sits inside the version-byte interval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Impossible,
    Partial,
    Full,
    VersionImplied,
}

impl Class {
    pub fn label(self) -> &'static str {
        match self {
            Self::Impossible => "impossible",
            Self::Partial => "partially reachable",
            Self::Full => "fully reachable",
            Self::VersionImplied => "version-implied",
        }
    }

    pub fn reachable(self) -> bool {
        !matches!(self, Self::Impossible)
    }
}

/// One analyzed prefix. Bounds are present only when the intersection is nonempty.
#[derive(Clone, PartialEq)]
pub struct Analysis {
    pub prefix: String,
    pub network: Network,
    pub kind: AddressKind,
    pub class: Class,
    pub expected: Option<u64>,
    pub median: Option<u64>,
    pub p90: Option<u64>,
    pub p99: Option<u64>,
    pub unrounded: String,
    pub vanity: String,
    pub endpoint_low: String,
    pub endpoint_high: String,
    pub address_len: usize,
    pub implied: String,
    pub next_full: String,
    pub next_edge: String,
    pub next_absent: String,
    pub too_rare: bool,
    low: Option<[u8; PAYLOAD_LEN]>,
    high: Option<[u8; PAYLOAD_LEN]>,
    overlap: Option<U256>,
}

impl Analysis {
    pub fn version(&self) -> u8 {
        self.kind.version(self.network)
    }

    pub fn is_searchable(&self) -> bool {
        self.class.reachable() && !self.too_rare && self.low.is_some() && self.expected.is_some()
    }

    pub fn needs_large_search_confirmation(&self) -> bool {
        self.expected
            .is_some_and(|expected| expected >= CONFIRMATION_THRESHOLD)
    }

    pub fn contains_payload(&self, payload: &[u8; PAYLOAD_LEN]) -> bool {
        match (self.low, self.high) {
            (Some(low), Some(high)) => {
                payload.as_slice() >= low.as_slice() && payload.as_slice() <= high.as_slice()
            }
            _ => false,
        }
    }

    pub fn report(&self) -> String {
        let mut out = String::new();
        push_pair(&mut out, "Dogecoin Vanity Analyzer", "");
        out.push('\n');
        push_pair(&mut out, "Network:", self.network.label());
        out.push('\n');
        push_pair(&mut out, "Address type:", self.kind.label());
        out.push('\n');
        push_pair(&mut out, "Encoding:", "Base58Check");
        out.push('\n');
        push_pair(&mut out, "Requested:", &self.prefix);
        out.push('\n');
        out.push_str("Fixed network constraints:\n");
        out.push_str(&format!("Version byte: 0x{:02x}\n", self.version()));
        out.push_str(&format!("Payload bytes: {PAYLOAD_LEN}\n"));
        out.push_str(&format!("Address characters: {}\n", self.address_len));
        out.push_str(&format!("Lowest payload encoding: {}\n", self.endpoint_low));
        out.push_str(&format!(
            "Highest payload encoding: {}\n",
            self.endpoint_high
        ));
        out.push_str("Endpoints are the mathematical version range, not funded addresses.\n");
        if self.implied.is_empty() {
            out.push_str("Version-implied leading text: (none)\n");
        } else {
            out.push_str(&format!("Version-implied leading text: {}\n", self.implied));
        }
        let next = if self.implied.is_empty() {
            "First character"
        } else {
            "Next character"
        };
        out.push_str(&format!("{next} fully inside: {}\n", self.next_full));
        out.push_str(&format!("{next} on an edge: {}\n", self.next_edge));
        out.push_str(&format!("{next} absent: {}\n", self.next_absent));
        out.push('\n');
        push_pair(
            &mut out,
            "Vanity portion:",
            if self.vanity.is_empty() {
                "(none)"
            } else {
                &self.vanity
            },
        );
        out.push('\n');
        push_pair(&mut out, "Classification:", self.class.label());
        out.push('\n');
        push_pair(
            &mut out,
            "Reachable:",
            if self.class.reachable() { "YES" } else { "NO" },
        );
        out.push('\n');
        push_pair(
            &mut out,
            "Probability per candidate:",
            &self.probability_line(),
        );
        out.push('\n');
        push_pair(&mut out, "Unrounded expected attempts:", &self.unrounded);
        out.push('\n');
        push_pair(&mut out, "Expected attempts:", &self.display_expected());
        out.push('\n');
        push_pair(&mut out, "50% probability:", &self.display_median());
        out.push('\n');
        push_pair(&mut out, "90% probability:", &self.display_p90());
        out.push('\n');
        push_pair(&mut out, "99% probability:", &self.display_p99());
        out.push('\n');
        if !self.vanity.is_empty() {
            out.push_str(&format!(
                "Rejected per-character approximation: 58^{} = {}\n",
                self.vanity.len(),
                group_digits(&pow58_decimal(self.vanity.len()))
            ));
            out.push('\n');
        }
        out.push_str(
            "Model:\nThe overlap of the prefix interval with the version-byte range, divided into 2^192.\nThis is not 58^n, and it is not a promise of wall-clock time.\n",
        );
        if self.too_rare {
            out.push_str("The attempt counter cannot hold this estimate.\n");
        }
        out
    }

    /// Chance of at least one match inside one BIP44 receive chain.
    ///
    /// The chain has `2^31` indexes, `0` through `2^31 - 1`. The probability
    /// uses the prefix overlap, `1 - (1 - overlap / 2^192)^(2^31)`, not the
    /// rounded expected-attempt count. A quantile above that window is absent.
    pub fn hd_window(&self) -> HdWindow {
        let trials = u64::from(crate::doge::hd::HARDENED);
        let Some(overlap) = self.overlap else {
            return HdWindow {
                trials,
                maximum: 0.0,
                median: None,
                p90: None,
                p99: None,
            };
        };
        HdWindow {
            trials,
            maximum: window_probability(overlap, trials),
            median: in_window(self.median, trials),
            p90: in_window(self.p90, trials),
            p99: in_window(self.p99, trials),
        }
    }

    /// The 50% count does not fit in one mnemonic's receive indexes.
    pub fn needs_hd_exhaust_confirmation(&self) -> bool {
        self.is_searchable() && self.hd_window().median.is_none()
    }

    pub fn hd_lines(&self) -> String {
        let window = self.hd_window();
        let last = group_digits(&(window.trials - 1).to_string());
        format!(
            "HD receive-index range:\n0 .. {last}\nMaximum probability of a match in this mnemonic:\n{}\n50% probability:\n{}\n90% probability:\n{}\n99% probability:\n{}\n",
            format_probability(window.maximum),
            display_window_count(window.median),
            display_window_count(window.p90),
            display_window_count(window.p99),
        )
    }

    fn probability_line(&self) -> String {
        match self.class {
            Class::Impossible => "0".to_owned(),
            Class::VersionImplied => "1".to_owned(),
            _ => match self.expected {
                Some(expected) => format!("1 / {}", group_digits(&expected.to_string())),
                None => "not representable in the attempt counter".to_owned(),
            },
        }
    }

    fn display_expected(&self) -> String {
        match self.expected {
            Some(value) => group_digits(&value.to_string()),
            None => "n/a".to_owned(),
        }
    }

    fn display_median(&self) -> String {
        match self.median {
            Some(value) => group_digits(&value.to_string()),
            None => "n/a".to_owned(),
        }
    }

    fn display_p90(&self) -> String {
        match self.p90 {
            Some(value) => group_digits(&value.to_string()),
            None => "n/a".to_owned(),
        }
    }

    fn display_p99(&self) -> String {
        match self.p99 {
            Some(value) => group_digits(&value.to_string()),
            None => "n/a".to_owned(),
        }
    }
}

impl std::fmt::Debug for Analysis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Analysis")
            .field("prefix", &self.prefix)
            .field("class", &self.class)
            .field("expected", &self.expected)
            .finish()
    }
}

pub fn analyze(network: Network, kind: AddressKind, prefix: &str) -> Result<Analysis, Error> {
    if prefix.is_empty() {
        return Err(Error::prefix(ERR_EMPTY));
    }
    if prefix.bytes().any(|byte| alphabet_index(byte).is_none()) {
        return Err(Error::prefix(ERR_ALPHABET));
    }
    let version = kind.version(network);
    let (version_low, version_high, endpoint_low, endpoint_high, address_len) =
        version_window(version)?;
    if prefix.len() > address_len {
        return Err(Error::prefix(ERR_LONG));
    }
    let implied = common_prefix(&endpoint_low, &endpoint_high);
    let (next_full, next_edge, next_absent) =
        next_characters(address_len, &implied, &version_low, &version_high);
    if prefix.len() == address_len {
        return reject_full_address(prefix, version);
    }

    let (text_low, text_high) = prefix_integer_span(prefix, address_len)?;
    let low = text_low.max(version_low);
    let high = text_high.min(version_high);
    let vanity = vanity_portion(prefix, &implied);
    if low > high {
        return Ok(Analysis {
            prefix: prefix.to_owned(),
            network,
            kind,
            class: Class::Impossible,
            expected: None,
            median: None,
            p90: None,
            p99: None,
            unrounded: "n/a".to_owned(),
            vanity,
            endpoint_low,
            endpoint_high,
            address_len,
            implied,
            next_full,
            next_edge,
            next_absent,
            too_rare: false,
            low: None,
            high: None,
            overlap: None,
        });
    }

    let class = if version_low >= text_low && version_high <= text_high {
        Class::VersionImplied
    } else if text_low >= version_low && text_high <= version_high {
        Class::Full
    } else {
        Class::Partial
    };
    let overlap = high
        .sub(low)
        .checked_add(U256::ONE)
        .ok_or_else(|| Error::prefix(ERR_RANGE))?;
    let unrounded = format_unrounded(overlap);
    let rounded = U256::pow2(192).div_round_u64(overlap);
    let too_rare = match rounded {
        Some(expected) => expected == 0 || expected > u64::MAX - SEARCH_COUNTER_HEADROOM,
        None => true,
    };
    let (expected, median, p90, p99) = if too_rare {
        (None, None, None, None)
    } else {
        let expected = rounded.expect("too_rare is false only when the quotient fits");
        let median = median_attempts(expected);
        let p90 = quantile_attempts(overlap, 0.90);
        let p99 = quantile_attempts(overlap, 0.99);
        (Some(expected), Some(median), Some(p90), Some(p99))
    };
    let low_bytes = low
        .to_payload_bytes()
        .ok_or_else(|| Error::prefix(ERR_RANGE))?;
    let high_bytes = high
        .to_payload_bytes()
        .ok_or_else(|| Error::prefix(ERR_RANGE))?;
    Ok(Analysis {
        prefix: prefix.to_owned(),
        network,
        kind,
        class,
        expected,
        median,
        p90,
        p99,
        unrounded,
        vanity,
        endpoint_low,
        endpoint_high,
        address_len,
        implied,
        next_full,
        next_edge,
        next_absent,
        too_rare,
        low: Some(low_bytes),
        high: Some(high_bytes),
        overlap: Some(overlap),
    })
}

/// Finite BIP44 receive-chain view of one prefix.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HdWindow {
    pub trials: u64,
    pub maximum: f64,
    pub median: Option<u64>,
    pub p90: Option<u64>,
    pub p99: Option<u64>,
}

pub fn require_searchable(analysis: &Analysis) -> Result<(), Error> {
    if analysis.too_rare {
        return Err(Error::prefix(ERR_RANGE));
    }
    if !analysis.is_searchable() {
        return Err(Error::prefix(format!(
            "no {} {} address has this prefix",
            analysis.network.name(),
            analysis.kind.label()
        )));
    }
    Ok(())
}

/// `ln(2) * expected`, rounded to the nearest integer.
pub fn median_attempts(expected: u64) -> u64 {
    if expected <= 1 {
        return expected;
    }
    let median = (expected as f64) * std::f64::consts::LN_2;
    median.round() as u64
}

pub fn group_digits(digits: &str) -> String {
    if digits.is_empty() {
        return String::new();
    }
    if digits.len() > 15 {
        let exponent = digits.len() - 1;
        let mut mantissa = String::new();
        mantissa.push(digits.as_bytes()[0] as char);
        mantissa.push('.');
        let fraction: String = digits.chars().skip(1).take(3).collect();
        mantissa.push_str(&fraction);
        return format!("{mantissa}e{exponent}");
    }
    let mut grouped = String::new();
    for (index, ch) in digits.chars().rev().enumerate() {
        if index > 0 && index % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(ch);
    }
    grouped.chars().rev().collect()
}

fn push_pair(out: &mut String, label: &str, value: &str) {
    if value.is_empty() {
        out.push_str(label);
        out.push('\n');
        return;
    }
    out.push_str(label);
    out.push('\n');
    out.push_str(value);
    out.push('\n');
}

fn vanity_portion(prefix: &str, implied: &str) -> String {
    if implied.is_empty() {
        return prefix.to_owned();
    }
    prefix.strip_prefix(implied).unwrap_or(prefix).to_owned()
}

fn reject_full_address(prefix: &str, version: u8) -> Result<Analysis, Error> {
    let payload =
        crate::doge::base58::base58check_decode(prefix).map_err(|_| Error::prefix(ERR_FULL))?;
    if payload.len() == 21 && payload[0] == version {
        Err(Error::prefix(ERR_FULL))
    } else {
        Err(Error::prefix(
            "a string of full address length is not a search prefix",
        ))
    }
}

fn version_window(version: u8) -> Result<(U256, U256, String, String, usize), Error> {
    let low = U256::from_be_bytes(&[version])
        .expect("version byte fits")
        .shl(192)
        .expect("version prefix fits in 256 bits");
    let high = low
        .checked_add(U256::pow2(192))
        .expect("version max fits")
        .sub(U256::ONE);
    let low_bytes = low
        .to_payload_bytes()
        .ok_or_else(|| Error::prefix(ERR_LENGTH))?;
    let high_bytes = high
        .to_payload_bytes()
        .ok_or_else(|| Error::prefix(ERR_LENGTH))?;
    let low_text = base58_encode(&low_bytes);
    let high_text = base58_encode(&high_bytes);
    if low_text.len() != high_text.len() || low_text.is_empty() || low_text.len() > MAX_ADDRESS_LEN
    {
        return Err(Error::prefix(ERR_LENGTH));
    }
    Ok((low, high, low_text.clone(), high_text, low_text.len()))
}

fn prefix_integer_span(prefix: &str, address_len: usize) -> Result<(U256, U256), Error> {
    let pad = address_len - prefix.len();
    let mut low_text = String::with_capacity(address_len);
    let mut high_text = String::with_capacity(address_len);
    low_text.push_str(prefix);
    high_text.push_str(prefix);
    low_text.extend(std::iter::repeat_n('1', pad));
    high_text.extend(std::iter::repeat_n('z', pad));
    let low = decode_u256(&low_text)?;
    let high = decode_u256(&high_text)?;
    if low > high {
        return Err(Error::prefix("prefix integer span is empty"));
    }
    Ok((low, high))
}

fn decode_u256(text: &str) -> Result<U256, Error> {
    let bytes = base58_decode(text).map_err(|_| Error::prefix("prefix is not Base58"))?;
    U256::from_be_bytes(bytes.as_slice()).ok_or_else(|| Error::prefix("prefix integer is too wide"))
}

fn next_characters(
    address_len: usize,
    implied: &str,
    version_low: &U256,
    version_high: &U256,
) -> (String, String, String) {
    let mut full = String::new();
    let mut edge = String::new();
    let mut absent = String::new();
    for byte in ALPHABET {
        let ch = *byte as char;
        let sample = if implied.is_empty() {
            ch.to_string()
        } else {
            format!("{implied}{ch}")
        };
        if sample.len() > address_len {
            break;
        }
        let class = match prefix_integer_span(&sample, address_len) {
            Ok((text_low, text_high)) => {
                let low = text_low.max(*version_low);
                let high = text_high.min(*version_high);
                if low > high {
                    Class::Impossible
                } else if *version_low >= text_low && *version_high <= text_high {
                    Class::VersionImplied
                } else if text_low >= *version_low && text_high <= *version_high {
                    Class::Full
                } else {
                    Class::Partial
                }
            }
            Err(_) => Class::Impossible,
        };
        match class {
            Class::Full | Class::VersionImplied => full.push(ch),
            Class::Partial => edge.push(ch),
            Class::Impossible => absent.push(ch),
        }
    }
    (full, edge, absent)
}

fn common_prefix(left: &str, right: &str) -> String {
    left.chars()
        .zip(right.chars())
        .take_while(|(a, b)| a == b)
        .map(|(a, _)| a)
        .collect()
}

fn format_unrounded(overlap: U256) -> String {
    let value = span_over_overlap(overlap);
    if !value.is_finite() {
        return "n/a".to_owned();
    }
    format!("{value:.6}")
}

fn in_window(count: Option<u64>, trials: u64) -> Option<u64> {
    count.filter(|count| *count <= trials)
}

fn display_window_count(count: Option<u64>) -> String {
    match count {
        Some(value) => group_digits(&value.to_string()),
        None => "not reachable within this mnemonic".to_owned(),
    }
}

fn format_probability(probability: f64) -> String {
    if probability >= 1.0 {
        "100%".to_owned()
    } else if probability <= 0.0 {
        "0%".to_owned()
    } else {
        format!("{:.2}%", probability * 100.0)
    }
}

/// `1 - (1 - overlap / 2^192)^trials`.
fn window_probability(overlap: U256, trials: u64) -> f64 {
    let expected = span_over_overlap(overlap);
    if !expected.is_finite() || expected <= 0.0 {
        return 0.0;
    }
    if expected <= 1.0 {
        return 1.0;
    }
    let p = 1.0 / expected;
    let log_miss = (trials as f64) * (1.0 - p).ln();
    if !log_miss.is_finite() || log_miss <= -745.0 {
        return 1.0;
    }
    -log_miss.exp_m1()
}

fn span_over_overlap(overlap: U256) -> f64 {
    let mut denom = 0.0f64;
    for byte in overlap.to_be_bytes() {
        denom = denom * 256.0 + f64::from(byte);
    }
    if denom == 0.0 {
        return f64::INFINITY;
    }
    2f64.powi(192) / denom
}

fn quantile_attempts(overlap: U256, probability: f64) -> u64 {
    let exact = span_over_overlap(overlap);
    if !exact.is_finite() || exact <= 1.0 {
        return 1;
    }
    let p = 1.0 / exact;
    let n = (1.0 - probability).ln() / (1.0 - p).ln();
    if !n.is_finite() || n <= 1.0 {
        return 1;
    }
    if n >= u64::MAX as f64 {
        u64::MAX
    } else {
        n.ceil() as u64
    }
}

fn pow58_decimal(exp: usize) -> String {
    let mut digits = vec![1u8];
    for _ in 0..exp {
        let mut carry = 0u16;
        for digit in &mut digits {
            let acc = u16::from(*digit) * 58 + carry;
            *digit = (acc % 10) as u8;
            carry = acc / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    digits
        .iter()
        .rev()
        .map(|digit| (b'0' + digit) as char)
        .collect()
}

/// Confirm the optimized interval agrees with a full Base58Check string.
pub fn optimized_matches_text(analysis: &Analysis, payload: &[u8; PAYLOAD_LEN]) -> bool {
    let address = encode_payload(payload);
    analysis.contains_payload(payload) == address.starts_with(&analysis.prefix)
}

#[cfg(test)]
mod tests {
    use super::{analyze, group_digits, median_attempts, Class};
    use crate::doge::base58::base58_encode;
    use crate::doge::keys::{address_from_hash, payload_for_hash, KeyEngine, PAYLOAD_LEN};
    use crate::doge::network::{AddressKind, Network};
    use crate::doge::uint::U256;
    use crate::error::Error;

    #[test]
    fn mainnet_p2pkh_endpoints_and_dzuzu() {
        let analysis = analyze(Network::Mainnet, AddressKind::P2pkh, "DZuZu").unwrap();
        assert_eq!(analysis.class, Class::Impossible);
        assert!(!analysis.is_searchable());
        assert_eq!(analysis.endpoint_low, "D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM");
        assert_eq!(analysis.endpoint_high, "DUUhXNEw1bNAMSKgm1Kt2tSPWdzF3G5pog");
        assert_eq!(analysis.address_len, 34);
        assert_eq!(analysis.vanity, "ZuZu");
        assert_eq!(analysis.implied, "D");
        assert_eq!(analysis.next_full, "6789ABCDEFGHJKLMNPQRST");
        assert_eq!(analysis.next_edge, "5U");
        let report = analysis.report();
        assert!(report.contains("Reachable:\nNO"));
        assert!(report.contains("impossible"));
        assert!(report.contains("58^4 = 11,316,496"));
        assert!(
            analyze(Network::Mainnet, AddressKind::P2pkh, "Dzuzu")
                .unwrap()
                .class
                == Class::Impossible
        );
        assert!(
            analyze(Network::Mainnet, AddressKind::P2pkh, "DWow")
                .unwrap()
                .class
                == Class::Impossible
        );
        assert!(
            analyze(Network::Mainnet, AddressKind::P2pkh, "Doge")
                .unwrap()
                .class
                == Class::Impossible
        );
        assert!(
            analyze(Network::Mainnet, AddressKind::P2pkh, "D123")
                .unwrap()
                .class
                == Class::Impossible
        );
    }

    #[test]
    fn reachable_counts_are_not_58_to_the_n() {
        let da = analyze(Network::Mainnet, AddressKind::P2pkh, "DA").unwrap();
        assert_eq!(da.class, Class::Full);
        assert_eq!(da.expected, Some(23));
        assert_eq!(da.median, Some(16));
        assert_eq!(da.p90, Some(53));
        assert_eq!(da.p99, Some(106));
        assert!(!da.needs_large_search_confirmation());
        assert_eq!(median_attempts(23), 16);

        let doge = analyze(Network::Mainnet, AddressKind::P2pkh, "DDoge").unwrap();
        assert_eq!(doge.expected, Some(4_553_521));
        assert_eq!(doge.median, Some(3_156_260));
        assert_eq!(doge.p90, Some(10_484_869));
        assert_eq!(doge.p99, Some(20_969_738));
        assert_ne!(doge.expected, Some(11_316_496));

        let target = analyze(Network::Mainnet, AddressKind::P2pkh, "DAZuZu").unwrap();
        assert_eq!(target.class, Class::Full);
        assert_eq!(target.expected, Some(264_104_224));
        assert_eq!(target.median, Some(183_063_098));
        assert_eq!(target.p90, Some(608_122_446));
        assert_eq!(target.p99, Some(1_216_244_892));
        assert!(!target.needs_large_search_confirmation());
        assert_eq!(target.vanity, "AZuZu");
        assert_eq!(
            analyze(Network::Mainnet, AddressKind::P2pkh, "DSuch")
                .unwrap()
                .expected,
            Some(4_553_521)
        );

        let edge = analyze(Network::Mainnet, AddressKind::P2pkh, "DU").unwrap();
        assert_eq!(edge.class, Class::Partial);
        assert_eq!(edge.expected, Some(49));
        assert_eq!(edge.median, Some(34));
        let low_edge = analyze(Network::Mainnet, AddressKind::P2pkh, "D5").unwrap();
        assert_eq!(low_edge.class, Class::Partial);
        assert_eq!(low_edge.expected, Some(27));
        assert_eq!(
            analyze(Network::Mainnet, AddressKind::P2pkh, "D5ZuZu")
                .unwrap()
                .class,
            Class::Full
        );
        assert_eq!(
            analyze(Network::Mainnet, AddressKind::P2pkh, "DUZuZu")
                .unwrap()
                .class,
            Class::Impossible
        );
        let letter = analyze(Network::Mainnet, AddressKind::P2pkh, "D").unwrap();
        assert_eq!(letter.class, Class::VersionImplied);
        assert_eq!(letter.expected, Some(1));
        assert_eq!(letter.median, Some(1));
        assert_eq!(letter.vanity, "");
        assert_eq!(letter.hd_window().maximum, 1.0);
        assert!(!letter.needs_hd_exhaust_confirmation());
    }

    #[test]
    fn hd_window_uses_the_receive_index_cap() {
        let easy = analyze(Network::Mainnet, AddressKind::P2pkh, "DAZuZu").unwrap();
        let easy_window = easy.hd_window();
        assert_eq!(easy_window.trials, 1 << 31);
        assert_eq!(easy_window.median, Some(183_063_098));
        assert_eq!(easy_window.p90, Some(608_122_446));
        assert_eq!(easy_window.p99, Some(1_216_244_892));
        assert!((easy_window.maximum - 0.99970578).abs() < 0.0000001);
        assert_eq!(
            easy.hd_lines(),
            "HD receive-index range:\n0 .. 2,147,483,647\nMaximum probability of a match in this mnemonic:\n99.97%\n50% probability:\n183,063,098\n90% probability:\n608,122,446\n99% probability:\n1,216,244,892\n"
        );
        assert!(!easy.needs_hd_exhaust_confirmation());

        let rare = analyze(Network::Mainnet, AddressKind::P2pkh, "DAZuZuZ").unwrap();
        let rare_window = rare.hd_window();
        assert!(rare_window.median.is_none());
        assert!(rare_window.p90.is_none());
        assert!(rare_window.p99.is_none());
        assert!((rare_window.maximum - 0.13080952).abs() < 0.0000001);
        assert!(rare.hd_lines().contains("13.08%"));
        assert!(rare
            .hd_lines()
            .contains("not reachable within this mnemonic"));
        assert!(rare.needs_hd_exhaust_confirmation());
        assert!(rare.hd_lines().contains("0 .. 2,147,483,647"));
        assert!(!rare.report().contains("HD receive-index range"));
        assert!(!analyze(Network::Mainnet, AddressKind::P2sh, "A1ZuZu")
            .unwrap()
            .report()
            .contains("HD receive-index range"));

        let impossible = analyze(Network::Mainnet, AddressKind::P2pkh, "DZuZu").unwrap();
        assert_eq!(impossible.hd_window().maximum, 0.0);
        assert!(!impossible.needs_hd_exhaust_confirmation());
    }

    #[test]
    fn p2sh_azuzu_is_impossible_and_a1zuzu_matches_dazuzu() {
        let impossible = analyze(Network::Mainnet, AddressKind::P2sh, "AZuZu").unwrap();
        assert_eq!(impossible.class, Class::Impossible);
        assert_eq!(
            impossible.endpoint_low,
            "9rSGfPZLcyCGzY4uYEL1fkzJr6fke9qKxb"
        );
        assert_eq!(
            impossible.endpoint_high,
            "AFmseVrdL9f9oyCzZefL9tG6UbvhMPRAGv"
        );
        assert_eq!(
            analyze(Network::Mainnet, AddressKind::P2sh, "9ZuZu")
                .unwrap()
                .class,
            Class::Impossible
        );
        let reachable = analyze(Network::Mainnet, AddressKind::P2sh, "A1ZuZu").unwrap();
        assert_eq!(reachable.class, Class::Full);
        assert_eq!(reachable.expected, Some(264_104_224));
        assert_eq!(
            analyze(Network::Mainnet, AddressKind::P2sh, "9sZuZu")
                .unwrap()
                .expected,
            Some(264_104_224)
        );
        assert_eq!(
            analyze(Network::Mainnet, AddressKind::P2sh, "A1")
                .unwrap()
                .expected,
            Some(23)
        );
    }

    #[test]
    fn testnet_lengths_and_labels_differ_from_mainnet() {
        let p2pkh = analyze(Network::Testnet, AddressKind::P2pkh, "n").unwrap();
        assert_eq!(p2pkh.class, Class::VersionImplied);
        assert_eq!(p2pkh.endpoint_low, "nUCAGGgZEPN1QyknmQe1oAku817bLTv8jy");
        assert_eq!(p2pkh.endpoint_high, "nsXmFNyqwZptEQtsnpyLHJ2gkWNY3hVy4J");
        assert_eq!(
            analyze(Network::Testnet, AddressKind::P2pkh, "DZuZu")
                .unwrap()
                .class,
            Class::Impossible
        );
        let p2sh = analyze(Network::Testnet, AddressKind::P2sh, "2").unwrap();
        assert_eq!(p2sh.address_len, 35);
        assert_eq!(p2sh.class, Class::VersionImplied);
        assert_eq!(p2sh.endpoint_low, "2MsFDzHRUAMpjHxKyoEHU3aMCMsVtLuLGzb");
        assert_eq!(p2sh.endpoint_high, "2NGapyPiksYHc7PU4pecnXhcyzNkq48v7Jv");
    }

    #[test]
    fn alphabet_is_rejected_before_reachability() {
        assert_eq!(
            analyze(Network::Mainnet, AddressKind::P2pkh, "D0").unwrap_err(),
            Error::prefix("prefix uses a character outside Base58 (0, O, I, and l are excluded)")
        );
        assert_eq!(
            analyze(Network::Mainnet, AddressKind::P2pkh, "DOGE").unwrap_err(),
            Error::prefix("prefix uses a character outside Base58 (0, O, I, and l are excluded)")
        );
        assert!(analyze(Network::Mainnet, AddressKind::P2pkh, "").is_err());
        assert!(analyze(Network::Mainnet, AddressKind::P2pkh, &"D".repeat(40)).is_err());
    }

    #[test]
    fn case_is_distinct_and_endpoints_round_trip() {
        let lower = analyze(Network::Mainnet, AddressKind::P2pkh, "DAZUZU").unwrap();
        let mixed = analyze(Network::Mainnet, AddressKind::P2pkh, "DAZuZu").unwrap();
        assert_eq!(lower.class, Class::Full);
        assert_ne!(lower.low, mixed.low);
        let (low, high, _, _, _) = super::version_window(0x1e).unwrap();
        assert_eq!(
            base58_encode(&low.to_payload_bytes().unwrap()),
            "D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM"
        );
        assert_eq!(
            base58_encode(&high.to_payload_bytes().unwrap()),
            "DUUhXNEw1bNAMSKgm1Kt2tSPWdzF3G5pog"
        );
        assert_eq!(high.sub(low).checked_add(U256::ONE), Some(U256::pow2(192)));
    }

    #[test]
    fn generator_payload_matches_its_text_prefix() {
        let mut key = [0u8; 32];
        key[31] = 1;
        let public = KeyEngine::new().unwrap().public_of(&key).unwrap();
        let address = address_from_hash(0x1e, &public.hash160);
        let payload = payload_for_hash(0x1e, &public.hash160);
        assert_eq!(payload.len(), PAYLOAD_LEN);
        for length in 1..=8 {
            let analysis =
                analyze(Network::Mainnet, AddressKind::P2pkh, &address[..length]).unwrap();
            assert!(analysis.contains_payload(&payload), "{length}");
            assert!(super::optimized_matches_text(&analysis, &payload));
        }
        let other = analyze(Network::Mainnet, AddressKind::P2pkh, "DAZuZu").unwrap();
        assert!(!other.contains_payload(&payload));
        assert!(super::optimized_matches_text(&other, &payload));
    }

    #[test]
    fn random_keys_agree_with_the_reference_string_match() {
        let engine = KeyEngine::new().unwrap();
        let targets = ["D", "DA", "D5", "D6", "DU", "DDoge"];
        let analyses: Vec<_> = targets
            .iter()
            .map(|prefix| analyze(Network::Mainnet, AddressKind::P2pkh, prefix).unwrap())
            .collect();
        for _ in 0..48 {
            let key = crate::doge::keys::random_scalar().unwrap();
            let public = engine.public_of(key.as_slice()).unwrap();
            let payload = payload_for_hash(0x1e, &public.hash160);
            for analysis in &analyses {
                assert!(super::optimized_matches_text(analysis, &payload));
            }
        }
    }

    #[test]
    fn grouped_digits_stop_at_fifteen() {
        assert_eq!(group_digits("4553521"), "4,553,521");
        assert_eq!(group_digits("264104224"), "264,104,224");
        assert_eq!(group_digits("10054102514374869639"), "1.005e19");
    }
}
