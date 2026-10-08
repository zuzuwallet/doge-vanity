// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use doge_vanity::{
    confirm_material, counter_would_overflow, search, AddressKind, Error, Network, SearchMode,
    SearchRequest, COUNTER_HEADROOM, HARDENED, MAX_THREADS,
};

fn request(prefix: &str, kind: AddressKind, mode: SearchMode) -> SearchRequest {
    SearchRequest {
        network: Network::Mainnet,
        kind,
        mode,
        prefix: prefix.to_owned(),
        threshold: if kind == AddressKind::Multisig { 2 } else { 0 },
        participants: if kind == AddressKind::Multisig { 2 } else { 1 },
        account: 0,
        index_limit: HARDENED,
    }
}

#[test]
fn counter_saturates_before_wrapping() {
    assert!(!counter_would_overflow(0));
    assert!(!counter_would_overflow(u64::MAX - COUNTER_HEADROOM - 1));
    assert!(counter_would_overflow(u64::MAX - COUNTER_HEADROOM));
    assert_eq!(MAX_THREADS, 256);
}

#[test]
fn thread_count_is_checked() {
    let cancel = Arc::new(AtomicBool::new(false));
    let err = search(
        &request("D", AddressKind::P2pkh, SearchMode::Independent),
        0,
        cancel,
        |_, _| {},
    )
    .unwrap_err();
    assert_eq!(err, Error::Threads);
}

#[test]
fn preset_cancel_does_no_work() {
    let cancel = Arc::new(AtomicBool::new(true));
    let err = search(
        &request("D", AddressKind::P2pkh, SearchMode::Independent),
        2,
        cancel,
        |_, _| {},
    )
    .unwrap_err();
    match err {
        Error::Cancelled { attempts } => assert_eq!(attempts, 0),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn prefix_d_stops_every_worker() {
    let cancel = Arc::new(AtomicBool::new(false));
    let hit = search(
        &request("DA", AddressKind::P2pkh, SearchMode::Independent),
        4,
        Arc::clone(&cancel),
        |_, _| {},
    )
    .unwrap();
    assert!(hit.address.starts_with("DA"), "{}", hit.address);
    assert_eq!(hit.address.len(), 34);
    assert!(hit.attempts > 0);
    assert!(hit.attempts < 20_000, "{}", hit.attempts);
    assert!(cancel.load(Ordering::Acquire));
    let rendered = format!("{hit:?}");
    assert!(rendered.contains("[redacted]"));
    assert!(!rendered.contains("WIF"));
    confirm_material(&hit.material, &hit.address).unwrap();
}

#[test]
fn cancel_during_a_rare_prefix_returns_cancelled() {
    let cancel = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&cancel);
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(50));
        flag.store(true, Ordering::Release);
    });
    let err = search(
        &request("DAZuZu", AddressKind::P2pkh, SearchMode::Independent),
        2,
        cancel,
        |_, _| {},
    )
    .unwrap_err();
    match err {
        Error::Cancelled { attempts } => assert!(attempts < 5_000_000, "{attempts}"),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn p2sh_and_multisig_find_a_short_reachable_prefix() {
    let cancel = Arc::new(AtomicBool::new(false));
    let p2sh = search(
        &request("A", AddressKind::P2sh, SearchMode::Independent),
        2,
        Arc::clone(&cancel),
        |_, _| {},
    )
    .unwrap();
    assert!(p2sh.address.starts_with('A'), "{}", p2sh.address);
    confirm_material(&p2sh.material, &p2sh.address).unwrap();
    assert!(!p2sh.material.redeem().is_empty());

    let multi = search(
        &request("A", AddressKind::Multisig, SearchMode::Independent),
        2,
        Arc::new(AtomicBool::new(false)),
        |_, _| {},
    )
    .unwrap();
    assert!(multi.address.starts_with('A'), "{}", multi.address);
    assert_eq!(multi.material.threshold(), 2);
    assert_eq!(multi.material.participants(), 2);
    confirm_material(&multi.material, &multi.address).unwrap();
}

#[test]
fn hd_index_finds_a_version_implied_prefix_and_exhausts_a_tiny_range() {
    let cancel = Arc::new(AtomicBool::new(false));
    let hit = search(
        &request("D", AddressKind::P2pkh, SearchMode::HdIndex),
        1,
        cancel,
        |_, _| {},
    )
    .unwrap();
    assert!(hit.address.starts_with('D'));
    assert_eq!(hit.material.path(), "m/44'/3'/0'/0/0");
    assert_eq!(hit.material.index(), 0);
    confirm_material(&hit.material, &hit.address).unwrap();
    let rendered = format!("{:?}", hit.material);
    assert!(rendered.contains("[redacted]"));

    let mut limited = request("DAZuZu", AddressKind::P2pkh, SearchMode::HdIndex);
    limited.index_limit = 2;
    let err = search(&limited, 1, Arc::new(AtomicBool::new(false)), |_, _| {}).unwrap_err();
    match err {
        Error::RangeExhausted { attempts } => assert!(attempts <= 2, "{attempts}"),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn impossible_prefix_does_not_search() {
    let err = search(
        &request("DZuZu", AddressKind::P2pkh, SearchMode::Independent),
        1,
        Arc::new(AtomicBool::new(false)),
        |_, _| {},
    )
    .unwrap_err();
    assert!(matches!(err, Error::Prefix(_)));
}
