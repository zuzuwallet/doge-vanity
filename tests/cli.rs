// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

#![forbid(unsafe_code)]

use std::process::Command;

fn bin() -> std::path::PathBuf {
    if let Some(path) = option_env!("CARGO_BIN_EXE_doge_vanity") {
        return std::path::PathBuf::from(path);
    }
    if let Some(path) = option_env!("CARGO_BIN_EXE_doge-vanity") {
        return std::path::PathBuf::from(path);
    }
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    path.push("doge-vanity");
    path
}

fn scratch(label: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("doge-vanity-cli-{label}-{nanos}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn self_test_command_passes() {
    let output = Command::new(bin()).arg("self-test").output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stdout {stdout}\nstderr {stderr}");
    assert!(stdout.contains("Cryptographic self-tests: PASS"));
    assert!(!stdout.contains("WIF:"));
}

#[test]
fn analyze_dzuzu_is_reachable_no_and_exits_zero() {
    let output = Command::new(bin())
        .args(["analyze", "--type", "p2pkh", "DZuZu"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    assert!(stdout.contains("Reachable:\nNO"));
    assert!(stdout.contains("D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM"));
    assert!(stdout.contains("58^4 = 11,316,496"));
    assert!(!stdout.contains("FOUND"));
}

#[test]
fn analyze_dazuzu_prints_the_integer_model() {
    let output = Command::new(bin())
        .args(["analyze", "--type", "p2pkh", "DAZuZu"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    assert!(stdout.contains("Reachable:\nYES"));
    assert!(stdout.contains("264,104,224"));
    assert!(stdout.contains("183,063,098"));
    assert!(!stdout.contains("HD receive-index range"));
}

#[test]
fn analyze_dazuzuz_stays_on_the_unlimited_model() {
    let output = Command::new(bin())
        .args(["analyze", "--type", "p2pkh", "DAZuZuZ"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    assert!(stdout.contains("15,318,045,009"));
    assert!(!stdout.contains("HD receive-index range"));
}

#[test]
fn analyze_p2sh_and_multisig_omit_the_hd_window() {
    for kind in ["p2sh", "multisig"] {
        let output = Command::new(bin())
            .args(["analyze", "--type", kind, "A1ZuZu"])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "{kind}\nstdout {stdout}\nstderr {stderr}"
        );
        assert!(stdout.contains("264,104,224"), "{kind}\n{stdout}");
        assert!(
            !stdout.contains("HD receive-index range"),
            "{kind}\n{stdout}"
        );
    }
}

#[test]
fn hd_index_rejects_p2sh_without_an_hd_window() {
    let output = Command::new(bin())
        .args(["generate", "--mode", "hd-index", "--type", "p2sh", "A1ZuZu"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("hd-index mode is only available for P2PKH"),
        "{stderr}"
    );
    assert!(!stdout.contains("HD receive-index range"), "{stdout}");
    assert!(!stdout.contains("Type EXHAUST to continue:"), "{stdout}");
}

#[test]
fn analyze_azuzu_is_not_a_p2sh_target() {
    let output = Command::new(bin())
        .args(["analyze", "--type", "p2sh", "AZuZu"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    assert!(stdout.contains("Reachable:\nNO"));
    assert!(stdout.contains("9rSGfPZLcyCGzY4uYEL1fkzJr6fke9qKxb"));
}

#[test]
fn generate_dzuzu_creates_no_wallet_and_skips_self_test() {
    let dir = scratch("dzuzu");
    let output = Command::new(bin())
        .args(["generate", "--type", "p2pkh", "DZuZu"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("Reachable:\nNO"), "{stdout}");
    assert!(!stdout.contains("Cryptographic vectors"));
    assert!(!stdout.contains("FOUND"));
    assert!(!stdout.contains("Address:"));
    assert!(!stderr.contains("WIF:"));
    assert!(!dir.join("DZuZu-wallet.json").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn zero_threads_creates_no_wallet() {
    let dir = scratch("threads");
    let output = Command::new(bin())
        .args(["generate", "--type", "p2pkh", "DAZuZu", "--threads", "0"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid thread count"));
    assert!(!dir.join("DAZuZu-wallet.json").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn doge_is_an_alphabet_error() {
    let output = Command::new(bin())
        .args(["analyze", "DOGE"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Base58"));
}

#[test]
fn inspect_checks_checksum_rather_than_the_first_letter() {
    let output = Command::new(bin())
        .args(["inspect", "DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    assert!(stdout.contains("Type:\nP2PKH"));
    assert!(stdout.contains("Checksum:\nPASS"));
    assert!(stdout.contains("Valid:\nYES"));
    assert!(stdout.contains("Network:\nMainnet"));

    let bad = Command::new(bin())
        .args(["inspect", "DZuZu"])
        .output()
        .unwrap();
    let bad_out = String::from_utf8_lossy(&bad.stdout);
    assert!(bad.status.success(), "{bad_out}");
    assert!(bad_out.contains("Valid:\nNO"));
    assert!(!bad_out.contains("Type:\nP2PKH"));
}

#[test]
fn collection_does_not_invent_a_wallet() {
    let dir = scratch("collection");
    let output = Command::new(bin())
        .args(["collection", "ZuZu"])
        .current_dir(&dir)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stdout {stdout}\nstderr {stderr}");
    assert!(stdout.contains("DZuZu"));
    assert!(stdout.contains("AZuZu"));
    assert!(stdout.contains("Reachable:\nNO"));
    assert!(!stdout.contains("HD receive-index range"));
    assert!(!stdout.contains("FOUND"));
    assert!(!stdout.contains("Address:"));
    assert!(std::fs::read_dir(&dir).unwrap().next().is_none());
    let _ = std::fs::remove_dir_all(&dir);
}
