// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! CLI for the offline Dogecoin vanity generator.
//!
//! Private keys, WIF text, mnemonics, and passphrases are printed only by
//! `export`, after an explicit confirmation, and only when both stdin and
//! stdout are terminals.

#![forbid(unsafe_code)]

use std::io::{self, IsTerminal, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use doge_vanity::{
    analyze, check_new_passphrase, check_passphrase, check_policy, export_wallet_text,
    group_digits, inspect, measure_miss_rate, open_and_verify, require_searchable, run_self_tests,
    search, write_encrypted_wallet, AddressKind, Analysis, Error, Network, SearchMode,
    SearchRequest, CONFIRMATION_THRESHOLD, HARDENED, MAX_THREADS, MIN_NEW_PASSPHRASE_CHARS,
};

#[derive(Parser)]
#[command(
    name = "doge-vanity",
    about = "Offline Dogecoin vanity address generator",
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run cryptographic self-tests and exit.
    SelfTest,
    /// Show whether PREFIX is a reachable Dogecoin Base58 prefix.
    Analyze {
        prefix: String,
        /// mainnet or testnet. The default is mainnet.
        #[arg(long, default_value = "mainnet")]
        network: String,
        /// p2pkh, p2sh, or multisig. The default is p2pkh.
        #[arg(long = "type", default_value = "p2pkh")]
        kind: String,
    },
    /// Measure the miss path, then print reachable difficulty ranges.
    Benchmark {
        #[arg(long, default_value = "mainnet")]
        network: String,
        #[arg(long = "type", default_value = "p2pkh")]
        kind: String,
        #[arg(long)]
        threads: Option<usize>,
    },
    /// Search for PREFIX and store the winning secret in an encrypted wallet.
    Generate {
        prefix: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
        #[arg(long = "type", default_value = "p2pkh")]
        kind: String,
        /// independent or hd-index. The default is independent.
        #[arg(long, default_value = "independent")]
        mode: String,
        #[arg(long)]
        threads: Option<usize>,
        #[arg(long)]
        output: Option<PathBuf>,
        /// Multisig threshold. The default is 2. Only valid with --type multisig.
        #[arg(long)]
        threshold: Option<u8>,
        /// Multisig participant count. The default is 3. Only valid with --type multisig.
        #[arg(long)]
        participants: Option<u8>,
        /// BIP44 account. The default is 0. Only valid with --mode hd-index.
        #[arg(long)]
        account: Option<u32>,
        /// Print the compressed public key after the wallet is saved.
        #[arg(long)]
        show_public_key: bool,
    },
    /// Decode an address and check its checksum and version.
    Inspect { address: String },
    /// Decrypt a wallet offline and check the stored address.
    Verify { wallet: PathBuf },
    /// Decrypt a wallet and print recovery secrets. Offline only.
    Export { wallet: PathBuf },
    /// Report natural D… and A… forms of STEM. This does not generate a wallet.
    Collection { stem: String },
}

fn main() -> ExitCode {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn run() -> Result<(), Error> {
    match Cli::parse().command {
        Command::SelfTest => cmd_self_test(),
        Command::Analyze {
            prefix,
            network,
            kind,
        } => cmd_analyze(&prefix, &network, &kind),
        Command::Benchmark {
            network,
            kind,
            threads,
        } => cmd_benchmark(&network, &kind, threads),
        Command::Generate {
            prefix,
            network,
            kind,
            mode,
            threads,
            output,
            threshold,
            participants,
            account,
            show_public_key,
        } => cmd_generate(GenerateArgs {
            prefix: &prefix,
            network: &network,
            kind: &kind,
            mode: &mode,
            threads,
            output,
            threshold,
            participants,
            account,
            show_public_key,
        }),
        Command::Inspect { address } => {
            println!("{}", inspect(&address));
            Ok(())
        }
        Command::Verify { wallet } => cmd_verify(&wallet),
        Command::Export { wallet } => cmd_export(&wallet),
        Command::Collection { stem } => cmd_collection(&stem),
    }
}

struct GenerateArgs<'a> {
    prefix: &'a str,
    network: &'a str,
    kind: &'a str,
    mode: &'a str,
    threads: Option<usize>,
    output: Option<PathBuf>,
    threshold: Option<u8>,
    participants: Option<u8>,
    account: Option<u32>,
    show_public_key: bool,
}

fn cmd_self_test() -> Result<(), Error> {
    if let Err(err) = run_self_tests() {
        println!("Cryptographic self-tests: FAIL");
        return Err(err);
    }
    println!("Cryptographic self-tests: PASS");
    Ok(())
}

fn cmd_analyze(prefix: &str, network: &str, kind: &str) -> Result<(), Error> {
    let network = Network::parse(network)?;
    let kind = AddressKind::parse(kind)?;
    let analysis = analyze(network, kind, prefix)?;
    println!("{}", analysis.report());
    Ok(())
}

fn cmd_benchmark(network: &str, kind: &str, threads: Option<usize>) -> Result<(), Error> {
    let network = Network::parse(network)?;
    let kind = AddressKind::parse(kind)?;
    let threads = resolve_threads(threads)?;
    if let Err(err) = run_self_tests() {
        println!("Cryptographic self-tests: FAIL");
        return Err(err);
    }
    println!("Cryptographic self-tests: PASS");
    let rate = measure_miss_rate(network, kind, threads, Duration::from_secs(1))?;
    println!("Dogecoin Vanity Benchmark");
    println!();
    println!("Network:");
    println!("{}", network.label());
    println!();
    println!("Address type:");
    println!("{}", kind.label());
    println!();
    println!("Threads:");
    println!("{threads}");
    println!();
    println!("Measured miss-path rate:");
    println!("{} candidates/sec", group_u64(rate));
    println!();
    println!("There is no guaranteed completion time.");
    println!(
        "These counts assume a fresh candidate each attempt. HD index mode can test only 2,147,483,648 receive indexes of one mnemonic."
    );
    println!();
    for prefix in benchmark_targets(network, kind) {
        let analysis = analyze(network, kind, prefix)?;
        if !analysis.class.reachable() || analysis.too_rare {
            continue;
        }
        println!("Target:");
        println!("{prefix}");
        println!("Classification:");
        println!("{}", analysis.class.label());
        println!("Expected attempts:");
        println!("{}", display_option(analysis.expected));
        println!("50% probability:");
        println!("{}", display_option(analysis.median));
        println!("90% probability:");
        println!("{}", display_option(analysis.p90));
        println!("99% probability:");
        println!("{}", display_option(analysis.p99));
        println!();
    }
    Ok(())
}

fn benchmark_targets(network: Network, kind: AddressKind) -> &'static [&'static str] {
    match (network, kind) {
        (Network::Mainnet, AddressKind::P2pkh) => &["DA", "DAZ", "DAZu", "DAZuZ"],
        (Network::Mainnet, AddressKind::P2sh | AddressKind::Multisig) => {
            &["A1", "A1Z", "A1Zu", "A1ZuZ"]
        }
        (Network::Testnet, AddressKind::P2pkh) => &["na", "naZ", "naZu", "naZuZ"],
        (Network::Testnet, AddressKind::P2sh | AddressKind::Multisig) => {
            &["2N1", "2N1Z", "2N1Zu", "2N1ZuZ"]
        }
    }
}

fn cmd_generate(args: GenerateArgs<'_>) -> Result<(), Error> {
    let network = Network::parse(args.network)?;
    let kind = AddressKind::parse(args.kind)?;
    let mode = SearchMode::parse(args.mode)?;
    let analysis = analyze(network, kind, args.prefix)?;
    if let Err(err) = require_searchable(&analysis) {
        println!("{}", analysis.report());
        return Err(err);
    }
    if mode == SearchMode::HdIndex && kind != AddressKind::P2pkh {
        return Err(Error::HdMode);
    }
    let (threshold, participants) = policy_for(kind, args.threshold, args.participants)?;
    let account = account_for(mode, args.account)?;
    let threads = resolve_threads(args.threads)?;
    let output = args
        .output
        .unwrap_or_else(|| PathBuf::from(format!("{}-wallet.json", args.prefix)));
    ensure_output_available(&output)?;
    warn_if_output_dir_is_shared(&output);

    print_banner(&analysis, mode, threads, threshold, participants, account);
    if let Err(err) = run_self_tests() {
        println!("Cryptographic self-tests: FAIL");
        return Err(err);
    }
    println!("Cryptographic vectors:");
    println!("PASS");
    println!();
    println!("Dogecoin vectors:");
    println!("PASS");
    println!();
    print_difficulty(&analysis, mode);
    require_tty()?;
    if mode == SearchMode::HdIndex && analysis.needs_hd_exhaust_confirmation() {
        println!("This mnemonic's receive indexes do not reach a 50% chance.");
        println!("Type EXHAUST to continue:");
        confirm_line("EXHAUST")?;
    }
    if analysis.needs_large_search_confirmation() {
        println!(
            "This prefix is expected to take at least {} attempts.",
            group_digits(&CONFIRMATION_THRESHOLD.to_string())
        );
        println!("Type SEARCH to continue:");
        confirm_line("SEARCH")?;
    }

    let cancel = Arc::new(AtomicBool::new(false));
    let interrupt = Arc::new(AtomicBool::new(false));
    install_interrupt(Arc::clone(&cancel), Arc::clone(&interrupt))?;

    println!("Searching...");
    let _ = io::stdout().flush();
    let started = Instant::now();
    let request = SearchRequest {
        network,
        kind,
        mode,
        prefix: args.prefix.to_owned(),
        threshold,
        participants,
        account,
        index_limit: HARDENED,
    };
    let hit = search(
        &request,
        threads,
        Arc::clone(&cancel),
        move |attempts, rate| {
            println!("Attempts: {}", group_u64(attempts));
            println!("Rate: {} candidates/sec", group_u64(rate));
            println!("Elapsed: {}", format_elapsed(started.elapsed()));
            let _ = io::stdout().flush();
        },
    );
    let hit = match hit {
        Ok(hit) if interrupt.load(Ordering::Acquire) => {
            return Err(Error::Cancelled {
                attempts: hit.attempts,
            });
        }
        other => other?,
    };
    if interrupt.load(Ordering::Acquire) {
        return Err(Error::Cancelled {
            attempts: hit.attempts,
        });
    }

    println!();
    println!("Match found.");
    println!("Attempts: {}", group_u64(hit.attempts));
    println!("Elapsed: {}", format_elapsed(started.elapsed()));
    println!("The public address is printed after the encrypted wallet is saved.");
    println!();
    let _ = io::stdout().flush();

    let passphrase = match prompt_new_passphrase(interrupt.as_ref()) {
        Ok(passphrase) => passphrase,
        Err(err) => {
            eprintln!("Wallet was not saved.");
            return match err {
                Error::Cancelled { .. } => Err(Error::Cancelled {
                    attempts: hit.attempts,
                }),
                other => Err(other),
            };
        }
    };
    if interrupt.load(Ordering::Acquire) {
        eprintln!("Wallet was not saved.");
        return Err(Error::Cancelled {
            attempts: hit.attempts,
        });
    }
    let attempts = hit.attempts;
    let address = hit.address.clone();
    let path = hit.material.path().to_owned();
    let public_key = hit.material.public_key();
    let redeem = hit.material.redeem().to_vec();
    let kind = hit.material.kind();
    if let Err(err) = write_encrypted_wallet(&output, passphrase.as_str(), &hit.material, &address)
    {
        eprintln!("Wallet was not saved successfully.");
        return Err(err);
    }
    drop(hit);
    drop(passphrase);
    print_found(&FoundView {
        address: &address,
        attempts,
        elapsed: started.elapsed(),
        output: &output,
        derivation: &path,
        kind,
        show_public_key: args.show_public_key,
        public_key: &public_key,
        redeem: &redeem,
    });
    Ok(())
}

fn policy_for(
    kind: AddressKind,
    threshold: Option<u8>,
    participants: Option<u8>,
) -> Result<(u8, u8), Error> {
    if kind != AddressKind::Multisig {
        if threshold.is_some() || participants.is_some() {
            return Err(Error::Prefix(
                "threshold and participants apply only to multisig".to_owned(),
            ));
        }
        return Ok((0, 1));
    }
    let threshold = threshold.unwrap_or(2);
    let participants = participants.unwrap_or(3);
    check_policy(threshold, participants)?;
    Ok((threshold, participants))
}

fn account_for(mode: SearchMode, account: Option<u32>) -> Result<u32, Error> {
    if mode != SearchMode::HdIndex {
        if account.is_some() {
            return Err(Error::Prefix(
                "account applies only to hd-index mode".to_owned(),
            ));
        }
        return Ok(0);
    }
    let account = account.unwrap_or(0);
    if account >= HARDENED {
        Err(Error::Index)
    } else {
        Ok(account)
    }
}

fn print_banner(
    analysis: &Analysis,
    mode: SearchMode,
    threads: usize,
    threshold: u8,
    participants: u8,
    account: u32,
) {
    println!("Dogecoin Vanity Generator");
    println!();
    println!("Network:");
    println!("{}", analysis.network.label());
    println!();
    println!("Address type:");
    println!("{}", analysis.kind.label());
    println!();
    println!("Encoding:");
    println!("Base58Check");
    println!();
    println!("Mode:");
    println!("{}", mode.name());
    println!();
    println!("Target:");
    println!("{}", analysis.prefix);
    println!();
    println!("Target reachability:");
    println!("PASS");
    println!();
    if analysis.kind == AddressKind::Multisig {
        println!("Threshold:");
        println!("{threshold}");
        println!();
        println!("Participants:");
        println!("{participants}");
        println!();
        println!("Self-contained multisig:");
        println!("Every participant private key is stored in this one wallet.");
        println!("The threshold does not put keys on separate machines.");
        println!("This tool does not take outside public keys and does not cosign.");
        println!();
    }
    if mode == SearchMode::HdIndex {
        println!("Account:");
        println!("{account}");
        println!();
        println!("Change:");
        println!("0");
        println!();
    }
    println!("Threads:");
    println!("{threads}");
    println!();
}

fn print_difficulty(analysis: &Analysis, mode: SearchMode) {
    if mode == SearchMode::HdIndex {
        println!("Expected attempts in the fresh-candidate model:");
        println!("{}", display_option(analysis.expected));
        println!();
        print!("{}", analysis.hd_lines());
    } else {
        println!("Expected attempts:");
        println!("{}", display_option(analysis.expected));
        println!("50% probability:");
        println!("{}", display_option(analysis.median));
        println!("90% probability:");
        println!("{}", display_option(analysis.p90));
        println!("99% probability:");
        println!("{}", display_option(analysis.p99));
    }
    println!("There is no guaranteed completion time.");
    println!();
}

struct FoundView<'a> {
    address: &'a str,
    attempts: u64,
    elapsed: Duration,
    output: &'a Path,
    derivation: &'a str,
    kind: AddressKind,
    show_public_key: bool,
    public_key: &'a [u8; 33],
    redeem: &'a [u8],
}

fn print_found(view: &FoundView<'_>) {
    println!("FOUND");
    println!();
    println!("Address:");
    println!("{}", view.address);
    println!();
    println!("Attempts: {}", group_u64(view.attempts));
    println!("Elapsed: {}", format_elapsed(view.elapsed));
    println!(
        "Rate: {} candidates/sec",
        group_u64(rate(view.attempts, view.elapsed))
    );
    println!();
    if view.show_public_key && (view.public_key[0] == 0x02 || view.public_key[0] == 0x03) {
        println!("Compressed public key:");
        println!("{}", hex_lower(view.public_key));
        println!();
    }
    if view.show_public_key && !view.redeem.is_empty() {
        println!("Redeem script:");
        println!("{}", hex_lower(view.redeem));
        println!();
    }
    if view.kind == AddressKind::Multisig {
        println!("Self-contained multisig: every participant private key is in this wallet.");
        println!("The threshold does not split keys across machines.");
        println!("The redeem script and every participant key are inside the wallet.");
        println!("The address alone is not enough to recover a multisig output.");
        println!();
    }
    if !view.derivation.is_empty() {
        println!("Derivation path:");
        println!("{}", view.derivation);
        println!("A mnemonic restore does not by itself rediscover this index.");
        println!("Dogecoin Core 1.14 has no BIP39 import. export prints the child import form.");
        println!("A gap limit of 20 will not discover a high index.");
        println!();
    }
    println!("Secret storage:");
    println!("{}", view.output.display());
    println!();
    println!("Independent Dogecoin verification:");
    println!("PASS");
    println!();
    println!("Recovery test:");
    println!("PENDING");
    println!();
    println!("This program did not broadcast a transaction.");
}

fn cmd_verify(path: &Path) -> Result<(), Error> {
    require_tty()?;
    let interrupt = install_command_interrupt()?;
    let passphrase = prompt_password_interruptible("Passphrase: ", interrupt.as_ref())?;
    check_passphrase(passphrase.as_str())?;
    let opened = open_and_verify(path, passphrase.as_str())?;
    drop(passphrase);
    secret_output_allowed(interrupt.load(Ordering::Acquire))?;
    let address = opened.address.clone();
    let network = opened.network;
    let kind = opened.kind;
    let mode = opened.mode;
    let derivation = opened.path.clone();
    drop(opened);
    secret_output_allowed(interrupt.load(Ordering::Acquire))?;
    println!("Wallet authentication: PASS");
    println!("Secret-to-address reconstruction: PASS");
    println!("Independent verification: PASS");
    println!();
    println!("Network:");
    println!("{}", network.label());
    println!("Address type:");
    println!("{}", kind.label());
    println!("Mode:");
    println!("{}", mode.name());
    if !derivation.is_empty() {
        println!("Derivation path:");
        println!("{derivation}");
    }
    println!();
    println!("Stored:");
    println!("{address}");
    println!();
    println!("Derived:");
    println!("{address}");
    println!();
    println!("MATCH: YES");
    Ok(())
}

fn cmd_export(path: &Path) -> Result<(), Error> {
    require_export_terminals()?;
    println!("WARNING: This operation prints Dogecoin recovery secrets to this terminal.");
    println!(
        "Do not paste them into a website, chat, AI, issue tracker, shell history, or online verifier."
    );
    println!("Only the public address may be shared.");
    println!(
        "Clear the terminal scrollback after the secrets have been copied onto offline media."
    );
    println!("Type EXPORT to continue:");
    confirm_line("EXPORT")?;
    let interrupt = install_command_interrupt()?;
    let passphrase = prompt_password_interruptible("Passphrase: ", interrupt.as_ref())?;
    check_passphrase(passphrase.as_str())?;
    let opened = open_and_verify(path, passphrase.as_str())?;
    drop(passphrase);
    secret_output_allowed(interrupt.load(Ordering::Acquire))?;
    let secret = export_wallet_text(&opened)?;
    drop(opened);
    secret_output_allowed(interrupt.load(Ordering::Acquire))?;
    print!("{}", secret.as_str());
    Ok(())
}

fn cmd_collection(stem: &str) -> Result<(), Error> {
    if stem.is_empty() {
        return Err(Error::Prefix("collection stem is empty".to_owned()));
    }
    println!("DOGE ZUZU COLLECTION");
    println!();
    println!("This command does not generate a wallet.");
    println!("It does not substitute a different prefix when the natural one is unreachable.");
    println!("P2PKH remains the primary receiving address when you explicitly generate a reachable prefix.");
    println!();
    let p2pkh_prefix = format!("D{stem}");
    let p2sh_prefix = format!("A{stem}");
    let p2pkh = analyze(Network::Mainnet, AddressKind::P2pkh, &p2pkh_prefix)?;
    println!("{}", p2pkh.report());
    let p2sh = analyze(Network::Mainnet, AddressKind::P2sh, &p2sh_prefix)?;
    println!("{}", p2sh.report());
    println!("Multisig P2SH uses Dogecoin version 0x16, the same byte as the P2SH report above.");
    println!(
        "Legal next characters are listed in each report. An unreachable report is not a search."
    );
    Ok(())
}

fn display_option(value: Option<u64>) -> String {
    match value {
        Some(value) => group_digits(&value.to_string()),
        None => "n/a".to_owned(),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn warn_if_output_dir_is_shared(path: &Path) {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let Ok(meta) = std::fs::metadata(parent) else {
        return;
    };
    if meta.permissions().mode() & 0o022 != 0 {
        eprintln!(
            "warning: output directory is writable by group or others. Create a private directory with: mkdir -m 700 <dir>"
        );
    }
}

fn ensure_output_available(path: &Path) -> Result<(), Error> {
    if path.exists() {
        return Err(Error::OutputExists);
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.is_dir() {
            return Err(Error::OutputDir);
        }
    }
    Ok(())
}

fn resolve_threads(threads: Option<usize>) -> Result<usize, Error> {
    match threads {
        Some(value) => {
            if value == 0 || value > MAX_THREADS {
                Err(Error::Threads)
            } else {
                Ok(value)
            }
        }
        None => Ok(default_threads()),
    }
}

fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .clamp(1, MAX_THREADS)
}

fn require_tty() -> Result<(), Error> {
    if io::stdin().is_terminal() {
        Ok(())
    } else {
        Err(Error::NeedTerminal)
    }
}

fn require_export_terminals() -> Result<(), Error> {
    export_terminals_ok(io::stdin().is_terminal(), io::stdout().is_terminal())
}

fn export_terminals_ok(stdin_tty: bool, stdout_tty: bool) -> Result<(), Error> {
    if stdin_tty && stdout_tty {
        Ok(())
    } else {
        Err(Error::ExportNeedsTerminal)
    }
}

fn confirm_line(expected: &str) -> Result<(), Error> {
    require_tty()?;
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|err| Error::Io(format!("stdin: {err}")))?;
    if line.trim() == expected {
        Ok(())
    } else {
        Err(Error::NotConfirmed)
    }
}

fn install_command_interrupt() -> Result<Arc<AtomicBool>, Error> {
    let interrupt = Arc::new(AtomicBool::new(false));
    let cancel = Arc::new(AtomicBool::new(false));
    install_interrupt(cancel, Arc::clone(&interrupt))?;
    Ok(interrupt)
}

fn secret_output_allowed(interrupted: bool) -> Result<(), Error> {
    if interrupted {
        Err(Error::Cancelled { attempts: 0 })
    } else {
        Ok(())
    }
}

fn prompt_new_passphrase(interrupt: &AtomicBool) -> Result<Zeroizing<String>, Error> {
    require_tty()?;
    for _ in 0..3 {
        if interrupt.load(Ordering::Acquire) {
            return Err(Error::Cancelled { attempts: 0 });
        }
        let first = prompt_password_interruptible("Passphrase: ", interrupt)?;
        let second = prompt_password_interruptible("Confirm passphrase: ", interrupt)?;
        if first.as_str() != second.as_str() {
            eprintln!("error: passphrase did not match");
            continue;
        }
        match check_new_passphrase(first.as_str()) {
            Ok(()) => return Ok(first),
            Err(_) => {
                if check_passphrase(first.as_str()).is_ok() {
                    eprintln!(
                        "error: a new passphrase must be at least {MIN_NEW_PASSPHRASE_CHARS} characters"
                    );
                    eprintln!(
                        "That minimum only stops accidents. It is not a measure of strength."
                    );
                } else {
                    eprintln!("error: passphrase rejected");
                }
            }
        }
    }
    Err(Error::Passphrase)
}

fn prompt_password_interruptible(
    label: &str,
    interrupt: &AtomicBool,
) -> Result<Zeroizing<String>, Error> {
    if interrupt.load(Ordering::Acquire) {
        return Err(Error::Cancelled { attempts: 0 });
    }
    password_prompt_result(
        rpassword::prompt_password(label),
        interrupt.load(Ordering::Acquire),
    )
}

fn password_prompt_result(
    read: Result<String, std::io::Error>,
    interrupted: bool,
) -> Result<Zeroizing<String>, Error> {
    if interrupted {
        if let Ok(password) = read {
            drop(Zeroizing::new(password));
        }
        return Err(Error::Cancelled { attempts: 0 });
    }
    match read {
        Ok(password) => Ok(Zeroizing::new(password)),
        Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {
            Err(Error::Cancelled { attempts: 0 })
        }
        Err(_) => Err(Error::NeedTerminal),
    }
}

fn install_interrupt(cancel: Arc<AtomicBool>, interrupt: Arc<AtomicBool>) -> Result<(), Error> {
    ctrlc::set_handler(move || {
        interrupt.store(true, Ordering::Release);
        cancel.store(true, Ordering::Release);
    })
    .map_err(|_| Error::Io("could not install the interrupt handler".to_owned()))
}

fn group_u64(value: u64) -> String {
    group_digits(&value.to_string())
}

fn rate(attempts: u64, elapsed: Duration) -> u64 {
    let seconds = elapsed.as_secs_f64();
    if seconds <= 0.0 {
        attempts
    } else {
        (attempts as f64 / seconds) as u64
    }
}

fn format_elapsed(elapsed: Duration) -> String {
    if elapsed.as_secs() < 60 {
        format!("{:.3}s", elapsed.as_secs_f64())
    } else {
        let seconds = elapsed.as_secs();
        format!("{}m {}s", seconds / 60, seconds % 60)
    }
}

#[cfg(test)]
mod tests {
    use super::{export_terminals_ok, password_prompt_result, secret_output_allowed, Error};

    #[test]
    fn export_requires_both_terminals() {
        assert!(export_terminals_ok(true, true).is_ok());
        assert_eq!(
            export_terminals_ok(true, false),
            Err(Error::ExportNeedsTerminal)
        );
        assert_eq!(
            export_terminals_ok(false, true),
            Err(Error::ExportNeedsTerminal)
        );
    }

    #[test]
    fn interrupted_passphrase_read_cancels_without_keeping_it() {
        let accepted =
            password_prompt_result(Ok("correct horse battery".to_owned()), false).unwrap();
        assert_eq!(accepted.as_str(), "correct horse battery");
        assert!(matches!(
            password_prompt_result(Ok("secret-passphrase".to_owned()), true),
            Err(Error::Cancelled { attempts: 0 })
        ));
        let interrupted = std::io::Error::new(std::io::ErrorKind::Interrupted, "interrupted");
        assert!(matches!(
            password_prompt_result(Err(interrupted), false),
            Err(Error::Cancelled { attempts: 0 })
        ));
    }

    #[test]
    fn cancelled_decrypt_does_not_release_a_secret() {
        assert!(secret_output_allowed(false).is_ok());
        assert!(matches!(
            secret_output_allowed(true),
            Err(Error::Cancelled { attempts: 0 })
        ));
    }
}
