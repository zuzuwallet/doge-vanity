// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Parallel vanity search.
//!
//! Independent mode draws a fresh scalar from the operating-system CSPRNG for
//! every attempt. Workers do not walk `k, k+1, ...` and do not derive secrets
//! from the vanity text or from worker ids. HD index mode strides the
//! non-hardened receive index. That index is a counter by definition. The
//! mnemonic entropy is still one CSPRNG draw.
//!
//! A panic, an RNG failure, or an invalid hit cancels the search and discards
//! every other worker's candidate. Invalid scalars are not counted.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::doge::hash::hash160;
use crate::doge::keys::{
    encode_payload, payload_for_hash, random_entropy_32, random_scalar, KeyEngine, PAYLOAD_LEN,
};
use crate::doge::optimized_matches_text;
use crate::doge::script::{multisig_redeem, p2pkh_redeem};
use crate::doge::{
    address_from_hash, analyze, derive_index, master_from_seed, receive_address,
    require_searchable, seed_from_entropy, AddressKind, Analysis, HdNode, Network, SearchMode,
    HARDENED, SEARCH_COUNTER_HEADROOM,
};
use crate::error::Error;
use crate::verify::confirm_material;
use crate::wallet::WalletMaterial;

pub const MAX_THREADS: usize = 256;
pub const COUNTER_HEADROOM: u64 = SEARCH_COUNTER_HEADROOM;
const ATTEMPT_CHUNK: u64 = 1024;

/// External-chain parent copied into an HD worker. The mnemonic stays in the parent thread.
struct WorkerParent {
    key: Zeroizing<[u8; 32]>,
    chain: Zeroizing<[u8; 32]>,
    depth: u8,
}

pub fn counter_would_overflow(current: u64) -> bool {
    current >= u64::MAX.saturating_sub(COUNTER_HEADROOM)
}

pub struct SearchRequest {
    pub network: Network,
    pub kind: AddressKind,
    pub mode: SearchMode,
    pub prefix: String,
    pub threshold: u8,
    pub participants: u8,
    pub account: u32,
    /// Exclusive end of the non-hardened HD receive index.
    ///
    /// The command-line tool sets this to `HARDENED` (`2^31`). A smaller
    /// exclusive end is how tests observe range exhaustion. It cannot move
    /// the search into hardened indices.
    pub index_limit: u32,
}

pub struct SearchHit {
    pub address: String,
    pub attempts: u64,
    pub material: WalletMaterial,
}

impl std::fmt::Debug for SearchHit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SearchHit")
            .field("address", &self.address)
            .field("attempts", &self.attempts)
            .field("material", &self.material)
            .finish()
    }
}

enum RawHit {
    One(Zeroizing<[u8; 32]>),
    Many(Zeroizing<Vec<[u8; 32]>>),
    Index(u32),
}

pub fn validate_threads(threads: usize) -> Result<(), Error> {
    if threads == 0 || threads > MAX_THREADS {
        Err(Error::Threads)
    } else {
        Ok(())
    }
}

pub fn search<F>(
    request: &SearchRequest,
    threads: usize,
    cancel: Arc<AtomicBool>,
    progress: F,
) -> Result<SearchHit, Error>
where
    F: Fn(u64, u64) + Send + Sync + 'static,
{
    if request.mode == SearchMode::HdIndex && request.kind != AddressKind::P2pkh {
        return Err(Error::HdMode);
    }
    if request.kind == AddressKind::Multisig {
        crate::doge::check_policy(request.threshold, request.participants)?;
    }
    if request.mode == SearchMode::HdIndex
        && (request.account >= HARDENED
            || request.index_limit == 0
            || request.index_limit > HARDENED)
    {
        return Err(Error::Index);
    }
    let analysis = analyze(request.network, request.kind, &request.prefix)?;
    require_searchable(&analysis)?;
    validate_threads(threads)?;

    let entropy = if request.mode == SearchMode::HdIndex {
        Some(random_entropy_32()?)
    } else {
        None
    };
    let hd_parent = if let Some(entropy) = &entropy {
        Some(external_chain(request, entropy.as_slice())?)
    } else {
        None
    };

    let attempts = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicBool::new(false));
    let overflow = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<RawHit>();
    let reporter = spawn_reporter(Arc::clone(&attempts), Arc::clone(&cancel), progress);

    let mut handles = Vec::with_capacity(threads);
    for worker_id in 0..threads {
        let tx = tx.clone();
        let cancel_worker = Arc::clone(&cancel);
        let attempts = Arc::clone(&attempts);
        let failed_worker = Arc::clone(&failed);
        let overflow = Arc::clone(&overflow);
        let analysis = analysis.clone();
        let request_kind = request.kind;
        let request_network = request.network;
        let request_mode = request.mode;
        let threshold = request.threshold;
        let participants = request.participants;
        let index_limit = request.index_limit;
        let parent = hd_parent.as_ref().map(|node| WorkerParent {
            key: Zeroizing::new(*node.key_bytes()),
            chain: Zeroizing::new(*node.chain_code()),
            depth: node.depth,
        });
        match thread::Builder::new()
            .name("doge-vanity".to_owned())
            .spawn(move || {
                let outcome = catch_unwind(AssertUnwindSafe(|| {
                    worker(
                        &analysis,
                        request_network,
                        request_kind,
                        request_mode,
                        threshold,
                        participants,
                        worker_id,
                        threads,
                        index_limit,
                        parent,
                        &cancel_worker,
                        &attempts,
                        &overflow,
                        &tx,
                    )
                }));
                if !matches!(outcome, Ok(Ok(()))) {
                    failed_worker.store(true, Ordering::Release);
                    cancel_worker.store(true, Ordering::Release);
                }
            }) {
            Ok(handle) => handles.push(handle),
            Err(_) => {
                failed.store(true, Ordering::Release);
                cancel.store(true, Ordering::Release);
                break;
            }
        }
    }
    drop(tx);

    let first = rx.recv();
    // Read the flag before this function sets it. HD workers that finish the
    // index space leave the flag false. A user interrupt, a panic, or an
    // overflow sets it. Storing first would make exhaustion look like a cancel.
    let user_cancelled = cancel.load(Ordering::Acquire);
    cancel.store(true, Ordering::Release);
    join_workers(handles);
    let _ = reporter.join();
    while rx.try_recv().is_ok() {}

    let total = attempts.load(Ordering::Relaxed);
    if failed.load(Ordering::Acquire) {
        return Err(Error::SearchFailed);
    }
    if overflow.load(Ordering::Acquire) && first.is_err() {
        return Err(Error::SearchFailed);
    }
    let Some(raw) = first.ok() else {
        return Err(empty_channel(request.mode, user_cancelled, total));
    };
    finish_hit(request, &analysis, raw, total, entropy)
}

fn empty_channel(mode: SearchMode, user_cancelled: bool, attempts: u64) -> Error {
    if mode == SearchMode::HdIndex && !user_cancelled {
        Error::RangeExhausted { attempts }
    } else {
        Error::Cancelled { attempts }
    }
}

fn finish_hit(
    request: &SearchRequest,
    analysis: &Analysis,
    raw: RawHit,
    attempts: u64,
    entropy: Option<Zeroizing<[u8; 32]>>,
) -> Result<SearchHit, Error> {
    let engine = KeyEngine::new()?;
    let (address, material) = match raw {
        RawHit::One(key) => finish_one(request, &engine, key)?,
        RawHit::Many(keys) => finish_many(request, &engine, keys)?,
        RawHit::Index(index) => {
            let entropy = entropy.ok_or(Error::SearchFailed)?;
            finish_index(request, &engine, &entropy, index)?
        }
    };
    if !address.starts_with(analysis.prefix.as_str()) {
        return Err(Error::SearchFailed);
    }
    confirm_material(&material, &address)?;
    Ok(SearchHit {
        address,
        attempts,
        material,
    })
}

fn finish_one(
    request: &SearchRequest,
    engine: &KeyEngine,
    key: Zeroizing<[u8; 32]>,
) -> Result<(String, WalletMaterial), Error> {
    let public = engine.public_of(key.as_slice())?;
    match request.kind {
        AddressKind::P2pkh => {
            let address = address_from_hash(request.network.p2pkh_version(), &public.hash160);
            Ok((
                address,
                WalletMaterial::p2pkh(request.network, key, public.key),
            ))
        }
        AddressKind::P2sh => {
            let script = p2pkh_redeem(&public.hash160);
            let address = address_from_hash(request.network.p2sh_version(), &hash160(&script));
            Ok((
                address,
                WalletMaterial::p2sh(request.network, key, script.to_vec(), public.key),
            ))
        }
        AddressKind::Multisig => Err(Error::SearchFailed),
    }
}

fn finish_many(
    request: &SearchRequest,
    engine: &KeyEngine,
    keys: Zeroizing<Vec<[u8; 32]>>,
) -> Result<(String, WalletMaterial), Error> {
    let mut publics = Vec::with_capacity(keys.len());
    for key in keys.iter() {
        publics.push(engine.public_of(key)?.key);
    }
    let script = multisig_redeem(request.threshold, &publics)?;
    let address = address_from_hash(request.network.p2sh_version(), &hash160(&script));
    Ok((
        address,
        WalletMaterial::multisig(request.network, request.threshold, keys, script),
    ))
}

fn finish_index(
    request: &SearchRequest,
    engine: &KeyEngine,
    entropy: &Zeroizing<[u8; 32]>,
    index: u32,
) -> Result<(String, WalletMaterial), Error> {
    let seed = seed_from_entropy(entropy.as_slice())?;
    let (child, address) = receive_address(
        engine,
        seed.as_slice(),
        request.network,
        request.account,
        index,
    )?;
    let public = engine.public_of(child.key_bytes())?;
    let steps = crate::doge::receive_steps(request.network, request.account, index)?;
    let path = crate::doge::format_path(&steps);
    Ok((
        address,
        WalletMaterial::hd(
            request.network,
            Zeroizing::new(**entropy),
            request.account,
            index,
            path,
            public.key,
        ),
    ))
}

fn external_chain(request: &SearchRequest, entropy: &[u8]) -> Result<HdNode, Error> {
    let seed = seed_from_entropy(entropy)?;
    let engine = KeyEngine::new()?;
    let master = master_from_seed(seed.as_slice())?;
    let steps = [
        44 | HARDENED,
        request.network.coin_type() | HARDENED,
        request.account | HARDENED,
        0,
    ];
    crate::doge::derive_path(&engine, &master, &steps)
}

pub fn measure_miss_rate(
    network: Network,
    kind: AddressKind,
    threads: usize,
    duration: Duration,
) -> Result<u64, Error> {
    validate_threads(threads)?;
    let prefix = match (network, kind) {
        (Network::Mainnet, AddressKind::P2pkh) => "DAZuZu",
        (Network::Mainnet, AddressKind::P2sh | AddressKind::Multisig) => "A1ZuZu",
        // `n` and `2` are version-implied. These longer prefixes sit inside
        // the endpoint text, so the miss path is a real search.
        (Network::Testnet, AddressKind::P2pkh) => "naZuZu",
        (Network::Testnet, AddressKind::P2sh | AddressKind::Multisig) => "2N1ZuZu",
    };
    let analysis = analyze(network, kind, prefix)?;
    require_searchable(&analysis)?;
    let attempts = Arc::new(AtomicU64::new(0));
    let cancel = Arc::new(AtomicBool::new(false));
    let started = Instant::now();
    let mut handles = Vec::new();
    for _ in 0..threads {
        let attempts = Arc::clone(&attempts);
        let cancel = Arc::clone(&cancel);
        let analysis = analysis.clone();
        let threshold = if kind == AddressKind::Multisig { 2 } else { 0 };
        let participants = if kind == AddressKind::Multisig { 3 } else { 1 };
        handles.push(thread::spawn(move || {
            let _ = worker(
                &analysis,
                network,
                kind,
                SearchMode::Independent,
                threshold,
                participants,
                0,
                1,
                0,
                None,
                &cancel,
                &attempts,
                &AtomicBool::new(false),
                &{
                    let (tx, _rx) = mpsc::channel();
                    tx
                },
            );
        }));
    }
    while started.elapsed() < duration {
        thread::sleep(Duration::from_millis(20));
    }
    cancel.store(true, Ordering::Release);
    join_workers(handles);
    let total = attempts.load(Ordering::Relaxed);
    let seconds = started.elapsed().as_secs_f64();
    if seconds <= 0.0 {
        Ok(total)
    } else {
        Ok((total as f64 / seconds) as u64)
    }
}

fn spawn_reporter<F>(
    attempts: Arc<AtomicU64>,
    cancel: Arc<AtomicBool>,
    progress: F,
) -> JoinHandle<()>
where
    F: Fn(u64, u64) + Send + Sync + 'static,
{
    thread::spawn(move || {
        let mut last_count = 0u64;
        let mut last_report = Instant::now();
        while !cancel.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(50));
            if cancel.load(Ordering::Acquire) {
                break;
            }
            if last_report.elapsed() < Duration::from_secs(1) {
                continue;
            }
            let now = attempts.load(Ordering::Relaxed);
            let elapsed = last_report.elapsed().as_secs_f64();
            let rate = if elapsed > 0.0 {
                ((now.saturating_sub(last_count)) as f64 / elapsed) as u64
            } else {
                0
            };
            let _ = catch_unwind(AssertUnwindSafe(|| progress(now, rate)));
            last_count = now;
            last_report = Instant::now();
        }
    })
}

fn join_workers(handles: Vec<JoinHandle<()>>) {
    for handle in handles {
        let _ = handle.join();
    }
}

#[allow(clippy::too_many_arguments)]
fn worker(
    analysis: &Analysis,
    network: Network,
    kind: AddressKind,
    mode: SearchMode,
    threshold: u8,
    participants: u8,
    worker_id: usize,
    threads: usize,
    index_limit: u32,
    parent: Option<WorkerParent>,
    cancel: &AtomicBool,
    attempts: &AtomicU64,
    overflow: &AtomicBool,
    tx: &Sender<RawHit>,
) -> Result<(), Error> {
    let engine = KeyEngine::new()?;
    let mut local = 0u64;
    let result = if mode == SearchMode::HdIndex {
        let parent = parent.ok_or(Error::SearchFailed)?;
        hd_worker(
            analysis,
            network,
            &engine,
            HdNode::from_private(parent.key, parent.chain, parent.depth),
            worker_id,
            threads,
            index_limit,
            cancel,
            attempts,
            overflow,
            tx,
            &mut local,
        )
    } else if kind == AddressKind::Multisig {
        multi_worker(
            analysis,
            network,
            &engine,
            threshold,
            participants,
            cancel,
            attempts,
            overflow,
            tx,
            &mut local,
        )
    } else {
        single_worker(
            analysis, network, kind, &engine, cancel, attempts, overflow, tx, &mut local,
        )
    };
    if local > 0 {
        attempts.fetch_add(local, Ordering::Relaxed);
    }
    result
}

fn text_match(analysis: &Analysis, payload: &[u8; PAYLOAD_LEN]) -> Result<bool, Error> {
    if !analysis.contains_payload(payload) {
        return Ok(false);
    }
    let address = encode_payload(payload);
    if !optimized_matches_text(analysis, payload) || !address.starts_with(analysis.prefix.as_str())
    {
        return Err(Error::SearchFailed);
    }
    Ok(true)
}

fn bump(
    cancel: &AtomicBool,
    attempts: &AtomicU64,
    overflow: &AtomicBool,
    local: &mut u64,
) -> Result<bool, Error> {
    if cancel.load(Ordering::Acquire) {
        return Ok(false);
    }
    let observed = attempts.load(Ordering::Relaxed).saturating_add(*local);
    if counter_would_overflow(observed) {
        overflow.store(true, Ordering::Release);
        cancel.store(true, Ordering::Release);
        return Ok(false);
    }
    *local += 1;
    if *local >= ATTEMPT_CHUNK {
        attempts.fetch_add(*local, Ordering::Relaxed);
        *local = 0;
    }
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
fn single_worker(
    analysis: &Analysis,
    network: Network,
    kind: AddressKind,
    engine: &KeyEngine,
    cancel: &AtomicBool,
    attempts: &AtomicU64,
    overflow: &AtomicBool,
    tx: &Sender<RawHit>,
    local: &mut u64,
) -> Result<(), Error> {
    loop {
        if cancel.load(Ordering::Acquire) {
            return Ok(());
        }
        let secret = random_scalar()?;
        let public = match engine.public_of(secret.as_slice()) {
            Ok(public) => public,
            Err(Error::InvalidKey) => continue,
            Err(err) => return Err(err),
        };
        let payload = match kind {
            AddressKind::P2pkh => payload_for_hash(network.p2pkh_version(), &public.hash160),
            AddressKind::P2sh => {
                let script = p2pkh_redeem(&public.hash160);
                payload_for_hash(network.p2sh_version(), &hash160(&script))
            }
            AddressKind::Multisig => return Err(Error::SearchFailed),
        };
        if !bump(cancel, attempts, overflow, local)? {
            return Ok(());
        }
        if text_match(analysis, &payload)? {
            let _ = tx.send(RawHit::One(secret));
            cancel.store(true, Ordering::Release);
            return Ok(());
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn multi_worker(
    analysis: &Analysis,
    network: Network,
    engine: &KeyEngine,
    threshold: u8,
    participants: u8,
    cancel: &AtomicBool,
    attempts: &AtomicU64,
    overflow: &AtomicBool,
    tx: &Sender<RawHit>,
    local: &mut u64,
) -> Result<(), Error> {
    let mut fixed_keys = Vec::new();
    let mut fixed_pubs = Vec::new();
    for _ in 1..participants {
        let key = random_scalar()?;
        let public = engine.public_of(key.as_slice())?;
        fixed_pubs.push(public.key);
        fixed_keys.push(key);
    }
    loop {
        if cancel.load(Ordering::Acquire) {
            return Ok(());
        }
        let varying = random_scalar()?;
        let public = match engine.public_of(varying.as_slice()) {
            Ok(public) => public,
            Err(Error::InvalidKey) => continue,
            Err(err) => return Err(err),
        };
        let mut pubs = fixed_pubs.clone();
        pubs.push(public.key);
        let redeem = match multisig_redeem(threshold, &pubs) {
            Ok(script) => script,
            Err(Error::Policy) => continue,
            Err(err) => return Err(err),
        };
        let payload = payload_for_hash(network.p2sh_version(), &hash160(&redeem));
        if !bump(cancel, attempts, overflow, local)? {
            return Ok(());
        }
        if text_match(analysis, &payload)? {
            let mut all = Zeroizing::new(Vec::with_capacity(fixed_keys.len() + 1));
            for key in &fixed_keys {
                let bytes: &[u8; 32] = key;
                all.push(*bytes);
            }
            let varying_bytes: &[u8; 32] = &varying;
            all.push(*varying_bytes);
            let _ = tx.send(RawHit::Many(all));
            cancel.store(true, Ordering::Release);
            return Ok(());
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn hd_worker(
    analysis: &Analysis,
    network: Network,
    engine: &KeyEngine,
    parent: HdNode,
    worker_id: usize,
    threads: usize,
    index_limit: u32,
    cancel: &AtomicBool,
    attempts: &AtomicU64,
    overflow: &AtomicBool,
    tx: &Sender<RawHit>,
    local: &mut u64,
) -> Result<(), Error> {
    let mut index = u32::try_from(worker_id).map_err(|_| Error::Index)?;
    let step = u32::try_from(threads).map_err(|_| Error::Index)?;
    if step == 0 || index_limit == 0 || index_limit > HARDENED {
        return Err(Error::Index);
    }
    loop {
        if cancel.load(Ordering::Acquire) || index >= index_limit {
            return Ok(());
        }
        match derive_index(engine, &parent, index) {
            Ok(child) => {
                let public = engine.public_of(child.key_bytes())?;
                let payload = payload_for_hash(network.p2pkh_version(), &public.hash160);
                if !bump(cancel, attempts, overflow, local)? {
                    return Ok(());
                }
                if text_match(analysis, &payload)? {
                    let _ = tx.send(RawHit::Index(index));
                    cancel.store(true, Ordering::Release);
                    return Ok(());
                }
            }
            Err(Error::InvalidKey) => {}
            Err(err) => return Err(err),
        }
        index = match index.checked_add(step) {
            Some(next) if next < index_limit => next,
            _ => return Ok(()),
        };
    }
}
