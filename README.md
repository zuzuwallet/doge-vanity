# doge-vanity

Offline generator for Dogecoin addresses whose Base58Check text starts with a chosen prefix.

`DZuZu` cannot be a Dogecoin mainnet P2PKH address. The mainnet P2PKH version byte `0x1e` forces every 34-character address into this closed interval:

```text
D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM
DUUhXNEw1bNAMSKgm1Kt2tSPWdzF3G5pog
```

`Z` is outside the second-character window. `doge-vanity analyze --type p2pkh DZuZu` prints `Reachable: NO` and exits 0. `generate` prints that report and exits 1. It does not search, and it does not write a wallet. It does not substitute another prefix.

A reachable exact-case illustration that still contains `ZuZu` is `DAZuZu`. The analyzer in this tree gives it an expected attempt count of 264,104,224. That count is the integer model below. It is not `58^4` and it is not a promise of wall-clock time.

Base58 is case-sensitive. `DZuZu`, `Dzuzu`, `DZUZU`, and `DZuZU` are different strings. This program keeps the case you type.

This is Dogecoin. It does not emit Bitcoin SegWit (`bc1q`), Bitcoin Taproot (`bc1p`), P2WPKH, P2WSH, or BIP86. Dogecoin Core 1.14.9 sets the SegWit deployment timeout to 0, and it has no Taproot deployment. Libdogecoin’s bech32 human-readable part `doge` is planned for a later release and is not a live address family here.

A recognizable address such as `DAZuZu...` is a public identifier. Vanity does not improve privacy. It can make a transaction history easier to associate with a person, and it can make repeated payments easier to recognize. Do not describe it as an anonymity feature.

Never paste a generated WIF, raw private key, mnemonic, seed, xprv, encryption passphrase, or wallet file into a website, an AI or chat system, an issue tracker, a shell command, or an online verification service. The terminal scrollback, shell history, and process list are copies of a secret. Only the public address may be shared.

Passing `cargo test` does not make a wallet appropriate for significant funds. Before an address from this program receives meaningful DOGE, require all of the following on the machine that will hold the key:

1. Cryptographic known-answer tests pass.
2. Dogecoin network-parameter tests pass.
3. A full secret-to-address reconstruction passes.
4. An independent implementation agrees with the address.
5. An encrypted backup of the secret exists and can be opened.
6. A disposable restoration test passes.
7. A disposable receive-and-spend test passes on a test network.

This tree completed the in-process forms of items 1–4 and an in-process restoration of items 5–6. It did not run Dogecoin Core or libdogecoin, it did not broadcast a transaction, and it did not fund an address. The section “What this tree did not verify” lists that explicitly.

## P2PKH derivation

The default engine is mainnet P2PKH with a compressed public key.

1. Read 32 bytes from the operating-system CSPRNG (`getrandom`), once per candidate.
2. Accept those bytes only when they are a secp256k1 scalar in `1..=n-1`. Zero and values at or above the curve order are discarded and are not counted as attempts. The bytes are not reduced modulo `n`.
3. Derive the compressed SEC1 public key with libsecp256k1 (`0x02` or `0x03` plus the 32-byte x coordinate).
4. Compute HASH160 as RIPEMD-160(SHA-256(compressed public key)).
5. Build the 25-byte payload `version || HASH160 || checksum`. The checksum is the first 4 bytes of SHA-256(SHA-256(version || hash)).
6. Test that 25-byte integer against the inclusive prefix interval. Base58 text is built only for a hit, and the text must still start with the prefix.

Curve order `n` is `0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`.

The grinder does not walk `k, k+1, k+2`. It does not derive a key from `DZuZu`, `DOGE`, a password, a timestamp, a dictionary, or a worker id. HD index mode, described below, is the only mode that uses a counter, and that counter is a BIP44 child index under one CSPRNG mnemonic.

There is no `--uncompressed` mode. An uncompressed public key (`0x04||x||y`) hashes to a different address. The self-test locks that mismatch: the compressed generator key must not confirm against the uncompressed address.

## Network parameters

Checked against Dogecoin Core 1.14.9 `src/chainparams.cpp` at commit `e0a1c157791544e818c901bd9341896965afbf9d` (release, 2024-12-01) and libdogecoin `src/chainparams.c` at commit `b4a79c34fbd95090494b0aa0c006d1b8f0de8e15` (main, v0.1.4, 2025-04-28). Core master `47a303a449999314abcf83bd1fc7e77dd4540fcd` (2026-09-10) uses the same Base58 versions. It is not a release tag. SLIP-44 assigns Dogecoin coin type 3. Coin type 1 is the testnet type for all coins.

| Parameter | Mainnet | Testnet | Bitcoin mainnet, rejected by tests |
| --- | --- | --- | --- |
| P2PKH version | `0x1e` | `0x71` | `0x00` |
| P2SH version | `0x16` | `0xc4` | `0x05` |
| WIF version | `0x9e` | `0xf1` | `0x80` |
| BIP32 public | `0x02facafd` (`dgub`) | `0x043587cf` | — |
| BIP32 private | `0x02fac398` (`dgpv`) | `0x04358394` | — |
| SLIP-44 coin type | 3 | 1 | 0 |

Litecoin mainnet P2PKH `0x30` and WIF `0xb0` are also rejected by the constant test. Regtest is omitted: its public-key version `0x6f` and secret version `0xef` are the Bitcoin testnet bytes, and this crate will not emit them.

Mainnet P2PKH and P2SH addresses are 34 characters. Testnet P2SH addresses are 35 characters. The analyzer computes the length from the two endpoint encodings and fails closed if those lengths differ.

Testnet P2SH version `0xc4` is also Bitcoin testnet P2SH. `inspect` says so. A leading `D` or `A` is not proof of type. `inspect` Base58-decodes the text, checks the 4-byte checksum, and then reads the version byte. Invalid text still exits 0 and prints `Valid: NO`.

`--network` defaults to `mainnet`. A testnet result is labeled `Testnet`.

## Why `DZuZu` is unreachable

The payload is 25 bytes: 1 version byte, 20 hash bytes, and 4 checksum bytes. Every payload with version `0x1e` is an integer in `[0x1e << 192, 0x1e << 192 + 2^192)`. Base58-encoding those two endpoints produces the addresses above. They are the mathematical ends of the version range. They are not funded addresses, and they are not targets this program searched for.

The only character shared by that whole interval is `D`. The next character is fully inside `6789ABCDEFGHJKLMNPQRST`, on an edge for `5` and `U`, and absent for `1234`, `VWXYZ`, and every lowercase letter. `Z` is absent, so `DZuZu`, `Dzuzu`, `DWow`, `Doge`, and `D123` are impossible. `DOGE` fails earlier: `O` is not in the Base58 alphabet (`0`, `O`, `I`, and `l` are excluded). Alphabet checks run before the range check.

The same `DZuZu` string is also impossible for testnet P2PKH. Testnet P2PKH endpoints are `nUCAGGgZEPN1QyknmQe1oAku817bLTv8jy` and `nsXmFNyqwZptEQtsnpyLHJ2gkWNY3hVy4J`. The version-implied character is `n`.

This is the report printed by this tree:

```text
Dogecoin Vanity Analyzer

Network:
Mainnet

Address type:
P2PKH

Encoding:
Base58Check

Requested:
DZuZu

Fixed network constraints:
Version byte: 0x1e
Payload bytes: 25
Address characters: 34
Lowest payload encoding: D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM
Highest payload encoding: DUUhXNEw1bNAMSKgm1Kt2tSPWdzF3G5pog
Endpoints are the mathematical version range, not funded addresses.
Version-implied leading text: D
Next character fully inside: 6789ABCDEFGHJKLMNPQRST
Next character on an edge: 5U
Next character absent: 1234VWXYZabcdefghijkmnopqrstuvwxyz

Vanity portion:
ZuZu

Classification:
impossible

Reachable:
NO

Probability per candidate:
0

Unrounded expected attempts:
n/a

Expected attempts:
n/a

50% probability:
n/a

90% probability:
n/a

99% probability:
n/a

Rejected per-character approximation: 58^4 = 11,316,496

Model:
The overlap of the prefix interval with the version-byte range, divided into 2^192.
This is not 58^n, and it is not a promise of wall-clock time.
```

`generate` then exits with `invalid prefix: no mainnet P2PKH address has this prefix`.

## Probability

For a prefix that intersects the version range, the program takes the inclusive 25-byte integer span of every complete address that would start with that text, intersects it with the version interval, and divides the overlap by `2^192`.

- Fully reachable: the prefix span sits inside the version interval.
- Partially reachable: the spans overlap and neither contains the other.
- Version-implied: the version interval sits inside the prefix span. `D` alone is this class. Probability is 1. Expected attempts, and the 50%, 90%, and 99% counts, are all 1. The vanity portion is `(none)`.
- Impossible: the intersection is empty.

Expected attempts are `round(2^192 / overlap)` through an integer division that rounds half away from zero. The unrounded quotient is printed to six decimal places. The 50% count is `round(expected * ln 2)` when the expected count is greater than 1, and the expected count otherwise. The 90% and 99% counts use `ceil(ln(1-q) / ln(1-p))` in `f64`. `2^192` is exact in `f64`. This is a model of the encoding. It is not a proof that HASH160 outputs are uniform.

`58^n` is printed only as the approximation the model rejects. Four free Base58 characters would be `58^4 = 11,316,496`. The version byte does not leave four free characters after `D`.

Counts below are what `analyze` printed for this tree. Tests lock the integers.

| Prefix | Class | Expected | 50% | 90% | 99% | Unrounded |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| `D` | version-implied | 1 | 1 | 1 | 1 | 1.000000 |
| `DA` | fully reachable | 23 | 16 | 53 | 106 | 23.337986 |
| `D5` | partially reachable | 27 | 19 | 62 | 123 | 27.123870 |
| `DU` | partially reachable | 49 | 34 | 112 | 223 | 48.868866 |
| `DAZ` | fully reachable | 1,354 | 939 | 3,116 | 6,232 | 1353.603183 |
| `DAZu` | fully reachable | 78,509 | 54,418 | 180,773 | 361,545 | 78508.984631 |
| `DAZuZ` | fully reachable | 4,553,521 | 3,156,260 | 10,484,869 | 20,969,738 | 4553521.108587 |
| `DDoge`, `DSuch` | fully reachable | 4,553,521 | 3,156,260 | 10,484,869 | 20,969,738 | 4553521.108587 |
| `DAZuZu` | fully reachable | 264,104,224 | 183,063,098 | 608,122,446 | 1,216,244,892 | 264104224.298071 |
| `DAZuZuZ` | fully reachable | 15,318,045,009 | 10,617,659,710 | 35,271,121,564 | 70,542,243,128 | 15318045009.288103 |

`D5ZuZu` is fully reachable. `DUZuZu` is impossible: `U` is only an edge, and `ZuZu` after it leaves the version interval. `D9ZuZu` and `DTZuZu` share the `DAZuZu` class in the same model; run `analyze` on the exact string you intend to search.

The vanity portion of `DAZuZu` is `AZuZu`, because `D` is version-implied. The rejected approximation for that prefix is `58^5 = 656,356,768`, not `58^4`.

`DAZuZu` does not ask for a `SEARCH` confirmation. The threshold is 1,000,000,000 expected attempts. `DAZuZuZ` is above it, and independent `generate` asks you to type `SEARCH` before workers start. A prefix whose estimate does not fit in a `u64` minus 1,048,576 is rejected. The in-search counter stops 1,048,576 attempts before a `u64` would wrap. A full 34-character string is rejected. It is not searched.

HD index mode does not have an unlimited attempt counter. One mnemonic has receive indexes `0` through `2,147,483,647` only (`2^31` candidates). The chance of at least one match in that window is `1 - (1 - overlap / 2^192)^(2^31)`. From this tree's overlap, that chance is 99.97% for `DAZuZu` and 13.08% for `DAZuZuZ`. The 50%, 90%, and 99% counts for `DAZuZu` all fit inside the window. The same three counts for `DAZuZuZ` do not, so `generate --mode hd-index` prints `not reachable within this mnemonic` and asks you to type `EXHAUST` before `SEARCH`. The search is still allowed. Exhausting the index range writes no wallet. `analyze` and `collection` print only the unlimited counts. They do not print this HD window, including for P2SH and multisig, because those commands have no HD search.

`analyze` of an impossible but alphabet-valid prefix exits 0. `generate` of that prefix exits 1 before self-test, so a rejection does not depend on the vector suite.

## `DAZuZu` report

```text
Dogecoin Vanity Analyzer

Network:
Mainnet

Address type:
P2PKH

Encoding:
Base58Check

Requested:
DAZuZu

Fixed network constraints:
Version byte: 0x1e
Payload bytes: 25
Address characters: 34
Lowest payload encoding: D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM
Highest payload encoding: DUUhXNEw1bNAMSKgm1Kt2tSPWdzF3G5pog
Endpoints are the mathematical version range, not funded addresses.
Version-implied leading text: D
Next character fully inside: 6789ABCDEFGHJKLMNPQRST
Next character on an edge: 5U
Next character absent: 1234VWXYZabcdefghijkmnopqrstuvwxyz

Vanity portion:
AZuZu

Classification:
fully reachable

Reachable:
YES

Probability per candidate:
1 / 264,104,224

Unrounded expected attempts:
264104224.298071

Expected attempts:
264,104,224

50% probability:
183,063,098

90% probability:
608,122,446

99% probability:
1,216,244,892

Rejected per-character approximation: 58^5 = 656,356,768

Model:
The overlap of the prefix interval with the version-byte range, divided into 2^192.
This is not 58^n, and it is not a promise of wall-clock time.
```

## P2SH

P2SH is a separate engine. The redeem script is the standard compressed P2PKH script:

```text
OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
```

That is 25 bytes: `76 a9 14 || HASH160(compressed public key) || 88 ac`. The address is Dogecoin P2SH version `0x16`, then HASH160 of that script, then the Base58Check checksum. The program does not append a nonce, `OP_DROP`, or any other byte to steer the prefix.

Mainnet P2SH endpoints, again mathematical and unfunded:

```text
9rSGfPZLcyCGzY4uYEL1fkzJr6fke9qKxb
AFmseVrdL9f9oyCzZefL9tG6UbvhMPRAGv
```

No first character sits fully inside that interval. `9` and `A` are the edge characters. `AZuZu` and `9ZuZu` are impossible. Do not assume `AZuZu` from the observation that many Dogecoin P2SH addresses begin with `A`.

`A1ZuZu` is fully reachable. Its expected count is the same 264,104,224 as `DAZuZu`. `A1` is fully reachable with expected count 23. `A` alone is partially reachable with expected count 2 (unrounded 1.579701; 50% is 1; 90% is 3; 99% is 5). `9r` is partially reachable with expected count 41. `AF` is partially reachable with expected count 30. `9sZuZu` matches the `A1ZuZu` expected count. Run `analyze --type p2sh` on the exact prefix before `generate`.

Testnet P2SH endpoints are 35 characters: `2MsFDzHRUAMpjHxKyoEHU3aMCMsVtLuLGzb` through `2NGapyPiksYHc7PU4pecnXhcyzNkq48v7Jv`. The version-implied character is `2`.

The wallet stores the redeem script. The address alone does not recover the script.

## Self-contained multisig vanity P2SH

`--type multisig` builds a valid P2SH multisig script. It is self-contained: every participant private key is generated here and stored in the same wallet file under one passphrase. Someone who opens that file gets all `n` keys, so the `m-of-n` threshold does not isolate keys across machines. This tool does not accept an outside participant's public key and does not cosign. The command name stays `multisig`.

The policy is chosen before the search and is not changed to chase a prefix. The address type uses the same P2SH version byte and the same analyzer.

The default, used when `--threshold` and `--participants` are omitted, is 2-of-3. Any `1 <= m <= n <= 15` is accepted, which includes 2-of-2, 2-of-3, and 3-of-5. Fifteen is Dogecoin Core `MAX_P2SH_SIGOPS`. Core 1.14.9 `AreInputsStandard` does not recursively require the redeem script to pass `IsStandard`. It rejects a P2SH input whose sigop count exceeds 15. Bare multisig standardness is a different rule (n in 1..=3). This crate never emits a bare multisig output.

Each attempt draws one new participant key from the CSPRNG. The other participant keys are drawn once per worker and held. Keys are compressed. They are sorted by raw bytes (BIP67) before the script is built:

```text
OP_m <33-byte keys> OP_n OP_CHECKMULTISIG
```

A duplicate key is skipped and is not a failed search. The threshold and the participant count stay fixed. The wallet stores every participant private key, the threshold, the participant count, and the exact redeem script. `export` prints one WIF per participant, in sorted public-key order, plus the redeem script. The P2SH address alone is not a recovery package. The generate banner and the success text repeat that every key is in this wallet.

`--threshold` and `--participants` are errors on `p2pkh` and `p2sh`.

## HD index mode

`--mode hd-index` is P2PKH only. It draws 256 bits from the OS CSPRNG with no secp256k1 range check, encodes a 24-word BIP39 mnemonic, and derives one account with the BIP32 HMAC key `Bitcoin seed`. Direct private keys still reject `0` and values at or above the curve order. Mnemonic entropy does not. The BIP39 passphrase is empty. That empty string is the interoperability default. It is not a secret you pass on the command line.

Mainnet receive path:

```text
m/44'/3'/account'/0/index
```

Testnet uses coin type 1: `m/44'/1'/account'/0/index`. Account defaults to 0 and must be below `2^31`. Change is fixed at 0. The index runs through `0 .. 2^31-1` inclusive. Workers stride that range. The hardened bit is never set on the index, and the search never walks into change `1`. Overflow stops with `derivation index range exhausted`.

The difficulty screen for this mode prints the fresh-candidate expected count and then the finite window: the index range, the maximum probability of a match in this mnemonic, and `not reachable within this mnemonic` for any 50%, 90%, or 99% count above `2,147,483,648` attempts. When that 50% count does not fit, the program asks for `EXHAUST` before it asks for `SEARCH`.

The mnemonic entropy stays in the parent thread. Workers receive a copy of the external-chain private key and chain code. A winning worker sends only the index. The parent derives that child again from the entropy. An invalid child (`IL >= n` or a zero sum) is skipped and is not counted.

A normal wallet gap limit of 20 will not find an index near `1.8e8`, and it will not find index 100. The in-process test derives index 100 and checks that a gap-20 scan misses it. The wallet stores the derivation standard as the full path, the account, the change branch (0), and the index. Restoring the mnemonic in a wallet that only scans the gap does not rediscover the address. Dogecoin Core 1.14 has no BIP39 import. `export` prints the child WIF so `importprivkey` can spend that one address. The program does not serialize an xprv.

There is one BIP32 implementation. Published vectors lock the path math. The independent address check re-derives the child address from the child scalar. It does not reimplement CKD with a second HD library.

`--account` is an error unless the mode is `hd-index`.

## Commands

```bash
doge-vanity self-test
doge-vanity analyze --type p2pkh DZuZu
doge-vanity analyze --type p2pkh DAZuZu
doge-vanity analyze --type p2sh AZuZu
doge-vanity analyze --type p2sh A1ZuZu
doge-vanity benchmark --type p2pkh
doge-vanity generate --type p2pkh DAZuZu
doge-vanity generate --type p2pkh DAZuZu --threads 16
doge-vanity generate --type p2pkh --mode hd-index DAZuZu
doge-vanity generate --type p2sh A1ZuZu
doge-vanity generate --type multisig --threshold 2 --participants 3 A1ZuZu
doge-vanity inspect DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE
doge-vanity verify DAZuZu-wallet.json
doge-vanity export DAZuZu-wallet.json
doge-vanity collection ZuZu
```

`--network mainnet` is the default. `--network testnet` is the other accepted value. `--type` is `p2pkh` (default), `p2sh`, or `multisig`. `--mode` is `independent` (default) or `hd-index`.

`generate` and `benchmark` run self-test before work. A vector failure aborts the process. `analyze`, `inspect`, and `collection` do not run self-test. `generate` of an unreachable prefix fails before self-test.

`generate` requires a terminal. Threads default to `available_parallelism`, clamped to 1..=256. `--threads 0` and values above 256 are rejected. The default output path is `{prefix}-wallet.json`. An existing file is refused before any key stretching. There is no overwrite flag. The parent directory must already exist. If that directory is writable by group or others, `generate` warns once and continues. Create it with `mkdir -m 700`. Mode `0600` on the wallet does not stop someone who can write the directory from replacing the file later.

`benchmark` measures the miss path for about one second and then prints probabilistic ranges for the reachable targets `DA`, `DAZ`, `DAZu`, and `DAZuZ` (P2PKH) or `A1`, `A1Z`, `A1Zu`, and `A1ZuZ` (P2SH and multisig). Testnet uses `na` / `naZ` / `naZu` / `naZuZ` and `2N1` / `2N1Z` / `2N1Zu` / `2N1ZuZ`, and only when the analyzer calls them reachable. `DZuZu` is not a benchmark target. One measured rate is not a completion promise, and multiplying it by 16 is not a promise either.

`collection ZuZu` prints the analyzer reports for `DZuZu` and `AZuZu`. Both are unreachable. It writes no wallet and it does not silently switch to `DAZuZu` or `A1ZuZu`. P2PKH remains the primary receiving address when you explicitly generate a reachable prefix.

Ctrl-C sets an atomic flag. It does not call `process::exit`. Workers leave the candidate loop on that flag. A hit that races with Ctrl-C is discarded. If Ctrl-C arrives while the passphrase prompt is up, echo is restored and no address or secret is printed.

`generate` prints `Match found.` before the passphrase prompt. It prints `FOUND` and the public address only after `write_encrypted_wallet` returns. On a write error it prints `Wallet was not saved successfully.` and does not print the address. A passphrase failure prints `Wallet was not saved.` The passphrase and the key material are dropped before the public lines. The success text includes `Recovery test: PENDING` because this binary does not import the wallet into Dogecoin Core.

## Wallet file

The file is versioned JSON with `deny_unknown_fields`. Public fields are the format version, network, address type, mode, public address, compression flag, derivation path, threshold, participant count, redeem-script hex, KDF name and parameters, salt, cipher name, nonce, and ciphertext. The ciphertext holds the secret.

Key stretching is Argon2id, RFC 9106 section 4 second option: 64 MiB (`memory_kib` 65536), `t=3`, `p=4`, version `0x13`, a 16-byte salt, and a 32-byte output. The cipher is ChaCha20-Poly1305 with a 12-byte random nonce. Associated data binds the format, network, address type, mode, compression, threshold, participant count, redeem script, derivation path, and address. A test-only KDF (32 KiB, `t=1`, `p=1`) is rejected by the public opener.

The file is created with mode `0600`, `O_CREAT|O_EXCL`, and `O_NOFOLLOW` on read. A same-directory temporary file is synced, hard-linked into place only if the destination is still absent, and the parent directory is synced. Set `umask 077` in the shell that runs `generate`.

There is no `--password` flag. The passphrase is read with echo disabled. A new wallet rejects a passphrase shorter than 12 Unicode scalar values or longer than 1024 bytes. The value is not trimmed. `verify` and `export` still open a shorter passphrase so an older file is not stranded. The 12-scalar check only stops accidents. It is not a measure of guessing resistance.

`export` is the only command that prints secret material. It requires a terminal on both stdin and stdout, asks you to type `EXPORT`, and checks the interrupt flag again immediately before the secret line. Independent P2PKH prints a WIF. P2SH also prints the redeem script. Multisig prints every participant WIF and the redeem script. HD mode prints the mnemonic, the path, and the child WIF. It does not print an xprv.

## Memory

Candidate scalars, WIFs, mnemonics, seeds, and passphrases sit in `zeroize` buffers where this crate controls the allocation. `secp256k1::SecretKey` is `Copy`. The search path borrows one `SecretKey` and calls `non_secure_erase` on drop, which writes `[1u8; 32]` rather than zeros. A second owned `SecretKey` would copy the scalar and leave the first value in place, so the code does not do that. `add_tweak` takes `self` by value and therefore copies; the parent and the returned child are erased after the child bytes are taken.

`zeroize` does not cover every copy. Swap, core dumps, allocator leftovers, register spills, debug logs, and a compromised kernel or root account can retain secrets. Disable swap or encrypt it, and restrict core dumps (`ulimit -c 0`, or the systemd equivalent), on a machine that will hold a funded key. Those steps are outside this program.

## Independent check

Every accepted hit is reconstructed on the CPU and checked by a second stack before a wallet is written:

- `k256` 0.13 derives the compressed point.
- `bitcoin_hashes` 0.16 computes HASH160 and the double-SHA256 checksum.
- `bs58` 0.5 encodes the 25 bytes. Its check feature is off.

That stack does not call this crate’s Base58Check, `sha2`, `ripemd`, or libsecp256k1. Dogecoin Core and libdogecoin are not linked, and they were not executed in this environment. The CLI line `Independent Dogecoin verification: PASS` means the second Rust stack agreed. It does not mean `dogecoin-cli` was run.

The offline signature check signs one synthetic legacy `SIGHASH_ALL` preimage with libsecp256k1 and verifies it with `k256`’s prehash verifier. It is not a transaction on a network, and it does not prove that a wallet can spend a UTXO.

## Known answers

Self-test compares these public values. A failure aborts before a reachable search. The WIF of scalar 1 is compared between the two stacks inside the test and is not printed here. The published all-ones BIP39 phrase is checked in the test and is not reprinted here.

| Check | Value |
| --- | --- |
| SHA-256 of the empty string | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| RIPEMD-160 of `abc` | `8eb208f7e05d987a9b044a8e98c6b087f15a0bfc` |
| Private key 1, compressed | `0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798` |
| HASH160 of that point | `751e76e8199196d454941c45d1b3a323f1433bd6` |
| Private key 2, compressed | `02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5` |
| Dogecoin mainnet P2PKH of key 1 | `DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE` |
| Uncompressed generator address | `DJRU7MLhcPwCTNRZ4e8gJzDebtG1H5M7pc` |
| Bitcoin P2PKH of the same key | `1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH` |
| Litecoin P2PKH of the same key (version `0x30`) | `LVuDpNCSSj6pQ7t9Pv6d6sUkLKoqDEVUnJ` |
| Dogecoin testnet P2PKH of the same key | `nesRpRaAbTDmZHwmzBkLd2AtF7Z9L9z5S2` |
| P2SH of that key’s standard redeem script | `ABAkrai6zU5KXkcbrBdtSo3Yee2saibFuM` |
| Testnet P2SH of the same script | `2NByiBUaEXrhmqAsg7BbLpcQSAQs1EDwt5w` |
| BIP32 vector 1 master chain code | `873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508` |
| Libdogecoin example account `dgub` | `dgub8rUhDtD3YFGZTUphBfpBbzvFxSMKQXYLzg87Me2ta78r2SdVLmypBUkkxrrn9RTnchsyiJSkHZyLWxD13ibBiXtuFWktBoDaGaZjQUBLNLs` |
| Published all-ones entropy at `m/44'/3'/0'/0/0` | `DTdKu8YgcxoXyjFCDtCeKimaZzsK27rcwT` |

The four mainnet-style address strings differ. Compressed Dogecoin WIF of a normal key starts with `Q`. An uncompressed WIF starts with `6` and is rejected by the decoder. The test builds that uncompressed form and requires the rejection. It does not teach the string as a wallet.

Property tests compare the integer interval with `full_address.starts_with(prefix)` for random keys and for the edge prefixes `D5` and `DU`. A hit whose interval and text disagree aborts the search.

## Matcher and threads

The reference match encodes Base58Check and calls `starts_with`. The search match compares the 25-byte payload with the inclusive prefix interval, then encodes only a hit and checks `starts_with` again. Checksum bytes are inside the 25-byte value, so they are not skipped. A winner is reconstructed and passed through the independent stack before it is saved.

`--threads N` gives each worker its own CSPRNG draws and one libsecp256k1 context. The context is blinded once, from 32 `getrandom` bytes, through `seeded_randomize`. The `rand` feature of `secp256k1` stays off. There is no per-candidate reseed and no timer reseed. Worker ids are not secret material. A worker panic or an RNG failure cancels the search, discards other workers’ hits, and writes no wallet. Attempts are aggregated. Progress prints about once a second: attempts, candidates per second, and elapsed time.

GPU search is not implemented. A later GPU candidate would still have to be reconstructed on the CPU, hashed on the CPU, encoded on the CPU, and checked by the independent stack before it could be accepted.

## Recovery tests in this tree

These tests use no funds and no node.

- Independent P2PKH: a wallet written with the test KDF reopens, and the independent stack reproduces the address from the stored scalar.
- HD: a wallet for index 100 reopens to the same address. A gap-20 scan of that chain does not contain index 100.
- Multisig: the stored keys rebuild the same redeem script and the same P2SH address on the independent stack.
- The PTY test sends Ctrl-C at the passphrase prompt for a short reachable prefix (`DA`, one thread). Echo is restored, the output must not contain an address line or a WIF line, and no wallet file is created.

A live `importprivkey` in Dogecoin Core, and a receive-and-spend on testnet, were not run. Do those with a disposable key before you send meaningful DOGE. `dogecoin-cli`, `dogecoind`, and `libdogecoin-config` were not present here, and they were not installed.

## Fedora: build online, then disconnect

On a normal Fedora machine, install a C compiler and Rust while the machine can reach the network. `secp256k1` compiles C code through `cc`. `python3` is required for the PTY test.

```bash
sudo dnf install gcc python3
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup component add rustfmt clippy
cargo install cargo-audit cargo-deny
```

The checks recorded below used rustc 1.99.0 and cargo 1.99.0. This environment did not run `sudo dnf`. It used a user-local GCC. A GCC configured with `--prefix=/usr` and then unpacked somewhere else does not search its own `usr/include` unless `C_INCLUDE_PATH` is set. That is an environment workaround, not the normal Fedora install:

```bash
source "$HOME/.cargo/env"
export PATH="/home/code/.local/gccroot/usr/bin:$PATH"
export CC=/home/code/.local/gccroot/usr/bin/gcc
export AR=/home/code/.local/gccroot/usr/bin/ar
export C_INCLUDE_PATH=/home/code/.local/gccroot/usr/include
export LIBRARY_PATH=/home/code/.local/gccroot/usr/lib64
```

From this directory, while still online:

```bash
umask 077
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
cargo audit
cargo deny check
cargo build --release
```

`cargo fmt --check` is `cargo fmt --all -- --check`. Read `Cargo.toml` and `Cargo.lock` before you trust the binary. `cargo audit` and `cargo deny` download advisory data. The `doge-vanity` binary does not.

Then disconnect and use only the binary you just built:

```bash
nmcli networking off
./target/release/doge-vanity self-test
./target/release/doge-vanity analyze --type p2pkh DZuZu
./target/release/doge-vanity analyze --type p2pkh DAZuZu
./target/release/doge-vanity benchmark --type p2pkh
./target/release/doge-vanity generate --type p2pkh DAZuZu
./target/release/doge-vanity verify DAZuZu-wallet.json
```

`nmcli networking off` may require privileges. Unplugging the network is the same step. This environment did not run `nmcli networking off` and did not run `unshare -n`. The release binary’s dynamic symbol table was checked with `nm -u` instead. Generation does not open a socket: there is no explorer client, Dogecoin RPC client, Electrum client, HTTP client, or telemetry. `Cargo.toml` has no `reqwest`.

Copy the wallet file to offline storage. Keep the passphrase with the same care as the file. Only after the encrypted secret is backed up, a disposable restore has been rehearsed, and a disposable spend has succeeded, consider funding the address.

## References

- Dogecoin Core 1.14.9, commit `e0a1c157791544e818c901bd9341896965afbf9d`. `src/chainparams.cpp` for the Base58 versions. `src/policy/policy.cpp` for `MAX_P2SH_SIGOPS` (15) and bare-multisig standardness. SegWit `nTimeout` is 0.
- Dogecoin Core master `47a303a449999314abcf83bd1fc7e77dd4540fcd` (2026-09-10). Base58 prefixes match 1.14.9. Not a release tag. Not executed.
- Libdogecoin commit `b4a79c34fbd95090494b0aa0c006d1b8f0de8e15` (2025-04-28, v0.1.4). `src/chainparams.c`. Documented mainnet path `m/44'/3'/0'/0/0`. Not executed. The bech32 HRP is not implemented here.
- SLIP-0044 coin type 3 for Dogecoin, coin type 1 for testnet.
- BIP32, BIP39, and BIP44. The HMAC key remains the BIP32 string `Bitcoin seed`.
- BIP67 compressed-key sort for the multisig redeem script.
- SEC 1 generator and `2G` as the public secp256k1 vectors.
- RFC 9106 Argon2id parameter choice used for the wallet.

## Threat model

Assume the following can go wrong. The tests catch some of them. They do not catch a compromised machine.

- A compromised Fedora install, a malicious Cargo crate, or a compromised Rust toolchain can replace the generator. Read the lockfile and build the binary yourself. `publish = false`. This crate is not on crates.io.
- OS CSPRNG failure. Candidates come from `getrandom`. A failed draw aborts the search and writes no wallet.
- A secp256k1 bug. The search stack and the check stack are different implementations, and both must agree before a file is written. Agreement does not prove both are right about an untested property.
- The wrong network byte, or a Bitcoin or Litecoin constant. Known-answer tests require the Dogecoin, Bitcoin, and Litecoin addresses of one key to differ, and they require the testnet address to differ from mainnet.
- A compressed key stored as an uncompressed WIF, or the reverse. The decoder rejects an uncompressed WIF, and the self-test rejects a compressed key paired with the uncompressed address.
- A HASH160 or Base58Check bug, including a wrong alphabet or a checksum that is not 4 bytes. Empty SHA-256, RIPEMD-160 of `abc`, and the generator address are locked. The checksum is checked again by `bitcoin_hashes` on every winner.
- A wrong HD path, Bitcoin coin type 0, testnet coin type 3, a hardened index, or a change branch of 1. The path is stored in the wallet. A gap-20 scan misses a high index on purpose in the test.
- Loss of a P2SH redeem script, or a multisig policy that was weakened to chase a prefix. The policy is an input. The script is stored. The address is not treated as sufficient.
- An optimized matcher false positive. A hit is re-encoded and must `starts_with` the prefix, and the interval must agree with that text, or the search fails closed.
- A future GPU false positive. GPU search is not in this version. The acceptance rule above would still apply.
- Private-key, mnemonic, or passphrase exposure through a flag, a log, a crash report, shell history, or the terminal scrollback. Secrets are not command-line arguments. `export` is the only printer, and it requires two terminals plus the word `EXPORT`.
- Swap, core dumps, allocator copies, and a hostile root account. See “Memory”.
- Backup loss, or a backup that cannot be decrypted. Rehearse `verify` and `export` on a disposable file before funding.
- Vanity reuse and linkability. A memorable address is easier to correlate across payments. It is not a privacy feature.
- Skipping the independent check, or trusting the first stack twice. Winners go through `k256` and `bitcoin_hashes`. Calling this crate’s address function a second time is not the check.
- Side channels. Scalar timing and cache leaks are out of scope for this version. Context blinding is one `seeded_randomize` per worker, not a side-channel proof.

## Dependencies

Direct dependencies, as resolved for this tree:

| Crate | Version |
| --- | --- |
| `argon2` | 0.5.3 |
| `base64` | 0.22.1 |
| `bip39` | 2.2.2 |
| `bitcoin_hashes` | 0.16.0 |
| `bs58` | 0.5.1 |
| `chacha20poly1305` | 0.10.1 |
| `clap` | 4.6.7 |
| `ctrlc` | 3.5.2 |
| `generic-array` | 0.14.7 |
| `getrandom` | 0.2.17 |
| `hmac` | 0.12.1 |
| `k256` | 0.13.4 |
| `ripemd` | 0.1.3 |
| `rpassword` | 7.5.4 |
| `secp256k1` | 0.30.0 (`secp256k1-sys` 0.10.1, built with `cc` 1.6.0) |
| `serde` / `serde_json` | 1.0.229 / 1.0.151 |
| `sha2` | 0.10.9 |
| `thiserror` | 2.0.21 |
| `zeroize` | 1.9.1 |

`criterion` 0.5.1 is a dev-dependency for the miss-path bench. It is not linked into the release binary.

`secp256k1` is built with `std` and `alloc` only. Its `rand` feature is off. `k256` is built with `arithmetic`, `ecdsa`, and `std`. `bs58` is built with `alloc` only. `bip39` is built with `std` and `zeroize`, and it pulls `bitcoin_hashes` 0.14.101 beside this crate’s 0.16.0. `deny.toml` warns on multiple versions and does not fail the build for that warning.

`Cargo.lock` records `rand` 0.8.8 as an optional dependency of `secp256k1` 0.30.0. `cargo tree -i rand` prints nothing, including for the normal and build edges. Candidate scalars and the context seed come from `getrandom` 0.2.17. `rand_core` 0.6.4 is a separate trait crate. It is in the release graph through `k256`, `argon2`, and `chacha20poly1305`. This program does not draw vanity candidates from it.

The advisory run below is historical (2026-10-08). Run `cargo audit` and `cargo deny check` again on the day you build.

## What this tree did not verify

- Dogecoin Core was not executed. `dogecoin-cli` and `dogecoind` were not installed.
- Libdogecoin was not executed. The `dgub` and the all-ones-entropy address were checked against published vectors inside this crate’s own BIP32 code.
- No multi-million-attempt mainnet search was run, and nothing was funded.
- No transaction was broadcast. The signature fixture is local.
- `nmcli networking off` and `unshare -n` were not run.
- Side channels, swap, core dumps, and a compromised kernel remain outside the tests.
- The difficulty figures are the integer-range model. They are not a uniformity proof and not a schedule.
- The version-range endpoints are not funded addresses.
- One BIP32 implementation is locked by published vectors. A second HD library was not used. The child address is still checked from the child scalar on the independent stack.
- The GitHub repository is the distribution source. This crate is not published to crates.io. `publish = false`.

## Checks in this session

Toolchain: rustc 1.99.0 (`b940084d7`, 2026-09-28), cargo 1.99.0 (`5f94df478`, 2026-08-27). Host compiler: the user-local GCC described above. Date: 2026-10-08.

- `cargo fmt --all -- --check` passed before this public source release.
- `cargo clippy --locked --all-targets --all-features -- -D warnings` passed before this public source release.
- `cargo test --locked --all -- --test-threads=8` passed before this public source release: 34 library tests, 3 binary tests, 12 CLI tests, 1 PTY test, 8 search tests. The PTY test covers `EXHAUST` before `SEARCH` for HD `DAZuZuZ` and does not leave that search running.
- `cargo audit --deny warnings` loaded 1294 advisories and scanned 158 crate dependencies. It exited 0 and printed no vulnerabilities or warnings.
- `cargo deny check advisories bans licenses sources` reported advisories, bans, licenses, and sources ok. Warnings, which do not fail the check: duplicate `bitcoin_hashes` 0.14.101 (via `bip39`) and 0.16.0; duplicate `hex-conservative` 0.2.3 and 0.3.2; duplicate `syn` 2.0.119 and 3.0.6; allowances for BSD-1-Clause and ISC were not encountered.
- `cargo tree -i rand` printed nothing.
- `cargo build --release --locked` finished before this public source release, and `./target/release/doge-vanity self-test` printed `Cryptographic self-tests: PASS`.
- `nm -u` on that release binary did not list `connect`, `getaddrinfo`, or `sendto`.

## License

MIT OR Apache-2.0. See `LICENSE-MIT`, `LICENSE-APACHE`, and `NOTICE`.
