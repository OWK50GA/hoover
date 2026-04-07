# hoover

A watch-only Bitcoin CLI tool that identifies dust attack UTXOs and sweeps them away — without revealing address linkage.

Hoover never holds private keys. It produces PSBTs for an external signer, then broadcasts the finalized transactions via Bitcoin Core RPC. Persistent state is stored locally in a `redb` database.

---

## What is a dust attack?

A dust attack is a privacy attack where an adversary sends tiny amounts of bitcoin (dust) to addresses in your wallet. The goal is to get you to spend that dust alongside your other UTXOs, which reveals that those addresses belong to the same wallet — breaking your privacy.

Hoover detects these UTXOs and sweeps them to `OP_RETURN` outputs, neutralizing the attack without linking your addresses.

---

## Requirements

- Rust 1.75+
- Bitcoin Core (with RPC enabled)

---

## Installation

```bash
git clone https://github.com/yourname/hoover
cd hoover
cargo build --release
```

The binary will be at `target/release/hoover`.

---

## Quick start

**1. Start Bitcoin Core** with RPC enabled. Add to `bitcoin.conf`:

```
rpcuser=youruser
rpcpassword=yourpassword
```

**2. Register a descriptor**

```bash
hoover --chain mainnet \
       --rpc-url http://127.0.0.1:8332 \
       --rpc-user youruser \
       --rpc-pass yourpassword \
       add --descriptor "wpkh(xpub.../0/*)" \
           --change-descriptor "wpkh(xpub.../1/*)" \
           --start-height 800000
```

**3. Scan for dust**

```bash
hoover list
```

**4. Create sweep PSBTs**

```bash
hoover clean
```

This writes one `.psbt` file per address group to the current directory.

**5. Sign the PSBTs** with your hardware wallet or signing tool.

**6. Broadcast**

```bash
# Broadcast a specific file
hoover broadcast --psbt <fingerprint>-0.psbt

# Or broadcast all .psbt files at once
hoover broadcast
```

**7. Check status**

```bash
hoover status <txid>
```

---

## Commands

| Command | Description |
|---|---|
| `add` | Register a descriptor to watch |
| `list` | Scan for dust UTXOs across all registered descriptors |
| `clean` | Build sweep PSBTs (one per address group) |
| `broadcast` | Finalize and broadcast signed PSBTs |
| `status` | Check confirmation status of a transaction |

### Global flags

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--chain` | `HOOVER_CHAIN` | `main` | Network: `main`, `testnet`, `signet`, `regtest` |
| `--rpc-url` | `HOOVER_RPC_URL` | `http://127.0.0.1:8332` | Bitcoin Core RPC URL |
| `--rpc-user` | `HOOVER_RPC_USER` | — | RPC username |
| `--rpc-pass` | `HOOVER_RPC_PASS` | — | RPC password |
| `--datadir` | `HOOVER_DATADIR` | `~/.hoover` | Directory for the database |
| `--amount` | `HOOVER_AMOUNT` | `546` | Dust threshold in satoshis |
| `--fingerprint` | `HOOVER_FINGERPRINT` | — | Filter by descriptor fingerprint |

---

## Privacy model

Hoover is designed around one principle: **never link addresses**.

- Each sweep transaction contains inputs from exactly one address — no cross-address consolidation
- Outputs go to `OP_RETURN` (unspendable), eliminating change address creation
- Transactions signal RBF so fees can be bumped if they get stuck
- The tool is watch-only — private keys never touch it

---

## Dust detection policies

Hoover uses a scoring system to classify UTXOs. Each UTXO is evaluated against a set of heuristics, each contributing a weighted signal. UTXOs above the suspicion threshold are flagged.

Current heuristics:

| Heuristic | Signal |
|---|---|
| Dust on change address | Very high — change addresses are never shared |
| Value below relay floor | High — matches the minimum spendable threshold exactly |
| Economic dust | Medium — costs more to spend than the UTXO is worth |

More heuristics are in development (spray pattern detection, sender address reuse, fee anomaly detection).

---

## Development

```bash
# Run all tests
cargo test

# Unit tests only (no bitcoind required)
cargo test --lib

# Integration tests (requires bitcoind on PATH)
cargo test --test descriptor_to_utxos
```

---

## License

MIT
