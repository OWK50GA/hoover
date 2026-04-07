use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client, RpcApi};
use bitcoin::{Address, Network};
use clap::Parser;
use hoover::{
    cli::command_parser::{Chain, Cli, Commands},
    network::monitoring::{TxStatus, tx_status},
    psbt::psbt_builder::{build_sweep_psbt, finalize_psbt, read_psbt_file, write_psbt_file},
    redb::storage::Store,
    utxo::{
        context::{build_context, build_tx_cache},
        dust_policies::heuristic::{
                DustHeuristic, aggregate, change_address::ChangeAddressHeuristic, exact_floor::ExactFloorPolicy, multi_address::MultiAddressHeuristic
            },
        utxo_parser::{DustReason, DustUtxo, Utxo},
    },
    wallet_descriptor::wallet_parser::parse_descriptor,
};
use std::path::PathBuf;
use tabled::{Table, Tabled};

#[derive(Debug)]
struct Config {
    network: Network,
    db: Store,
    rpc_client: Client,
    dust_threshold: u64,
}

fn main() {
    let cli = Cli::parse();

    let network = get_network(cli.chain);

    // Build RPC auth from CLI args — prefer user:pass, fall back to cookie file
    let auth = match (cli.rpc_user, cli.rpc_pass) {
        (Some(user), Some(pass)) => Auth::UserPass(user, pass),
        _ => Auth::None,
    };

    let rpc_client =
        Client::new(&cli.rpc_url, auth).expect("failed to connect to Bitcoin Core RPC");

    // Expand ~ in datadir path
    let datadir = if cli.datadir.starts_with("~") {
        let home = std::env::var("HOME").expect("HOME env var not set");
        PathBuf::from(cli.datadir.to_string_lossy().replacen("~", &home, 1))
    } else {
        cli.datadir
    };

    std::fs::create_dir_all(&datadir).expect("failed to create datadir");
    let db_path = datadir.join("hoover.db");
    let db = Store::open(&db_path).expect("failed to open database");

    let config = Config {
        network,
        db,
        rpc_client,
        dust_threshold: cli.amount,
    };

    match cli.command {
        Commands::Add {
            descriptor,
            change_descriptor,
            start_height,
        } => add(config, descriptor, change_descriptor, start_height),
        Commands::List => list(config, cli.fingerprint),
        Commands::Clean {
            output_dir,
            address,
        } => clean(config, output_dir, address),
        Commands::Broadcast { psbt, output_dir } => broadcast(config, psbt, output_dir),
        Commands::Status { txid } => status(config, txid),
    }
}

fn get_network(chain: Chain) -> Network {
    match chain {
        Chain::Main => Network::Bitcoin,
        Chain::Testnet => Network::Testnet,
        Chain::Testnet4 => Network::Testnet4,
        Chain::Signet => Network::Signet,
        Chain::Regtest => Network::Regtest,
    }
}

fn add(config: Config, descriptor: String, change_descriptor: Option<String>, start_height: u32) {
    let parsed = parse_descriptor(
        &descriptor,
        change_descriptor.as_deref(),
        config.network,
        start_height,
    )
    .expect("Failed to parse descriptor");
    config
        .db
        .upsert_descriptor(&parsed)
        .expect("Failed to update store");
    println!(
        "Registered: {} (start_height={})",
        parsed.wallet_name, start_height
    );
}

fn list(config: Config, fingerprint: Option<String>) {
    let descriptors = config
        .db
        .load_descriptors()
        .expect("failed to load descriptors");

    if descriptors.is_empty() {
        println!("No descriptors registered. Use `hoover add` to register one.");
        return;
    }

    let tip_height = config.rpc_client
        .get_block_count()
        .unwrap_or(0) as u32;

    let mut all_utxos: Vec<Utxo> = Vec::new();
    let mut descriptor_map: Vec<(Utxo, &hoover::wallet_descriptor::wallet_parser::ParsedDescriptor)> = Vec::new();

    for descriptor in &descriptors {
        if let Some(ref fp) = fingerprint {
            if &descriptor.wallet_name != fp { continue; }
        }
        match Utxo::fetch_for_descriptor(&config.rpc_client, descriptor) {
            Ok(utxos) => {
                for u in &utxos {
                    descriptor_map.push((u.clone(), descriptor));
                }
                all_utxos.extend(utxos);
            }
            Err(e) => eprintln!("Warning: failed to fetch UTXOs for {}: {e}", descriptor.wallet_name),
        }
    }

    // Population 1: unconditional dust — below threshold, sweep regardless
    let mut all_dust: Vec<DustUtxo> = Utxo::filter_dust_utxos(&all_utxos, config.dust_threshold);

    // Deduplicate by outpoint
    let mut seen = std::collections::HashSet::new();
    all_dust.retain(|d| seen.insert(d.utxo.outpoint));

    // Build tx cache covering all UTXOs — one getrawtransaction per unique txid
    let tx_cache = build_tx_cache(&config.rpc_client, &all_utxos, config.dust_threshold, tip_height);

    // Register heuristics
    let heuristics: Vec<&dyn DustHeuristic> = vec![
        &ChangeAddressHeuristic,
        &ExactFloorPolicy,
        &MultiAddressHeuristic,
    ];

    // Score population 1
    for dust in &mut all_dust {
        let descriptor = descriptor_map
            .iter()
            .find(|(u, _)| u.outpoint == dust.utxo.outpoint)
            .map(|(_, d)| *d);
        if let Some(desc) = descriptor {
            let ctx = build_context(&dust.utxo, &all_utxos, &tx_cache, desc, tip_height);
            let score = aggregate(&dust.utxo, &ctx, &heuristics);
            dust.suspicion_score = Some(score.score);
            dust.suspicion_reasons = score.reasons;
        }
    }

    // Population 2: above threshold but within scan window (4x threshold)
    // Only added if heuristic score exceeds suspicion threshold
    const SUSPICION_THRESHOLD: f32 = 0.5;
    let scan_window = config.dust_threshold * 4;
    let already_included: std::collections::HashSet<_> =
        all_dust.iter().map(|d| d.utxo.outpoint).collect();

    for utxo in all_utxos.iter().filter(|u| {
        let sats = u.value.to_sat();
        sats >= config.dust_threshold
            && sats < scan_window
            && !already_included.contains(&u.outpoint)
    }) {
        let descriptor = descriptor_map
            .iter()
            .find(|(u, _)| u.outpoint == utxo.outpoint)
            .map(|(_, d)| *d);
        if let Some(desc) = descriptor {
            let ctx = build_context(utxo, &all_utxos, &tx_cache, desc, tip_height);
            let score = aggregate(utxo, &ctx, &heuristics);
            if score.score >= SUSPICION_THRESHOLD {
                all_dust.push(DustUtxo {
                    utxo: utxo.clone(),
                    reason: DustReason::SuspectedAttack { score: score.score },
                    is_spent: false,
                    suspicion_score: Some(score.score),
                    suspicion_reasons: score.reasons,
                });
            }
        }
    }

    if all_dust.is_empty() {
        println!("{} descriptor(s) registered — no dust UTXOs found.", descriptors.len());
        return;
    }

    config.db.upsert_utxos(&all_dust).expect("Failed to store dust to table");

    let rows: Vec<DustRow> = all_dust.iter().map(DustRow::from).collect();
    let table = Table::new(&rows).to_string();
    println!("Network: {}", config.network);
    println!("{table}");
    println!(
        "\n{} descriptor(s) registered, {} dust UTXO(s) found.",
        descriptors.len(),
        all_dust.len()
    );
}

#[derive(Tabled)]
struct DustRow {
    #[tabled(rename = "TxID (short)")]
    txid: String,
    #[tabled(rename = "Vout")]
    vout: u32,
    #[tabled(rename = "Value (sats)")]
    value_sats: u64,
    #[tabled(rename = "Height")]
    block_height: u32,
    #[tabled(rename = "Reason")]
    reason: String,
    #[tabled(rename = "Score")]
    score: String,
    #[tabled(rename = "Wallet")]
    wallet: String,
}

impl From<&DustUtxo> for DustRow {
    fn from(d: &DustUtxo) -> Self {
        let txid_full = d.utxo.outpoint.txid.to_string();
        // Show first 8 + "…" + last 8 chars to keep the table readable
        let txid_short = format!("{}…{}", &txid_full[..8], &txid_full[txid_full.len() - 8..]);

        let reason = match &d.reason {
            DustReason::BelowDustLimit { threshold_sats } =>
                format!("below dust limit ({threshold_sats} sats)"),
            DustReason::UneconomicalToSpend { fee_to_spend_sats, value_sats } =>
                format!("uneconomical (fee {fee_to_spend_sats} > value {value_sats})"),
            DustReason::SuspiciousRoundValue =>
                "suspicious round value".to_string(),
            DustReason::SuspectedAttack { score } =>
                format!("suspected attack (score {score:.2})"),
        };

        DustRow {
            txid: txid_short,
            vout: d.utxo.outpoint.vout,
            value_sats: d.utxo.value.to_sat(),
            block_height: d.utxo.block_height,
            reason,
            score: d.suspicion_score
                .map(|s| format!("{:.2}", s))
                .unwrap_or_else(|| "-".to_string()),
            wallet: d.utxo.descriptor_fingerprint.clone(),
        }
    }
}

fn clean(config: Config, output_dir: Option<PathBuf>, address: Option<String>) {
    let out_dir = output_dir
        .unwrap_or_else(|| std::env::current_dir().expect("failed to get current directory"));

    // Load all dust UTXOs from the DB (populated by `list`)
    let all_dust = config
        .db
        .load_dust_utxos()
        .expect("failed to load dust UTXOs");

    if all_dust.is_empty() {
        println!("No dust UTXOs in the database. Run `hoover list` first.");
        return;
    }

    // Build address → UTXOs groups, respecting the optional address filter
    let groups: Vec<(Address, Vec<DustUtxo>)> = if let Some(addr_str) = address {
        let addr: Address = addr_str
            .parse::<Address<bitcoin::address::NetworkUnchecked>>()
            .expect("invalid address")
            .require_network(config.network)
            .expect("address is for the wrong network");

        let filtered = Utxo::filter_by_address(&all_dust, &addr);
        if filtered.is_empty() {
            println!("No dust UTXOs found for address {addr}.");
            return;
        }
        vec![(addr, filtered)]
    } else {
        let map = Utxo::group_by_address(&all_dust, config.network);
        if map.is_empty() {
            println!("No dust UTXOs could be grouped by address.");
            return;
        }
        map.into_iter().collect()
    };

    std::fs::create_dir_all(&out_dir).expect("failed to create output directory");

    let mut written = 0usize;
    for (i, (addr, utxos)) in groups.iter().enumerate() {
        let psbt = build_sweep_psbt(utxos).expect("failed to build sweep PSBT");

        // Name: <wallet_fingerprint>-<index>.psbt
        let fingerprint = &utxos[0].utxo.descriptor_fingerprint;
        let filename = format!("{fingerprint}-{i}.psbt");
        let path = out_dir.join(&filename);

        write_psbt_file(&psbt, &path).expect("failed to write PSBT file");

        println!(
            "  [{i}] {filename}  ({} input(s), address {})",
            utxos.len(),
            addr
        );
        written += 1;
    }

    println!(
        "\n{written} PSBT file(s) written to {}\n\
         Sign each file with your signer, then broadcast with:\n\
         hoover broadcast --psbt <file.psbt>",
        out_dir.display()
    );
}

fn broadcast(config: Config, psbt_path: Option<PathBuf>, output_dir: Option<PathBuf>) {
    let dir = output_dir
        .unwrap_or_else(|| std::env::current_dir().expect("failed to get current directory"));

    // Collect the list of files to broadcast
    let files: Vec<PathBuf> = if let Some(path) = psbt_path {
        vec![path]
    } else {
        // Scan the directory for all *.psbt files
        let entries = std::fs::read_dir(&dir).expect("failed to read output directory");
        let mut found: Vec<PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("psbt"))
            .collect();
        found.sort(); // deterministic order
        found
    };

    if files.is_empty() {
        println!("No .psbt files found. Run `hoover clean` first to generate them.");
        return;
    }

    let mut succeeded = 0usize;
    let mut failed = 0usize;

    for path in &files {
        let psbt = match read_psbt_file(path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("  ✗ {} — failed to read: {e}", path.display());
                failed += 1;
                continue;
            }
        };

        let tx = match finalize_psbt(psbt) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("  ✗ {} — not fully signed: {e}", path.display());
                failed += 1;
                continue;
            }
        };

        let hex = bitcoin::consensus::encode::serialize_hex(&tx);
        match config.rpc_client.send_raw_transaction(hex) {
            Ok(txid) => {
                println!("  ✓ {} → txid {txid}", path.display());
                // Mark the spent UTXOs in the DB
                let outpoints: Vec<bitcoin::OutPoint> =
                    tx.input.iter().map(|i| i.previous_output).collect();
                if let Err(e) = config.db.mark_utxos_spent(&outpoints) {
                    eprintln!("    warning: could not mark UTXOs as spent: {e}");
                }
                if let Err(e) = std::fs::remove_file(path) {
                    eprintln!("    warning: could not delete {}: {e}", path.display());
                }
                succeeded += 1;
            }
            Err(e) => {
                eprintln!("  ✗ {} — broadcast failed: {e}", path.display());
                failed += 1;
            }
        }
    }

    println!("\n{succeeded} broadcast(s) succeeded, {failed} failed.",);
    if succeeded > 0 {
        println!("Use `hoover status <txid>` to check confirmation.");
    }
}

fn status(config: Config, txid: String) {
    let txid: bitcoin::Txid = txid
        .parse()
        .expect("invalid txid — expected 64 hex characters");

    match tx_status(&config.rpc_client, &txid) {
        Ok(TxStatus::Unconfirmed) => {
            println!("Status: Unconfirmed (in mempool)");
        }
        Ok(TxStatus::Confirmed {
            confirmations,
            block_hash,
        }) => {
            println!("Status:        Confirmed");
            println!("Confirmations: {confirmations}");
            println!("Block hash:    {block_hash}");
        }
        Err(e) => {
            eprintln!("Error: {e}");
            eprintln!("Tip: node may need -txindex=1 to query confirmed transactions.");
        }
    }
}
