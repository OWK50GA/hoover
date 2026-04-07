use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client as BdkClient, RpcApi};
/// Integration test: full flow from registering a descriptor to fetching raw UTXOs.
///
/// Requires a `bitcoind` binary on PATH. The test spins up a regtest node via
/// `corepc-node`, creates a wallet, mines coins, sends to a descriptor-derived
/// address, then runs the full flow:
///   1. parse_descriptor  → ParsedDescriptor
///   2. Store::open + upsert_descriptor  → persisted to redb
///   3. Store::load_descriptors  → round-trip check
///   4. Utxo::fetch_for_descriptor  → Vec<Utxo> from Bitcoin Core
use bitcoin::Network;
use corepc_node::{Conf, Node};
use hoover::{
    redb::storage::Store, utxo::utxo_parser::Utxo,
    wallet_descriptor::wallet_parser::parse_descriptor,
};
use tempfile::tempdir;

/// BIP-84 wpkh descriptor for regtest (known test key — never use for real funds).
const REGTEST_WPKH: &str = "wpkh(tprv8ZgxMBicQKsPdcAqYBpzAFwU5yxBUo88ggoBqu1qPcHUfSbKK1sKMLmC7EAk438btHQrSdu3jGGQa6PA71nvH5nkDexhLteJqkM4dQmWF9g/84'/1'/0'/0/*)";

fn start_node() -> Node {
    let exe = corepc_node::exe_path().expect("bitcoind not found on PATH");
    let mut conf = Conf::default();
    conf.args.push("-fallbackfee=0.0001");
    Node::with_conf(exe, &conf).expect("failed to start node")
}

/// Build a `bitcoincore_rpc::Client` pointed at a specific wallet on the node.
/// Used to bridge corepc-node's connection params with the bdk_bitcoind_rpc client
/// that `Utxo::fetch_for_descriptor` expects.
fn wallet_client(node: &Node, wallet_name: &str) -> BdkClient {
    let rpc_url = format!("http://{}/wallet/{}", node.params.rpc_socket, wallet_name);
    BdkClient::new(&rpc_url, Auth::CookieFile(node.params.cookie_file.clone()))
        .expect("failed to create wallet RPC client")
}

#[test]
fn parse_store_and_fetch_utxos() {
    // --- Step 1: parse descriptor ---
    let parsed =
        parse_descriptor(REGTEST_WPKH, None, Network::Regtest, 0).expect("descriptor should parse");
    assert!(!parsed.wallet_name.is_empty());

    // --- Step 2: persist to redb ---
    let db_dir = tempdir().unwrap();
    let store = Store::open(&db_dir.path().join("test.db")).unwrap();
    store.upsert_descriptor(&parsed).unwrap();

    // --- Step 3: round-trip load ---
    let loaded = store.load_descriptors().unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].wallet_name, parsed.wallet_name);
    assert_eq!(loaded[0].descriptor_str, parsed.descriptor_str);

    // --- Step 4: spin up regtest node ---
    let node = start_node();

    // Separate wallet for mining so its UTXOs don't pollute our descriptor wallet.
    let miner = node.create_wallet("miner").expect("create miner wallet");
    let mining_addr = miner.new_address().unwrap();

    // Mine 101 blocks so coinbase is spendable.
    miner.generate_to_address(101, &mining_addr).unwrap();

    // Descriptor wallet — watch-only wallet our tool manages.
    node.create_wallet("descriptor-wallet")
        .expect("create descriptor wallet");
    let desc_client = wallet_client(&node, "descriptor-wallet");

    // Before any sends, the descriptor wallet should have no UTXOs.
    let utxos_before = Utxo::fetch_for_descriptor(&desc_client, &parsed)
        .expect("fetch should succeed before any sends");
    assert!(
        utxos_before.is_empty(),
        "expected no UTXOs before sending, got {}",
        utxos_before.len()
    );

    // Derive the first receive address from the descriptor wallet.
    let desc_addr = desc_client
        .get_new_address(None, None)
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap();

    // Send 500 sats from the miner to the descriptor address.
    miner
        .send_to_address(&desc_addr, bitcoin::Amount::from_sat(500))
        .unwrap();

    // Mine 1 block to confirm the send.
    miner.generate_to_address(1, &mining_addr).unwrap();

    // --- Step 5: fetch UTXOs — should now have the 500 sat output ---
    let utxos_after =
        Utxo::fetch_for_descriptor(&desc_client, &parsed).expect("fetch should succeed after send");

    assert!(
        !utxos_after.is_empty(),
        "expected at least one UTXO after sending to descriptor address"
    );

    // Verify UTXO fields.
    let utxo = &utxos_after[0];
    assert_eq!(utxo.value.to_sat(), 500);
    assert!(utxo.block_height > 0, "block_height should be set");
    assert_eq!(utxo.descriptor_fingerprint, parsed.wallet_name);
    assert!(!utxo.script_pubkey.is_empty());
}
