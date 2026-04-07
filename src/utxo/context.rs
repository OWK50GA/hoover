use bdk_bitcoind_rpc::bitcoincore_rpc::{Client, RpcApi};
use bdk_wallet::KeychainKind;
use bitcoin::{AddressType, Txid};
use std::collections::HashMap;

use crate::utxo::dust_policies::UtxoContext;
use crate::utxo::utxo_parser::Utxo;
use crate::wallet_descriptor::wallet_parser::ParsedDescriptor;

/// Cached data extracted from a single sending transaction.
/// One entry per unique txid — populated via one `getrawtransaction` call.
#[derive(Debug, Clone)]
pub struct TxInfo {
    pub output_count: u32,
    pub dust_output_count: u32,
    pub input_count: u32,
    pub distinct_input_addresses: u32,
    /// Outputs fan-out: how many distinct addresses the tx sent to
    pub output_fan_out: u32,
    /// Fee rate in sat/vbyte, if derivable
    pub fee_rate: f64,
    /// Confirmations at time of scan
    pub confirmations: u32,
}

/// Builds a `TxInfo` cache for all unique sending txids in `utxos`.
/// Makes one `getrawtransaction` call per unique txid.
/// UTXOs whose txid cannot be fetched are silently skipped (node may lack txindex).
pub fn build_tx_cache(
    client: &Client,
    utxos: &[Utxo],
    dust_threshold_sats: u64,
    tip_height: u32,
) -> HashMap<Txid, TxInfo> {
    let mut cache: HashMap<Txid, TxInfo> = HashMap::new();

    // Collect unique txids
    let txids: Vec<Txid> = {
        let mut seen = std::collections::HashSet::new();
        utxos
            .iter()
            .filter(|u| seen.insert(u.outpoint.txid))
            .map(|u| u.outpoint.txid)
            .collect()
    };

    for txid in txids {
        let Ok(tx_info) = client.get_raw_transaction_info(&txid, None) else {
            // Node lacks txindex or tx is unknown — skip
            continue;
        };

        let output_count = tx_info.vout.len() as u32;
        let input_count = tx_info.vin.len() as u32;

        // Count dust-sized outputs
        let dust_output_count = tx_info
            .vout
            .iter()
            .filter(|o| o.value.to_sat() < dust_threshold_sats)
            .count() as u32;

        // Count distinct output addresses (fan-out) using script hex as key
        let output_fan_out = tx_info
            .vout
            .iter()
            .map(|o| o.script_pub_key.hex.clone())
            .collect::<std::collections::HashSet<_>>()
            .len() as u32;

        // Count distinct input addresses — not available without prevout lookup,
        // so default to input_count as a conservative estimate
        let distinct_input_addresses = input_count;

        // Estimate fee rate from vsize if mempool entry available
        let fee_rate = client
            .get_mempool_entry(&txid)
            .ok()
            .and_then(|e| {
                let fee_sats = e.fees.base.to_sat() as f64;
                let vsize = tx_info.vsize as f64;
                if vsize > 0.0 {
                    Some(fee_sats / vsize)
                } else {
                    None
                }
            })
            .unwrap_or(0.0);

        let confirmations = tx_info.confirmations.unwrap_or(0);
        let age_blocks = tip_height.saturating_sub(tip_height.saturating_sub(confirmations));

        cache.insert(
            txid,
            TxInfo {
                output_count,
                dust_output_count,
                input_count,
                distinct_input_addresses,
                output_fan_out,
                fee_rate,
                confirmations: age_blocks,
            },
        );
    }

    cache
}

/// Builds a `UtxoContext` for a single UTXO.
///
/// - `all_dust` — the full list of dust UTXOs (for cross-UTXO counts)
/// - `tx_cache` — pre-built cache from `build_tx_cache`
/// - `descriptor` — the descriptor this UTXO belongs to
/// - `tip_height` — current chain tip
pub fn build_context(
    utxo: &Utxo,
    all_dust: &[Utxo],
    tx_cache: &HashMap<Txid, TxInfo>,
    descriptor: &ParsedDescriptor,
    tip_height: u32,
) -> UtxoContext {
    // Determine keychain from descriptor label convention:
    // change descriptors are stored with "/change" suffix in wallet_name
    let keychain = if descriptor.change_descriptor_str.is_some()
        && utxo.descriptor_fingerprint.ends_with("/change")
    {
        KeychainKind::Internal
    } else {
        KeychainKind::External
    };

    // External addresses are assumed shared; internal (change) are not
    let address_ever_shared = matches!(keychain, KeychainKind::External);

    // Detect address type from script_pubkey
    let address_type = if utxo.script_pubkey.is_p2pkh() {
        AddressType::P2pkh
    } else if utxo.script_pubkey.is_p2sh() {
        AddressType::P2sh
    } else if utxo.script_pubkey.is_p2wpkh() {
        AddressType::P2wpkh
    } else if utxo.script_pubkey.is_p2wsh() {
        AddressType::P2wsh
    } else {
        AddressType::P2tr // default for taproot and unknown
    };

    // Count how many other dust UTXOs share the same sending txid (spray detection)
    let other_utxos_same_sender = all_dust
        .iter()
        .filter(|u| u.outpoint.txid == utxo.outpoint.txid && u.outpoint != utxo.outpoint)
        .count() as u32;

    // Count how many times this address has received outputs in the dust list
    let times_address_received = all_dust
        .iter()
        .filter(|u| u.script_pubkey == utxo.script_pubkey)
        .count() as u32;

    let age_blocks = tip_height.saturating_sub(utxo.block_height);

    // Pull tx-level data from cache, or use safe defaults if unavailable
    let tx = tx_cache.get(&utxo.outpoint.txid);

    UtxoContext {
        address_type,
        keychain,
        derivation_index: 0, // not yet derivable without full descriptor scan
        address_ever_shared,
        times_address_received,
        source_output_count: tx.map(|t| t.output_count).unwrap_or(0),
        source_dust_output_count: tx.map(|t| t.dust_output_count).unwrap_or(0),
        source_input_count: tx.map(|t| t.input_count).unwrap_or(0),
        distinct_input_addresses: tx.map(|t| t.distinct_input_addresses).unwrap_or(0),
        source_age_blocks: tx.map(|t| t.confirmations).unwrap_or(0),
        source_fee_rate: tx.map(|t| t.fee_rate).unwrap_or(0.0),
        source_addr_known: false,
        source_is_exchange: None,
        source_addr_reused: false,
        source_output_fan_out: tx.map(|t| t.output_fan_out).unwrap_or(0),
        block_height: utxo.block_height,
        age_blocks,
        prev_spend_attempts: 0,
        wallet_total_utxo_count: all_dust.len() as u32,
        other_utxos_same_sender,
    }
}
