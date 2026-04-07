use bdk_bitcoind_rpc::bitcoincore_rpc::{Client, RpcApi, json::ImportDescriptors, json::Timestamp};
use bitcoin::{Address, Amount, Network, OutPoint, ScriptBuf};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::wallet_descriptor::wallet_parser::ParsedDescriptor;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Utxo {
    pub outpoint: OutPoint,
    pub value: Amount,
    pub script_pubkey: ScriptBuf,
    pub block_height: u32,
    pub descriptor_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DustReason {
    BelowDustLimit {
        threshold_sats: u64,
    },
    UneconomicalToSpend {
        fee_to_spend_sats: u64,
        value_sats: u64,
    },
    SuspiciousRoundValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DustUtxo {
    pub utxo: Utxo,
    pub reason: DustReason,
    pub is_spent: bool
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("rpc error: {0}")]
    Rpc(#[from] bdk_bitcoind_rpc::bitcoincore_rpc::Error),
    #[error("invalid txid: {0}")]
    InvalidTxid(String),
}

impl Utxo {
    /// Imports the descriptor into Bitcoin Core's wallet (triggering a rescan from
    /// `start_height`), then calls `listunspent` to fetch all UTXOs belonging to
    /// that descriptor. Returns a `Vec<Utxo>` of confirmed, unspent outputs.
    pub fn fetch_for_descriptor(
        client: &Client,
        // second_client: &CoreRpcClient,
        descriptor: &ParsedDescriptor,
    ) -> Result<Vec<Self>, ScanError> {
        // Step 1: importdescriptors
        // Timestamp::Time(0) tells Bitcoin Core to rescan from genesis.
        // internal: Some(false) marks this as the external (receive) descriptor.
        let external_import = ImportDescriptors {
            descriptor: descriptor.descriptor_str.clone(),
            timestamp: Timestamp::Time(0),
            active: Some(true),
            range: Some((0, 1000)),
            next_index: None,
            internal: Some(false),
            label: Some(descriptor.wallet_name.clone()),
        };
        client.import_descriptors(external_import)?;
        // second_client.import_descriptors(external_import)?;

        // Import the change descriptor separately if present.
        // internal: Some(true) marks it as the internal (change) descriptor.
        if let Some(change_desc) = &descriptor.change_descriptor_str {
            let change_import = ImportDescriptors {
                descriptor: change_desc.clone(),
                timestamp: Timestamp::Time(0),
                active: Some(true),
                range: Some((0, 1000)),
                next_index: None,
                internal: Some(true),
                label: Some(format!("{}/change", descriptor.wallet_name)),
            };
            client.import_descriptors(change_import)?;
        }

        // Step 2: get current tip height so we can compute block_height from confirmations.
        // listunspent returns `confirmations`, not `block_height` directly.
        // block_height = tip_height - confirmations + 1
        let tip_height = client.get_block_count()? as u32;

        // Step 3: listunspent — minconf=1 to exclude unconfirmed, no address filter
        // (Bitcoin Core already knows which addresses belong to the imported descriptor).
        let unspent = client.list_unspent(
            Some(1),     // minconf: confirmed only
            None,        // maxconf: no upper limit
            None,        // addresses: None = all wallet addresses
            Some(false), // include_unsafe: false
            None,        // query_options
        )?;

        // Step 4: map each listunspent entry to our Utxo type.
        let utxos = unspent
            .into_iter()
            .map(|entry| Utxo {
                outpoint: OutPoint {
                    txid: entry.txid,
                    vout: entry.vout,
                },
                value: entry.amount,
                script_pubkey: entry.script_pub_key,
                block_height: confirmations_to_height(tip_height, entry.confirmations),
                descriptor_fingerprint: descriptor.wallet_name.clone(),
            })
            .collect();

        Ok(utxos)
    }

    pub fn filter_dust_utxos(utxos: &[Utxo], min_amount: u64) -> Vec<DustUtxo> {
        let mut dust_utxos = vec![];

        for utxo in utxos {
            if utxo.value.to_sat() < min_amount {
                let dust_utxo = DustUtxo {
                    utxo: utxo.clone(),
                    reason: DustReason::BelowDustLimit {
                        threshold_sats: 546,
                    },
                    is_spent: false
                };
                dust_utxos.push(dust_utxo);
                continue;
            }
        }

        dust_utxos
    }

    /// Returns all dust UTXOs whose script_pubkey matches the given address.
    /// Comparison is done via script_pubkey bytes — no string parsing needed.
    pub fn filter_by_address(utxos: &[DustUtxo], address: &Address) -> Vec<DustUtxo> {
        let target = address.script_pubkey();
        utxos
            .iter()
            .filter(|d| d.utxo.script_pubkey == target)
            .cloned()
            .collect()
    }

    /// Groups dust UTXOs by address, returning a HashMap of script_pubkey → UTXOs.
    ///
    /// Each group contains only UTXOs that share the same address. This is the
    /// required input shape for sweep PSBT construction — mixing inputs from
    /// different addresses in one transaction would reveal address linkage to
    /// an observer (common input ownership heuristic).
    pub fn group_by_address(utxos: &[DustUtxo], network: Network) -> HashMap<Address, Vec<DustUtxo>> {
        let mut map: HashMap<Address, Vec<DustUtxo>> = HashMap::new();
        for dust in utxos {
            // Derive the address from the script_pubkey. Skip UTXOs whose
            // script type cannot be represented as an address (e.g. bare OP_RETURN).
            if let Ok(addr) = Address::from_script(&dust.utxo.script_pubkey, network) {
                map.entry(addr).or_default().push(dust.clone());
            }
        }
        map
    }
}

/// Derives the block height at which a UTXO was confirmed.
///
/// Bitcoin Core's `listunspent` returns `confirmations`, not `block_height`.
/// A UTXO with 1 confirmation was confirmed in the tip block itself.
/// A UTXO with 0 confirmations is unconfirmed (mempool) — we return 0.
pub fn confirmations_to_height(tip_height: u32, confirmations: u32) -> u32 {
    if confirmations == 0 {
        return 0;
    }
    tip_height.saturating_sub(confirmations - 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Address, Amount, OutPoint, ScriptBuf, Txid, hashes::Hash};

    fn dummy_utxo(value_sats: u64, confirmations: u32, tip_height: u32) -> Utxo {
        Utxo {
            outpoint: OutPoint {
                txid: Txid::all_zeros(),
                vout: 0,
            },
            value: Amount::from_sat(value_sats),
            script_pubkey: ScriptBuf::new(),
            block_height: confirmations_to_height(tip_height, confirmations),
            descriptor_fingerprint: "deadbeef".to_string(),
        }
    }

    // --- confirmations_to_height ---

    #[test]
    fn height_from_one_confirmation_is_tip() {
        // 1 confirmation means confirmed in the tip block.
        assert_eq!(confirmations_to_height(800_000, 1), 800_000);
    }

    #[test]
    fn height_from_six_confirmations() {
        // 6 confirmations at tip 800_000 → confirmed at block 799_995.
        assert_eq!(confirmations_to_height(800_000, 6), 799_995);
    }

    #[test]
    fn height_from_zero_confirmations_is_zero() {
        // Unconfirmed (mempool) → height 0.
        assert_eq!(confirmations_to_height(800_000, 0), 0);
    }

    #[test]
    fn height_does_not_underflow() {
        // confirmations > tip_height + 1 should not panic or wrap.
        assert_eq!(confirmations_to_height(5, 100), 0);
    }

    // --- Utxo struct construction ---

    #[test]
    fn utxo_value_is_preserved() {
        let utxo = dummy_utxo(546, 1, 800_000);
        assert_eq!(utxo.value.to_sat(), 546);
    }

    #[test]
    fn utxo_block_height_derived_correctly() {
        let utxo = dummy_utxo(1000, 10, 800_000);
        assert_eq!(utxo.block_height, 799_991);
    }

    #[test]
    fn utxo_fingerprint_is_set() {
        let utxo = dummy_utxo(1000, 1, 800_000);
        assert_eq!(utxo.descriptor_fingerprint, "deadbeef");
    }

    // --- filter_by_address ---

    fn p2wpkh_utxo(value_sats: u64, key_byte: u8) -> DustUtxo {
        // Build a distinct P2WPKH script for each key_byte
        let hash = bitcoin::WPubkeyHash::from_byte_array([key_byte; 20]);
        let script = ScriptBuf::new_p2wpkh(&hash);
        DustUtxo {
            utxo: Utxo {
                outpoint: OutPoint { txid: Txid::all_zeros(), vout: key_byte as u32 },
                value: Amount::from_sat(value_sats),
                script_pubkey: script,
                block_height: 800_000,
                descriptor_fingerprint: "deadbeef".to_string(),
            },
            reason: DustReason::BelowDustLimit { threshold_sats: 546 },
            is_spent: false
        }
    }

    #[test]
    fn filter_by_address_returns_matching_utxos() {
        use bitcoin::Network;
        let utxo_a = p2wpkh_utxo(300, 0xaa);
        let utxo_b = p2wpkh_utxo(200, 0xbb);
        let all = vec![utxo_a.clone(), utxo_b.clone()];

        let addr_a = Address::from_script(&utxo_a.utxo.script_pubkey, Network::Testnet).unwrap();
        let result = Utxo::filter_by_address(&all, &addr_a);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].utxo.script_pubkey, utxo_a.utxo.script_pubkey);
    }

    #[test]
    fn filter_by_address_returns_empty_for_no_match() {
        use bitcoin::Network;
        let utxo_a = p2wpkh_utxo(300, 0xaa);
        let utxo_b = p2wpkh_utxo(200, 0xcc); // different address
        let all = vec![utxo_b.clone()];

        let addr_a = Address::from_script(&utxo_a.utxo.script_pubkey, Network::Testnet).unwrap();
        let result = Utxo::filter_by_address(&all, &addr_a);
        assert!(result.is_empty());
    }

    // --- group_by_address ---

    #[test]
    fn group_by_address_produces_correct_groups() {
        use bitcoin::Network;
        let utxo_a1 = p2wpkh_utxo(300, 0xaa);
        let utxo_a2 = p2wpkh_utxo(200, 0xaa); // same address as a1
        let utxo_b  = p2wpkh_utxo(100, 0xbb); // different address
        let all = vec![utxo_a1.clone(), utxo_a2.clone(), utxo_b.clone()];

        let groups = Utxo::group_by_address(&all, Network::Testnet);

        assert_eq!(groups.len(), 2, "should have 2 distinct address groups");
        let addr_a = Address::from_script(&utxo_a1.utxo.script_pubkey, Network::Testnet).unwrap();
        assert_eq!(groups[&addr_a].len(), 2);
    }

    #[test]
    fn group_by_address_no_cross_address_mixing() {
        use bitcoin::Network;
        let utxos: Vec<DustUtxo> = (0u8..5)
            .map(|i| p2wpkh_utxo(300, i))
            .collect();

        let groups = Utxo::group_by_address(&utxos, Network::Testnet);

        // Every group must contain only UTXOs with the same script_pubkey
        for (addr, group_utxos) in &groups {
            let expected_script = addr.script_pubkey();
            for u in group_utxos {
                assert_eq!(u.utxo.script_pubkey, expected_script,
                    "cross-address mixing detected in group");
            }
        }
    }
}
