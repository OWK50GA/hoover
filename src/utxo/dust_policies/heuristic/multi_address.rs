use crate::utxo::dust_policies::UtxoContext;
use crate::utxo::dust_policies::heuristic::DustHeuristic;
use crate::utxo::utxo_parser::Utxo;

/// Flags dust when the same sending transaction reached multiple addresses in
/// your wallet.
///
/// If multiple of your UTXOs share the same `txid`, they all came from one
/// transaction — a classic spray pattern. The attacker sent dust to several of
/// your addresses in a single tx, hoping you consolidate them and reveal the
/// link between those addresses.
///
/// `other_utxos_same_sender` in `UtxoContext` is pre-computed before scoring:
///   - Cheap path: count UTXOs in your local DB sharing the same `outpoint.txid`
///   - Enhanced path: if RPC context is available, also count UTXOs from the
///     same sender across different transactions (cross-tx spray)
///
/// Signal scale:
///   0 others → 0.0  (no pattern)
///   1 other   → 0.6  (possible coincidence, moderate suspicion)
///   2 others  → 0.85 (unlikely coincidence)
///   3+        → 1.0  (almost certainly a spray attack)
pub struct MultiAddressHeuristic;

impl MultiAddressHeuristic {
    const NAME: &'static str = "multi_address_spray";
    const WEIGHT: f32 = 2.0;
}

impl DustHeuristic for MultiAddressHeuristic {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn weight(&self) -> f32 {
        Self::WEIGHT
    }

    fn evaluate(&self, _utxo: &Utxo, ctx: &UtxoContext) -> f32 {
        match ctx.other_utxos_same_sender {
            0 => 0.0,
            1 => 0.6,
            2 => 0.85,
            _ => 1.0,
        }
    }
}

/// Pre-computes `other_utxos_same_sender` for a batch of UTXOs using the
/// cheap txid-sharing approach — no RPC required.
///
/// For each UTXO, counts how many *other* UTXOs in the same batch share the
/// same `outpoint.txid`. This is the minimum count; if RPC-derived context
/// is available it can be added on top.
pub fn count_same_sender(utxos: &[Utxo], target: &Utxo) -> u32 {
    utxos
        .iter()
        .filter(|u| {
            u.outpoint.txid == target.outpoint.txid && u.outpoint != target.outpoint // don't count self
        })
        .count() as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utxo::dust_policies::UtxoContext;
    use bdk_wallet::KeychainKind;
    use bitcoin::{AddressType, Amount, OutPoint, ScriptBuf, Txid, hashes::Hash};

    fn utxo(txid_byte: u8, vout: u32) -> Utxo {
        Utxo {
            outpoint: OutPoint {
                txid: Txid::from_byte_array([txid_byte; 32]),
                vout,
            },
            value: Amount::from_sat(300),
            script_pubkey: ScriptBuf::new(),
            block_height: 800_000,
            descriptor_fingerprint: "deadbeef".to_string(),
        }
    }

    fn ctx(other_utxos_same_sender: u32) -> UtxoContext {
        UtxoContext {
            address_type: AddressType::P2wpkh,
            keychain: KeychainKind::External,
            derivation_index: 0,
            address_ever_shared: true,
            times_address_received: 1,
            source_output_count: 5,
            source_dust_output_count: 5,
            source_input_count: 1,
            distinct_input_addresses: 1,
            source_age_blocks: 2,
            source_fee_rate: 2.0,
            source_addr_known: false,
            source_is_exchange: None,
            source_addr_reused: false,
            source_output_fan_out: 5,
            block_height: 800_000,
            age_blocks: 2,
            prev_spend_attempts: 0,
            wallet_total_utxo_count: 10,
            other_utxos_same_sender,
        }
    }

    #[test]
    fn no_others_scores_zero() {
        let h = MultiAddressHeuristic;
        assert_eq!(h.evaluate(&utxo(0xaa, 0), &ctx(0)), 0.0);
    }

    #[test]
    fn one_other_scores_moderate() {
        let h = MultiAddressHeuristic;
        assert_eq!(h.evaluate(&utxo(0xaa, 0), &ctx(1)), 0.6);
    }

    #[test]
    fn two_others_scores_high() {
        let h = MultiAddressHeuristic;
        assert_eq!(h.evaluate(&utxo(0xaa, 0), &ctx(2)), 0.85);
    }

    #[test]
    fn three_plus_scores_max() {
        let h = MultiAddressHeuristic;
        assert_eq!(h.evaluate(&utxo(0xaa, 0), &ctx(3)), 1.0);
        assert_eq!(h.evaluate(&utxo(0xaa, 0), &ctx(10)), 1.0);
    }

    #[test]
    fn count_same_sender_finds_shared_txid() {
        let shared_txid = 0xbb;
        let u0 = utxo(shared_txid, 0);
        let u1 = utxo(shared_txid, 1); // same tx, different vout
        let u2 = utxo(shared_txid, 2); // same tx, different vout
        let u3 = utxo(0xcc, 0); // different tx

        let all = vec![u0.clone(), u1.clone(), u2.clone(), u3.clone()];

        assert_eq!(count_same_sender(&all, &u0), 2); // u1 and u2
        assert_eq!(count_same_sender(&all, &u3), 0); // no others from 0xcc
    }

    #[test]
    fn count_same_sender_excludes_self() {
        let u = utxo(0xaa, 0);
        let all = vec![u.clone()];
        assert_eq!(count_same_sender(&all, &u), 0);
    }
}
