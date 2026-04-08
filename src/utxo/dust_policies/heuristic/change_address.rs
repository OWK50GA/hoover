use bdk_wallet::KeychainKind;

use crate::utxo::dust_policies::UtxoContext;
use crate::utxo::dust_policies::heuristic::DustHeuristic;
use crate::utxo::utxo_parser::Utxo;

/// Flags dust received on an internal (change) address.
///
/// Change addresses are never shared with anyone — they are derived internally
/// by the wallet to receive change from your own transactions. Any external
/// party sending funds to a change address has been watching your transactions
/// on-chain to identify it. Receiving dust there is a strong indicator of a
/// targeted dust attack.
///
/// Signal:
///   1.0 — internal keychain AND address was never shared
///   0.7 — internal keychain but address_ever_shared is true (unusual but possible)
///   0.0 — external keychain (normal receive address)
pub struct ChangeAddressHeuristic;

impl ChangeAddressHeuristic {
    const NAME: &'static str = "dust_on_change_address";
    const WEIGHT: f32 = 3.0;
}

impl DustHeuristic for ChangeAddressHeuristic {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn weight(&self) -> f32 {
        Self::WEIGHT
    }

    fn evaluate(&self, _utxo: &Utxo, ctx: &UtxoContext) -> f32 {
        match ctx.keychain {
            KeychainKind::Internal => {
                if !ctx.address_ever_shared {
                    // Change address, never shared — strongest signal
                    1.0
                } else {
                    // Internal but somehow shared (edge case) — still suspicious
                    0.7
                }
            }
            KeychainKind::External => 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utxo::dust_policies::UtxoContext;
    use crate::utxo::utxo_parser::Utxo;
    use bitcoin::{AddressType, Amount, OutPoint, ScriptBuf, Txid, hashes::Hash};

    fn dummy_utxo() -> Utxo {
        Utxo {
            outpoint: OutPoint {
                txid: Txid::all_zeros(),
                vout: 0,
            },
            value: Amount::from_sat(300),
            script_pubkey: ScriptBuf::new(),
            block_height: 800_000,
            descriptor_fingerprint: "deadbeef".to_string(),
        }
    }

    fn ctx(keychain: KeychainKind, ever_shared: bool) -> UtxoContext {
        UtxoContext {
            address_type: AddressType::P2wpkh,
            keychain,
            derivation_index: 5,
            address_ever_shared: ever_shared,
            times_address_received: 1,
            source_output_count: 10,
            source_dust_output_count: 8,
            source_input_count: 1,
            distinct_input_addresses: 1,
            source_age_blocks: 3,
            source_fee_rate: 2.0,
            source_addr_known: false,
            source_is_exchange: None,
            source_addr_reused: true,
            source_output_fan_out: 10,
            block_height: 800_000,
            age_blocks: 3,
            prev_spend_attempts: 0,
            wallet_total_utxo_count: 5,
            other_utxos_same_sender: 0,
        }
    }

    #[test]
    fn internal_never_shared_scores_max() {
        let h = ChangeAddressHeuristic;
        let score = h.evaluate(&dummy_utxo(), &ctx(KeychainKind::Internal, false));
        assert_eq!(score, 1.0);
    }

    #[test]
    fn internal_ever_shared_scores_partial() {
        let h = ChangeAddressHeuristic;
        let score = h.evaluate(&dummy_utxo(), &ctx(KeychainKind::Internal, true));
        assert_eq!(score, 0.7);
    }

    #[test]
    fn external_scores_zero() {
        let h = ChangeAddressHeuristic;
        let score = h.evaluate(&dummy_utxo(), &ctx(KeychainKind::External, false));
        assert_eq!(score, 0.0);
    }
}
