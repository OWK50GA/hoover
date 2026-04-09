use crate::utxo::dust_policies::UtxoContext;
use crate::utxo::dust_policies::heuristic::DustHeuristic;
use crate::utxo::utxo_parser::Utxo;

/// Detects spray-pattern dust attacks by combining three signals:
///
/// 1. Dust output ratio — what fraction of outputs in the source tx are dust-sized.
/// 2. Output fan-out — how many distinct addresses the source tx reached.
/// 3. Input/output ratio — how many outputs were produced per input (amplification).
///
/// Guard conditions (returns 0.0 immediately if not met):
///   - source_output_count < 3
///   - source_dust_output_count < 2
///
/// Final score = mean of the three sub-signals, clamped to [0.0, 1.0].
pub struct SprayPatternHeuristic;

impl SprayPatternHeuristic {
    pub const NAME: &'static str = "spray_pattern";
    pub const WEIGHT: f32 = 2.5;
}

impl DustHeuristic for SprayPatternHeuristic {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn weight(&self) -> f32 {
        Self::WEIGHT
    }

    fn evaluate(&self, _utxo: &Utxo, ctx: &UtxoContext) -> f32 {
        // Guard conditions
        if ctx.source_output_count < 3 || ctx.source_dust_output_count < 2 {
            return 0.0;
        }

        // Signal 1: dust output ratio
        let dust_ratio =
            ctx.source_dust_output_count as f32 / ctx.source_output_count as f32;
        let signal_dust = if dust_ratio >= 0.8 {
            1.0
        } else if dust_ratio >= 0.5 {
            0.7
        } else {
            0.0
        };

        // Signal 2: output fan-out
        let signal_fanout = match ctx.source_output_fan_out {
            n if n >= 20 => 1.0,
            n if n >= 10 => 0.7,
            n if n >= 5 => 0.4,
            _ => 0.0,
        };

        // Signal 3: input/output ratio (amplification)
        let io_ratio = if ctx.source_input_count == 0 {
            0.0
        } else {
            ctx.source_output_count as f32 / ctx.source_input_count as f32
        };
        let signal_io = if io_ratio >= 10.0 {
            1.0
        } else if io_ratio >= 5.0 {
            0.6
        } else {
            0.0
        };

        // Equal-weight average, clamped to [0.0, 1.0]
        ((signal_dust + signal_fanout + signal_io) / 3.0_f32).clamp(0.0, 1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utxo::dust_policies::UtxoContext;
    use crate::utxo::utxo_parser::Utxo;
    use bdk_wallet::KeychainKind;
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

    fn ctx(
        source_output_count: u32,
        source_dust_output_count: u32,
        source_input_count: u32,
        source_output_fan_out: u32,
    ) -> UtxoContext {
        UtxoContext {
            address_type: AddressType::P2wpkh,
            keychain: KeychainKind::External,
            derivation_index: 0,
            address_ever_shared: false,
            times_address_received: 1,
            source_output_count,
            source_dust_output_count,
            source_input_count,
            distinct_input_addresses: 1,
            source_age_blocks: 3,
            source_fee_rate: 2.0,
            source_addr_known: false,
            source_is_exchange: None,
            source_addr_reused: false,
            source_output_fan_out,
            block_height: 800_000,
            age_blocks: 3,
            prev_spend_attempts: 0,
            wallet_total_utxo_count: 5,
            other_utxos_same_sender: 0,
        }
    }

    #[test]
    fn returns_zero_when_output_count_below_3() {
        let h = SprayPatternHeuristic;
        // output_count = 2, dust = 2 — guard fires on output_count
        let score = h.evaluate(&dummy_utxo(), &ctx(2, 2, 1, 20));
        assert_eq!(score, 0.0);
    }

    #[test]
    fn returns_zero_when_dust_output_count_below_2() {
        let h = SprayPatternHeuristic;
        // output_count = 5, dust = 1 — guard fires on dust_output_count
        let score = h.evaluate(&dummy_utxo(), &ctx(5, 1, 1, 20));
        assert_eq!(score, 0.0);
    }

    #[test]
    fn high_score_for_clear_spray_pattern() {
        let h = SprayPatternHeuristic;
        // 20 outputs, 18 dust (90% ratio), fan-out 20, 20 outputs / 1 input
        // signal_dust=1.0, signal_fanout=1.0, signal_io=1.0 → score=1.0
        let score = h.evaluate(&dummy_utxo(), &ctx(20, 18, 1, 20));
        assert_eq!(score, 1.0);
    }

    #[test]
    fn moderate_score_for_borderline_case() {
        let h = SprayPatternHeuristic;
        // 5 outputs, 3 dust (60% ratio → 0.7), fan-out 5 → 0.4, 5/1=5.0 → 0.6
        // mean = (0.7 + 0.4 + 0.6) / 3 = 0.5667
        let score = h.evaluate(&dummy_utxo(), &ctx(5, 3, 1, 5));
        let expected = (0.7_f32 + 0.4 + 0.6) / 3.0;
        assert!((score - expected).abs() < 1e-5, "score={score}, expected={expected}");
    }
}
