pub mod change_address;
pub mod multi_address;
pub mod exact_floor;

use crate::utxo::dust_policies::{SuspicionScore, UtxoContext};
use crate::utxo::utxo_parser::Utxo;

/// Every heuristic implements this trait.
/// `evaluate` returns a raw signal in [0.0, 1.0] — 0 means no suspicion,
/// 1 means maximum suspicion for this signal.
/// The weight controls how much this heuristic contributes to the final score.
pub trait DustHeuristic {
    fn name(&self) -> &'static str;
    fn weight(&self) -> f32;
    fn evaluate(&self, utxo: &Utxo, ctx: &UtxoContext) -> f32;
}

/// Runs all registered heuristics and returns a combined SuspicionScore.
/// Final score = sum(signal * weight) / sum(weights), clamped to [0.0, 1.0].
pub fn aggregate(
    utxo: &Utxo,
    ctx: &UtxoContext,
    heuristics: &[&dyn DustHeuristic],
) -> SuspicionScore {
    let mut weighted_sum = 0.0f32;
    let mut total_weight = 0.0f32;
    let mut reasons = Vec::new();

    for h in heuristics {
        let signal = h.evaluate(utxo, ctx).clamp(0.0, 1.0);
        let w = h.weight();
        weighted_sum += signal * w;
        total_weight += w;
        if signal > 0.0 {
            reasons.push(format!(
                "{} (signal={:.2}, weight={:.2})",
                h.name(),
                signal,
                w
            ));
        }
    }

    let score = if total_weight > 0.0 {
        (weighted_sum / total_weight).clamp(0.0, 1.0)
    } else {
        0.0
    };

    SuspicionScore { score, reasons }
}
