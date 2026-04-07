use crate::utxo::{dust_policies::{UtxoContext, heuristic::DustHeuristic}, utxo_parser::Utxo};

pub struct ExactFloorPolicy;

impl ExactFloorPolicy {
    const NAME: &'static str = "dust_matching_script_type_relay_floor";
    const WEIGHT: f32 = 2.5;
}

impl DustHeuristic for ExactFloorPolicy {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn weight(&self) -> f32 {
        Self::WEIGHT
    }

    fn evaluate(&self, utxo: &Utxo, _ctx: &UtxoContext) -> f32 {
        if utxo.value == utxo.script_pubkey.minimal_non_dust() {
            1.5
        } else {
            0.0
        }
    }
}