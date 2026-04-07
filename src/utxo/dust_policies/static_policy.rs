use bitcoin::{FeeRate, Script};

use crate::utxo::utxo_parser::Utxo;

pub struct StaticDustPolicy;

impl StaticDustPolicy {
    pub fn is_dust(&self, utxo: &Utxo) -> bool {
        let threshold = utxo.script_pubkey.minimal_non_dust();
        utxo.value < threshold
    }
}

pub struct EconomicDustPolicy {
    pub fee_rate_sat_per_vb: f64,
}

impl EconomicDustPolicy {
    pub fn is_dust(&self, utxo: &Utxo) -> bool {
        let threshold = utxo.script_pubkey.minimal_non_dust_custom(
            FeeRate::from_sat_per_vb(self.fee_rate_sat_per_vb as u64).unwrap(),
        );
        utxo.value < threshold
    }
}

pub fn input_weight_vbytes(script: &Script) -> u64 {
    if script.is_p2wpkh() {
        68
    } else if script.is_p2pkh() {
        148
    } else if script.is_p2tr() {
        58
    } else if script.is_p2sh() {
        91
    } else {
        148
    }
}

pub struct AgeDustPolicy {
    pub max_age_blocks: u32,
    pub max_fee_rate_sat_per_vb: f64, // only sweep when fees are cheap
}
