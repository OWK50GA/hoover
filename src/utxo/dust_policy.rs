use bdk_wallet::KeychainKind;
use bitcoin::AddressType;

use crate::utxo::utxo_parser::Utxo;

pub struct UtxoContext {
    // --- User Address provenance ---
    pub address_type: AddressType,
    pub keychain: KeychainKind, // external (shared) or Internal (change)
    pub derivation_index: u32,  // How deep into the keychain
    pub address_ever_shared: bool, // Whether address has been published publicly
    pub times_address_received: u32, // How often the address has received outputs

    // --- Sending tx props
    pub source_output_count: u32, // Total no of outputs in sending tx
    pub source_dust_output_count: u32, // How many of the outputs are dust-sized
    pub source_input_count: u32,  // No of inputs in the sending tx
    pub distinct_input_addresses: u32, // Distince input address
    pub source_age_blocks: u32,   // No of confirmations since sending tx
    pub source_fee_rate: f64,

    // --- Sender address props
    pub source_addr_known: bool, // Whether user recognizes the address
    pub source_is_exchange: Option<bool>, // If identifiable, is it an exchange?
    pub source_addr_reused: bool, // Has the address been used often
    pub source_output_fan_out: u32, // How many addresses the sender reached in the tx

    // --- UTXO History ---
    pub block_height: u32,        // When utxo was confirmed
    pub age_blocks: u32,          // How old UTXO is now
    pub prev_spend_attempts: u32, // Has wallet tried and failed to spend this?

    // --- Wallet context ---
    pub wallet_total_utxo_count: u32, // How many UTXOs the wallet has in total
    pub other_utxos_same_sender: u32, // How many UTXOs came from same sender
}
pub struct HeuristicDustPolicy {
    pub fee_rate_sat_per_vb: f64,
    pub suspicion_threshold: f32, // 0.0 to 1/0 - how suspicious to flag
}

pub struct SuspicionScore {
    pub score: f32,           // 0.0 = definitely legit, 1.0 = almost certainly an attack
    pub reasons: Vec<String>, // human-readable explanations
}

impl HeuristicDustPolicy {
    pub fn score(&self, _utxo: Utxo, _context: &UtxoContext) -> SuspicionScore {
        let reasons = vec![String::from("Because I said so")];
        SuspicionScore {
            score: 1.0,
            reasons,
        }
    }

    pub fn is_dust(&self, utxo: Utxo, context: &UtxoContext) -> bool {
        self.score(utxo, context).score >= self.suspicion_threshold
    }
}
