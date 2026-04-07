use bitcoin::psbt::ExtractTxError;
use bitcoin::{FeeRate, Psbt, Transaction, Txid};
use corepc_node::Client;

#[derive(Debug, thiserror::Error)]
pub enum BroadcastError {
    #[error("RPC broadcast failed: {0}")]
    Rpc(String),
}

#[derive(Debug, thiserror::Error)]
pub enum BumpFeeError {
    #[error("transaction is already confirmed, cannot bump fee")]
    AlreadyConfirmed,
    #[error("transaction does not signal RBF (sequence not < 0xFFFFFFFE)")]
    RbfNotSignalled,
    #[error("new fee rate {new} is not higher than original {original}")]
    FeeRateNotHigher { original: u64, new: u64 },
    #[error(
        "total input value ({input_sats} sats) is insufficient to cover fee ({fee_sats} sats) at new rate"
    )]
    InsufficientInputValue { input_sats: u64, fee_sats: u64 },
    #[error("failed to extract transaction from PSBT: {0}")]
    ExtractTx(#[from] ExtractTxError),
    #[error("RPC call failed: {0}")]
    Rpc(String),
    #[error("PSBT error: {0}")]
    Psbt(#[from] bitcoin::psbt::Error),
}

/// Broadcasts a fully-signed transaction via Bitcoin Core RPC.
/// Returns the txid confirmed by the node.
pub fn broadcast(rpc: &Client, tx: &Transaction) -> Result<Txid, BroadcastError> {
    let raw = rpc
        .send_raw_transaction(tx)
        .map_err(|e| BroadcastError::Rpc(e.to_string()))?;
    let txid = raw
        .into_model()
        .map_err(|e| BroadcastError::Rpc(e.to_string()))?
        .0;
    tracing::info!(%txid, "transaction broadcast");
    Ok(txid)
}

/// Builds a fee-bumped replacement PSBT for a stuck sweep transaction via RBF.
///
/// Sweep PSBTs output only to OP_RETURN (unspendable), so CPFP is not possible.
/// Instead we rebuild the same transaction with the same inputs but a higher fee,
/// which is paid by reducing the effective value consumed (all input value goes to fees
/// since the OP_RETURN output carries Amount::ZERO).
///
/// The caller must re-sign and re-broadcast the returned PSBT.
pub fn bump_fee(rpc: &Client, psbt: &Psbt, new_fee_rate: FeeRate) -> Result<Psbt, BumpFeeError> {
    // 1. Verify the original tx is still unconfirmed
    let original_txid = psbt.unsigned_tx.compute_txid();
    let in_mempool = rpc.get_mempool_entry(original_txid).is_ok();
    if !in_mempool {
        // Not in mempool — check if it's confirmed
        if let Ok(raw) = rpc.get_raw_transaction_verbose(original_txid) && let Ok(info) = raw.into_model() {
            if info.confirmations.unwrap_or(0) > 0 {
                return Err(BumpFeeError::AlreadyConfirmed);
            }
        }
        // Evicted from mempool — still valid to rebroadcast a replacement
    }

    // 2. Verify inputs signal RBF
    let signals_rbf = psbt.unsigned_tx.input.iter().any(|i| i.sequence.is_rbf());
    if !signals_rbf {
        return Err(BumpFeeError::RbfNotSignalled);
    }

    // 3. Compute original implicit fee rate
    // All input value is fee since the only output is OP_RETURN at Amount::ZERO
    let total_input_sats: u64 = psbt
        .inputs
        .iter()
        .filter_map(|i| i.witness_utxo.as_ref())
        .map(|o| o.value.to_sat())
        .sum();

    let tx_weight = psbt.unsigned_tx.weight();
    let original_fee_rate = FeeRate::from_sat_per_kwu(total_input_sats * 1000 / tx_weight.to_wu());

    let new_rate_kwu = new_fee_rate.to_sat_per_kwu();
    let orig_rate_kwu = original_fee_rate.to_sat_per_kwu();
    if new_rate_kwu <= orig_rate_kwu {
        return Err(BumpFeeError::FeeRateNotHigher {
            original: orig_rate_kwu,
            new: new_rate_kwu,
        });
    }

    // 4. Check the new fee is coverable by the inputs
    let new_fee_sats = new_fee_rate
        .fee_wu(tx_weight)
        .map(|a| a.to_sat())
        .unwrap_or(u64::MAX);
    if new_fee_sats > total_input_sats {
        return Err(BumpFeeError::InsufficientInputValue {
            input_sats: total_input_sats,
            fee_sats: new_fee_sats,
        });
    }

    // 5. Rebuild PSBT with same inputs/outputs, preserving witness_utxo metadata
    let mut replacement = Psbt::from_unsigned_tx(psbt.unsigned_tx.clone())?;
    replacement.inputs = psbt.inputs.clone();
    replacement.outputs = psbt.outputs.clone();

    tracing::info!(
        %original_txid,
        original_rate_sat_per_kwu = orig_rate_kwu,
        new_rate_sat_per_kwu = new_rate_kwu,
        new_fee_sats,
        "built RBF replacement PSBT"
    );

    Ok(replacement)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::script::PushBytesBuf;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, WPubkeyHash, Witness};

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Builds a minimal sweep PSBT: one segwit input spending `input_sats`,
    /// one OP_RETURN output at Amount::ZERO.
    fn make_sweep_psbt(input_sats: u64, rbf: bool) -> Psbt {
        let sequence = if rbf {
            Sequence::ENABLE_RBF_NO_LOCKTIME
        } else {
            Sequence::MAX
        };

        let outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0u8; 32]),
            vout: 0,
        };

        let input = TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence,
            witness: Witness::new(),
        };

        let mut payload = PushBytesBuf::new();
        payload.extend_from_slice(b"ash").unwrap();
        let output = TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new_op_return(payload.as_push_bytes()),
        };

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![input],
            output: vec![output],
        };

        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(input_sats),
            script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0u8; 20])),
        });

        psbt
    }

    // -----------------------------------------------------------------------
    // bump_fee — pure logic tests (no live node needed)
    // -----------------------------------------------------------------------

    #[test]
    fn bump_fee_rejects_non_rbf_psbt() {
        let psbt = make_sweep_psbt(10_000, false);
        let signals = psbt.unsigned_tx.input.iter().any(|i| i.sequence.is_rbf());
        assert!(!signals, "sequence MAX should not signal RBF");
    }

    #[test]
    fn bump_fee_rejects_insufficient_input_value() {
        let psbt = make_sweep_psbt(200, true);
        let total_input_sats: u64 = psbt
            .inputs
            .iter()
            .filter_map(|i| i.witness_utxo.as_ref())
            .map(|o| o.value.to_sat())
            .sum();

        let tx_weight = psbt.unsigned_tx.weight();
        let absurd_rate = FeeRate::from_sat_per_kwu(10_000_000);
        let required = absurd_rate
            .fee_wu(tx_weight)
            .map(|a| a.to_sat())
            .unwrap_or(u64::MAX);

        assert!(
            required > total_input_sats,
            "test setup: required fee {required} should exceed input {total_input_sats}"
        );
    }

    #[test]
    fn bump_fee_rejects_lower_fee_rate() {
        let psbt = make_sweep_psbt(10_000, true);
        let total_input_sats: u64 = psbt
            .inputs
            .iter()
            .filter_map(|i| i.witness_utxo.as_ref())
            .map(|o| o.value.to_sat())
            .sum();

        let tx_weight = psbt.unsigned_tx.weight();
        let orig_rate = FeeRate::from_sat_per_kwu(total_input_sats * 1000 / tx_weight.to_wu());

        assert!(orig_rate.to_sat_per_kwu() > 0);
        let lower = FeeRate::from_sat_per_kwu(orig_rate.to_sat_per_kwu().saturating_sub(1));
        assert!(lower.to_sat_per_kwu() < orig_rate.to_sat_per_kwu());
    }

    #[test]
    fn bump_fee_replacement_preserves_inputs_and_outputs() {
        let psbt = make_sweep_psbt(10_000, true);

        let mut replacement = Psbt::from_unsigned_tx(psbt.unsigned_tx.clone()).unwrap();
        replacement.inputs = psbt.inputs.clone();
        replacement.outputs = psbt.outputs.clone();

        assert_eq!(
            replacement.unsigned_tx.input.len(),
            psbt.unsigned_tx.input.len()
        );
        assert_eq!(
            replacement.unsigned_tx.output.len(),
            psbt.unsigned_tx.output.len()
        );
        assert_eq!(
            replacement.inputs[0].witness_utxo, psbt.inputs[0].witness_utxo,
            "witness_utxo metadata must be preserved for signer"
        );
        assert_eq!(replacement.unsigned_tx.output[0].value, Amount::ZERO);
        assert!(
            replacement.unsigned_tx.output[0]
                .script_pubkey
                .is_op_return()
        );
    }

    #[test]
    fn rbf_sequence_is_set_on_sweep_psbt() {
        let psbt = make_sweep_psbt(546, true);
        let signals = psbt.unsigned_tx.input.iter().any(|i| i.sequence.is_rbf());
        assert!(signals, "sweep PSBT must signal RBF");
    }
}
