use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::str::FromStr;
use std::{fs, io};

use crate::utxo::utxo_parser::DustUtxo;
use bitcoin::absolute::LockTime;
use bitcoin::base64::prelude::BASE64_STANDARD;
use bitcoin::base64::{self, Engine};
use bitcoin::psbt::{self, PsbtParseError};
use bitcoin::script::{PushBytesBuf, PushBytesError};
use bitcoin::transaction::Version;
use bitcoin::{Amount, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

#[derive(Debug, thiserror::Error)]
pub enum PsbtError {
    #[error("failed to parse psbt: {0}")]
    Psbt(#[from] PsbtParseError),
    #[error("failed to push bytes: {0}")]
    PushBytesBuf(#[from] PushBytesError),
    #[error("failed to unwrap psbt: {0}")]
    PsbtResult(#[from] psbt::Error),
    #[error("non-witness input not supported: {0}")]
    NonWitnessInput(String),
    #[error("Failed to read file contents: {0}")]
    IoError(#[from] io::Error),
    #[error("Failed to decode base64: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("Input {0} is not finalized - missing signature")]
    NotFinalized(usize),
    #[error("Failed to extract transaction: {0}")]
    ExtractTx(#[from] psbt::ExtractTxError),
}

pub fn build_sweep_psbt(utxos: &[DustUtxo]) -> Result<Psbt, PsbtError> {
    let mut inputs = Vec::new();
    for dust_utxo in utxos {
        let current_input = TxIn {
            previous_output: dust_utxo.utxo.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        };

        inputs.push(current_input);
    }

    let mut outputs = Vec::new();

    let mut payload = PushBytesBuf::new();
    payload.extend_from_slice(b"ash")?;

    let op_return_output = TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::new_op_return(payload.as_push_bytes()),
    };

    outputs.push(op_return_output);

    let tx = Transaction {
        input: inputs,
        output: outputs,
        version: Version::TWO,
        lock_time: LockTime::ZERO,
    };

    let mut psbt = Psbt::from_unsigned_tx(tx)?;

    for (i, item) in utxos.iter().enumerate() {
        let script_pubkey = &item.utxo.script_pubkey;

        if script_pubkey.is_witness_program() {
            psbt.inputs[i].witness_utxo = Some(TxOut {
                value: item.utxo.value,
                script_pubkey: script_pubkey.clone(),
            })
        } else {
            return Err(PsbtError::NonWitnessInput(format!(
                "Outpoint {} has non-witness script_pubkey",
                item.utxo.outpoint
            )));
        }
    }

    // let string_psbt = psbt.serialize();

    // Ok(BASE64_STANDARD.encode(string_psbt))
    Ok(psbt)
}

pub fn read_psbt_file(path: &Path) -> Result<Psbt, PsbtError> {
    let base64_str = fs::read_to_string(path)?;
    let bytes = BASE64_STANDARD.decode(base64_str)?;
    let psbt = Psbt::deserialize(&bytes)?;

    Ok(psbt)
}

pub fn write_psbt_file(psbt: &Psbt, path: &Path) -> Result<(), io::Error> {
    let mut file = File::create(path)?;
    let psbt_base64 = BASE64_STANDARD.encode(psbt.serialize());
    write!(file, "{psbt_base64}")?;

    Ok(())
}

pub fn finalize_psbt(psbt: Psbt) -> Result<Transaction, PsbtError> {
    for (i, input) in psbt.inputs.iter().enumerate() {
        if input.final_script_witness.is_none() && input.final_script_sig.is_none() {
            return Err(PsbtError::NotFinalized(i));
        }
    }

    psbt.extract_tx().map_err(PsbtError::ExtractTx)
}

pub fn parse_psbt(s: &str) -> Result<Psbt, PsbtError> {
    Ok(Psbt::from_str(s)?)
}
