use std::path::Path;

use bdk_redb::redb::{
    CommitError, Database, DatabaseError, ReadableTable, StorageError as RedbStorageError,
    TableDefinition, TableError, TransactionError,
};

use crate::{utxo::utxo_parser::DustUtxo, wallet_descriptor::wallet_parser::ParsedDescriptor};

/// Descriptors table: fingerprint (str) → JSON-encoded DescriptorRecord
const DESCRIPTORS: TableDefinition<&str, &[u8]> = TableDefinition::new("descriptors");

/// Dust UTXOs table: "txid:vout" (str) → JSON-encoded DustUtxo
const DUST_UTXOS: TableDefinition<&str, &[u8]> = TableDefinition::new("dust_utxos");

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("failed to open database: {0}")]
    Database(#[from] DatabaseError),
    #[error("failed to begin transaction: {0}")]
    Transaction(Box<TransactionError>),
    #[error("failed to open table: {0}")]
    Table(#[from] TableError),
    #[error("failed to commit transaction: {0}")]
    Commit(#[from] CommitError),
    #[error("serialisation error: {0}")]
    Serialise(#[from] serde_json::Error),
    #[error("redb storage error: {0}")]
    RedbStorage(#[from] RedbStorageError),
}

impl From<TransactionError> for StorageError {
    fn from(e: TransactionError) -> Self {
        StorageError::Transaction(Box::new(e))
    }
}

#[derive(Debug)]
pub struct Store {
    db: Database,
}

impl Store {
    /// Opens the redb database at `path`, creating it if it doesn't exist.
    /// Ensures both application tables exist before returning.
    pub fn open(path: &Path) -> Result<Self, Box<StorageError>> {
        let db = Database::create(path).expect("Failed to create database");

        // Single write transaction to initialise tables on a fresh db.
        // open_table is a no-op if the table already exists.
        let write_tx = db.begin_write().expect("Failed to begin write");
        {
            write_tx
                .open_table(DESCRIPTORS)
                .expect("Failed to open table");
            write_tx
                .open_table(DUST_UTXOS)
                .expect("Failed to open table");
        }
        write_tx.commit().expect("Failed to commit db tx");

        Ok(Self { db })
    }

    pub fn upsert_descriptor(
        &self,
        parsed_descriptor: &ParsedDescriptor,
    ) -> Result<(), StorageError> {
        // Read the existing record first so we can preserve registered_at on update.
        let existing = {
            let read_tx = self.db.begin_read()?;
            let table = read_tx.open_table(DESCRIPTORS)?;
            match table.get(parsed_descriptor.wallet_name.as_str())? {
                Some(guard) => {
                    let existing: ParsedDescriptor = serde_json::from_slice(guard.value())?;
                    Some(existing)
                }
                None => None,
            }
        };

        // Build the record to write, preserving registered_at if it already exists.
        let to_write = ParsedDescriptor {
            registered_at: existing
                .map(|e| e.registered_at)
                .unwrap_or(parsed_descriptor.registered_at),
            ..parsed_descriptor.clone()
        };

        let write_tx = self.db.begin_write()?;
        {
            let mut table = write_tx.open_table(DESCRIPTORS)?;
            let bytes = serde_json::to_vec(&to_write)?;
            table.insert(to_write.wallet_name.as_str(), bytes.as_slice())?;
        }
        write_tx.commit()?;
        Ok(())
    }

    pub fn upsert_utxos(&self, utxos: &[DustUtxo]) -> Result<(), StorageError> {
        let write_tx = self.db.begin_write()?;
        {
            let mut table = write_tx.open_table(DUST_UTXOS)?;
            for utxo in utxos {
                let key = format!("{}:{}", utxo.utxo.outpoint.txid, utxo.utxo.outpoint.vout);
                let dust_utxo_vec = serde_json::to_vec(&utxo)?;
                table.insert(key.as_str(), dust_utxo_vec.as_slice())?;
            }
        }
        write_tx.commit()?;
        Ok(())
    }

    pub fn load_descriptors(&self) -> Result<Vec<ParsedDescriptor>, StorageError> {
        let read_tx = self.db.begin_read()?;
        let table = read_tx.open_table(DESCRIPTORS)?;

        // range(..) with an unbounded range iterates every entry in the table.
        // Each item is a Result<(AccessGuard<&str>, AccessGuard<&[u8]>), StorageError>.
        let mut descriptors = Vec::new();
        for entry in table.range::<&str>(..)? {
            let (_, value) = entry?;
            let descriptor: ParsedDescriptor = serde_json::from_slice(value.value())?;
            descriptors.push(descriptor);
        }

        Ok(descriptors)
    }

    pub fn load_dust_utxos(&self) -> Result<Vec<DustUtxo>, StorageError> {
        let read_tx = self.db.begin_read()?;
        let table = read_tx.open_table(DUST_UTXOS)?;

        let mut dust_utxos = Vec::new();
        for entry in table.range::<&str>(..)? {
            let (_, value) = entry?;
            let utxo: DustUtxo = serde_json::from_slice(value.value())?;
            if !utxo.is_spent {
                dust_utxos.push(utxo);
            }
        }

        Ok(dust_utxos)
    }

    pub fn mark_utxos_spent(&self, outpoints: &[bitcoin::OutPoint]) -> Result<(), StorageError> {
        let write_tx = self.db.begin_write()?;
        {
            let mut table = write_tx.open_table(DUST_UTXOS)?;
            for outpoint in outpoints {
                let key = format!("{}:{}", outpoint.txid, outpoint.vout);
                let existing = table.get(key.as_str())?.map(|g| g.value().to_vec());
                if let Some(bytes) = existing {
                    let mut utxo: DustUtxo = serde_json::from_slice(&bytes)?;
                    utxo.is_spent = true;
                    let updated = serde_json::to_vec(&utxo)?;
                    table.insert(key.as_str(), updated.as_slice())?;
                }
            }
        }
        write_tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet_descriptor::wallet_parser::parse_descriptor;
    use bitcoin::Network;
    use tempfile::tempdir;

    // Real BDK testnet descriptors used across tests.
    const TR_EXTERNAL: &str = "tr([73c5da0a/86'/1'/0']tprv8fMn4hSKPRC1oaCPqxDb1JWtgkpeiQvZhsr8W2xuy3GEMkzoArcAWTfJxYb6Wj8XNNDWEjfYKK4wGQXh3ZUXhDF2NcnsALpWTeSwarJt7Vc/0/*)";
    const WPKH_EXTERNAL: &str = "wpkh(tprv8ZgxMBicQKsPdcAqYBpzAFwU5yxBUo88ggoBqu1qPcHUfSbKK1sKMLmC7EAk438btHQrSdu3jGGQa6PA71nvH5nkDexhLteJqkM4dQmWF9g/84'/1'/0'/0/*)";

    fn parsed(descriptor: &str) -> ParsedDescriptor {
        parse_descriptor(descriptor, None, Network::Testnet, 481_824).unwrap()
    }

    #[test]
    fn open_creates_db_and_tables() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.db");
        // Should not error — creates the file and initialises both tables.
        assert!(Store::open(&path).is_ok());
        // File must exist on disk after open.
        assert!(path.exists());
    }

    #[test]
    fn open_is_idempotent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.db");
        // Opening the same path twice must not error.
        Store::open(&path).unwrap();
        assert!(Store::open(&path).is_ok());
    }

    #[test]
    fn upsert_and_load_single_descriptor() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.db")).unwrap();
        let descriptor = parsed(WPKH_EXTERNAL);

        store.upsert_descriptor(&descriptor).unwrap();

        let loaded = store.load_descriptors().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].wallet_name, descriptor.wallet_name);
        assert_eq!(loaded[0].descriptor_str, descriptor.descriptor_str);
    }

    #[test]
    fn upsert_is_idempotent() {
        // Upserting the same descriptor twice must not duplicate it.
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.db")).unwrap();
        let descriptor = parsed(WPKH_EXTERNAL);

        store.upsert_descriptor(&descriptor).unwrap();
        store.upsert_descriptor(&descriptor).unwrap();

        let loaded = store.load_descriptors().unwrap();
        assert_eq!(loaded.len(), 1);
    }

    #[test]
    fn upsert_multiple_descriptors() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.db")).unwrap();

        store.upsert_descriptor(&parsed(WPKH_EXTERNAL)).unwrap();
        store.upsert_descriptor(&parsed(TR_EXTERNAL)).unwrap();

        let loaded = store.load_descriptors().unwrap();
        assert_eq!(loaded.len(), 2);
    }

    #[test]
    fn load_descriptors_empty_store() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.db")).unwrap();
        let loaded = store.load_descriptors().unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn data_persists_across_store_instances() {
        // Close the store and reopen it — data must survive.
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.db");
        let descriptor = parsed(WPKH_EXTERNAL);

        {
            let store = Store::open(&path).unwrap();
            store.upsert_descriptor(&descriptor).unwrap();
        } // store dropped here, db closed

        let store2 = Store::open(&path).unwrap();
        let loaded = store2.load_descriptors().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].wallet_name, descriptor.wallet_name);
    }

    #[test]
    fn mark_utxos_spent_updates_flag() {
        use crate::utxo::utxo_parser::{DustReason, DustUtxo, Utxo};
        use bitcoin::{Amount, ScriptBuf};
        use bitcoin::{OutPoint, Txid, hashes::Hash};

        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.db")).unwrap();

        let outpoint = OutPoint {
            txid: Txid::all_zeros(),
            vout: 0,
        };
        let dust = DustUtxo {
            utxo: Utxo {
                outpoint,
                value: Amount::from_sat(300),
                script_pubkey: ScriptBuf::new(),
                block_height: 800_000,
                descriptor_fingerprint: "deadbeef".to_string(),
            },
            reason: DustReason::BelowDustLimit {
                threshold_sats: 546,
            },
            is_spent: false,
            suspicion_score: None,
            suspicion_reasons: vec![]
        };

        store.upsert_utxos(&[dust]).unwrap();
        assert_eq!(store.load_dust_utxos().unwrap().len(), 1);

        store.mark_utxos_spent(&[outpoint]).unwrap();

        // load_dust_utxos filters out spent — should be empty now
        assert!(store.load_dust_utxos().unwrap().is_empty());
    }

    #[test]
    fn registered_at_preserved_on_update() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.db")).unwrap();
        let descriptor = parsed(WPKH_EXTERNAL);

        store.upsert_descriptor(&descriptor).unwrap();
        let original_ts = store.load_descriptors().unwrap()[0].registered_at;

        // Re-register with a different timestamp (simulating a later call)
        let mut updated = parsed(WPKH_EXTERNAL);
        updated.registered_at = original_ts + 9999;
        store.upsert_descriptor(&updated).unwrap();

        let loaded = store.load_descriptors().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            loaded[0].registered_at, original_ts,
            "registered_at must not change on re-registration"
        );
    }
}
