use bdk_bitcoind_rpc::bitcoincore_rpc::{Client, RpcApi};
use bitcoin::{BlockHash, Txid};

#[derive(Debug, thiserror::Error)]
pub enum MonitorError {
    #[error("RPC call failed: {0}")]
    Rpc(String),
}

#[derive(Debug)]
pub enum TxStatus {
    /// In mempool, not yet mined
    Unconfirmed,
    /// Mined with `confirmations` blocks on top, in `block_hash`
    Confirmed {
        confirmations: u32,
        block_hash: BlockHash,
    },
}

/// Queries Bitcoin Core for the current status of a transaction.
pub fn tx_status(rpc: &Client, txid: &Txid) -> Result<TxStatus, MonitorError> {
    let info = rpc
        .get_raw_transaction_info(txid, None)
        .map_err(|e| MonitorError::Rpc(e.to_string()))?;

    let status = match info.confirmations {
        None | Some(0) => TxStatus::Unconfirmed,
        Some(confs) => TxStatus::Confirmed {
            confirmations: confs,
            block_hash: info
                .blockhash
                .expect("blockhash present when confirmations > 0"),
        },
    };

    tracing::debug!(%txid, ?status, "tx status checked");
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client as BdkClient};
    use bitcoin::hashes::Hash;

    fn bdk_client(node: &corepc_node::Node) -> BdkClient {
        let url = format!("http://{}", node.params.rpc_socket);
        BdkClient::new(&url, Auth::CookieFile(node.params.cookie_file.clone()))
            .expect("failed to create bdk rpc client")
    }

    fn start_node() -> corepc_node::Node {
        let exe = corepc_node::exe_path().expect("bitcoind not found on PATH");
        let mut conf = corepc_node::Conf::default();
        conf.args.push("-fallbackfee=0.0001");
        corepc_node::Node::with_conf(exe, &conf).expect("failed to start node")
    }

    fn start_node_with_txindex() -> corepc_node::Node {
        let exe = corepc_node::exe_path().expect("bitcoind not found on PATH");
        let mut conf = corepc_node::Conf::default();
        conf.args.push("-fallbackfee=0.0001");
        conf.args.push("-txindex=1");
        corepc_node::Node::with_conf(exe, &conf).expect("failed to start node")
    }

    #[test]
    fn tx_status_unconfirmed() {
        let node = start_node();
        let wallet = node.create_wallet("test").unwrap();
        let rpc = bdk_client(&node);

        let addr = wallet.new_address().unwrap();
        wallet.generate_to_address(101, &addr).unwrap();

        let dest = wallet.new_address().unwrap();
        let txid = wallet
            .send_to_address(&dest, bitcoin::Amount::from_sat(10_000))
            .unwrap()
            .txid()
            .unwrap();

        let status = tx_status(&rpc, &txid).expect("tx_status should succeed");
        assert!(
            matches!(status, TxStatus::Unconfirmed),
            "tx in mempool should be Unconfirmed"
        );
    }

    #[test]
    fn tx_status_confirmed() {
        let node = start_node_with_txindex();
        let wallet = node.create_wallet("test").unwrap();
        let rpc = bdk_client(&node);

        let addr = wallet.new_address().unwrap();
        wallet.generate_to_address(101, &addr).unwrap();

        let dest = wallet.new_address().unwrap();
        let txid = wallet
            .send_to_address(&dest, bitcoin::Amount::from_sat(10_000))
            .unwrap()
            .txid()
            .unwrap();

        wallet.generate_to_address(1, &addr).unwrap();

        let status = tx_status(&rpc, &txid).expect("tx_status should succeed");
        match status {
            TxStatus::Confirmed { confirmations, .. } => assert_eq!(confirmations, 1),
            TxStatus::Unconfirmed => panic!("expected Confirmed after mining a block"),
        }
    }

    #[test]
    fn tx_status_unknown_txid_errors() {
        let node = start_node();
        let rpc = bdk_client(&node);
        let fake_txid = bitcoin::Txid::from_byte_array([0xab; 32]);
        let result = tx_status(&rpc, &fake_txid);
        assert!(result.is_err(), "unknown txid should return MonitorError");
    }
}
