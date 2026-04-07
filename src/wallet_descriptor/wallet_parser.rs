use bdk_wallet::{bitcoin::Network, descriptor::IntoWalletDescriptor, wallet_name_from_descriptor};
use bitcoin::secp256k1::Secp256k1;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedDescriptor {
    /// Deterministic wallet name derived from the descriptor.
    pub wallet_name: String,
    /// The network this descriptor belongs to.
    pub network: Network,
    /// The original external/receive descriptor string.
    pub descriptor_str: String,
    /// Optional internal/change descriptor string.
    pub change_descriptor_str: Option<String>,
    /// Start height records the start_height, so that it would be easier to scan
    #[serde(default)]
    pub start_height: u32,
    /// Unix timestamp (seconds) when this descriptor was first registered.
    pub registered_at: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum DescriptorError {
    #[error("invalid descriptor: {0}")]
    Invalid(String),
    #[error("descriptor name derivation failed: {0}")]
    NameDerivation(String),
}

/// Parses and validates a Bitcoin output descriptor using BDK.
///
/// - `descriptor`        — external/receive descriptor (e.g. `wpkh(xpub.../0/*)`)
/// - `change_descriptor` — optional internal/change descriptor (e.g. `wpkh(xpub.../1/*)`)
/// - `network`           — expected Bitcoin network
///
/// Validates both descriptors against the network, then derives a stable
/// wallet name (fingerprint) via `bdk_wallet::wallet_name_from_descriptor`.
pub fn parse_descriptor(
    descriptor: &str,
    change_descriptor: Option<&str>,
    network: Network,
    start_height: u32
) -> Result<ParsedDescriptor, DescriptorError> {
    let secp = Secp256k1::new();

    // Validate the external descriptor. IntoWalletDescriptor is implemented
    // for &str in bdk_wallet — it parses, checksums, and network-checks the descriptor.
    descriptor
        .into_wallet_descriptor(&secp, network)
        .map_err(|e| DescriptorError::Invalid(e.to_string()))?;

    // Validate change descriptor if provided.
    if let Some(change) = change_descriptor {
        change
            .into_wallet_descriptor(&secp, network)
            .map_err(|e| DescriptorError::Invalid(format!("change descriptor: {e}")))?;
    }

    // Derive a deterministic wallet name from the descriptor(s).
    // This hashes the descriptor keys and produces a stable hex-like identifier.
    let wallet_name = wallet_name_from_descriptor(descriptor, change_descriptor, network, &secp)
        .map_err(|e| DescriptorError::NameDerivation(e.to_string()))?;

    Ok(ParsedDescriptor {
        wallet_name,
        network,
        descriptor_str: descriptor.to_string(),
        change_descriptor_str: change_descriptor.map(str::to_string),
        registered_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        start_height
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real testnet descriptors sourced from BDK's own test suite.
    const WPKH_EXTERNAL: &str = "wpkh(tprv8ZgxMBicQKsPdcAqYBpzAFwU5yxBUo88ggoBqu1qPcHUfSbKK1sKMLmC7EAk438btHQrSdu3jGGQa6PA71nvH5nkDexhLteJqkM4dQmWF9g/84'/1'/0'/0/*)";

    // BIP-86 taproot (tr) testnet descriptors — key-path spend only, x-only pubkeys.
    const TR_EXTERNAL: &str = "tr([73c5da0a/86'/1'/0']tprv8fMn4hSKPRC1oaCPqxDb1JWtgkpeiQvZhsr8W2xuy3GEMkzoArcAWTfJxYb6Wj8XNNDWEjfYKK4wGQXh3ZUXhDF2NcnsALpWTeSwarJt7Vc/0/*)";
    const TR_INTERNAL: &str = "tr([73c5da0a/86'/1'/0']tprv8fMn4hSKPRC1oaCPqxDb1JWtgkpeiQvZhsr8W2xuy3GEMkzoArcAWTfJxYb6Wj8XNNDWEjfYKK4wGQXh3ZUXhDF2NcnsALpWTeSwarJt7Vc/1/*)";

    #[test]
    fn rejects_invalid_descriptor() {
        let result = parse_descriptor("not_a_descriptor", None, Network::Testnet, 0);
        assert!(result.is_err());
    }

    #[test]
    fn wpkh_wallet_name_is_deterministic() {
        let r1 = parse_descriptor(WPKH_EXTERNAL, None, Network::Testnet, 481_824).unwrap();
        let r2 = parse_descriptor(WPKH_EXTERNAL, None, Network::Testnet, 481_824).unwrap();
        assert_eq!(r1.wallet_name, r2.wallet_name);
    }

    #[test]
    fn taproot_descriptor_is_accepted() {
        // tr() descriptors must parse and validate without error.
        let result = parse_descriptor(TR_EXTERNAL, None, Network::Testnet, 481_824);
        assert!(
            result.is_ok(),
            "taproot descriptor rejected: {:?}",
            result.err()
        );
    }

    #[test]
    fn taproot_wallet_name_is_deterministic() {
        let r1 = parse_descriptor(TR_EXTERNAL, None, Network::Testnet, 481_824).unwrap();
        let r2 = parse_descriptor(TR_EXTERNAL, None, Network::Testnet, 481_824).unwrap();
        assert_eq!(r1.wallet_name, r2.wallet_name);
    }

    #[test]
    fn taproot_with_change_descriptor() {
        // Both external and internal tr() descriptors should be accepted together.
        let result = parse_descriptor(TR_EXTERNAL, Some(TR_INTERNAL), Network::Testnet, 481_824);
        assert!(
            result.is_ok(),
            "taproot with change descriptor rejected: {:?}",
            result.err()
        );
        let parsed = result.unwrap();
        assert_eq!(parsed.change_descriptor_str, Some(TR_INTERNAL.to_string()));
    }

    #[test]
    fn taproot_and_wpkh_produce_different_wallet_names() {
        let tr = parse_descriptor(TR_EXTERNAL, None, Network::Testnet, 481_824).unwrap();
        let wpkh = parse_descriptor(WPKH_EXTERNAL, None, Network::Testnet, 481_824).unwrap();
        assert_ne!(tr.wallet_name, wpkh.wallet_name);
    }
}
