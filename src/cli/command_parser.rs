use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, Default, ValueEnum, PartialEq)]
pub enum Chain {
    #[default]
    Main,
    Testnet,
    Testnet4,
    Signet,
    Regtest,
}

/// Dust Attack UTXO Identifier — watch-only dust sweep tool
#[derive(Debug, Parser)]
#[command(name = "hoover", version, about)]
pub struct Cli {
    /// Directory to store wallet data and the redb database
    #[arg(
        short = 'd',
        long,
        env = "HOOVER_DATADIR",
        default_value = "~/.hoover",
        global = true
    )]
    pub datadir: PathBuf,

    /// Bitcoin network
    #[arg(
        short = 'c',
        long,
        env = "HOOVER_CHAIN",
        default_value = "main",
        global = true,
        value_parser = clap::value_parser!(Chain)
    )]
    pub chain: Chain,

    /// Maximum UTXO amount to treat as dust (in satoshis)
    #[arg(
        short = 'a',
        long,
        env = "HOOVER_AMOUNT",
        default_value_t = 546,
        global = true
    )]
    pub amount: u64,

    /// Filter by descriptor fingerprint (if not provided, all descriptors are used)
    #[arg(short = 'f', long, env = "HOOVER_FINGERPRINT", global = true)]
    pub fingerprint: Option<String>,

    /// Bitcoin Core RPC URL
    #[arg(
        long,
        env = "HOOVER_RPC_URL",
        default_value = "http://127.0.0.1:8332",
        global = true
    )]
    pub rpc_url: String,

    /// Bitcoin Core RPC username
    #[arg(long, env = "HOOVER_RPC_USER", global = true)]
    pub rpc_user: Option<String>,

    /// Bitcoin Core RPC password
    #[arg(long, env = "HOOVER_RPC_PASS", global = true)]
    pub rpc_pass: Option<String>,

    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short = 'v', long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Add a public key descriptor to scan for dust UTXOs
    Add {
        /// Raw output descriptor (e.g. wpkh(xpub.../0/*))
        #[arg(long, required = true)]
        descriptor: String,

        /// Change/internal descriptor (e.g. wpkh(xpub.../1/*)).
        /// Any UTXO received on a change address from an external sender
        /// is flagged as suspicious, since change addresses are never shared.
        #[arg(long)]
        change_descriptor: Option<String>,

        /// Block height to start scanning from (0 = genesis)
        #[arg(long, default_value_t = 481_824)]
        start_height: u32,
    },

    /// List all dust UTXOs for registered descriptor(s)
    List,

    /// Create PSBTs to sweep dust UTXOs to OP_RETURN
    Clean {
        /// Directory to write .psbt files (defaults to current directory)
        #[arg(short, long)]
        output_dir: Option<PathBuf>,

        /// Only sweep dust UTXOs belonging to this address.
        /// If omitted, one PSBT is created per address that has dust.
        #[arg(long)]
        address: Option<String>,
    },

    /// Broadcast a signed PSBT
    Broadcast {
        /// Path to a specific signed .psbt file to broadcast.
        /// If omitted, all .psbt files in --output-dir are broadcast.
        #[arg(short, long)]
        psbt: Option<PathBuf>,

        /// Directory to look for .psbt files when no specific file is given
        #[arg(short, long)]
        output_dir: Option<PathBuf>,
    },

    /// Check confirmation status of a broadcast transaction
    Status {
        /// Transaction ID to check
        #[arg(required = true)]
        txid: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("parse failed")
    }

    fn try_parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(args)
    }

    // --- defaults ---

    #[test]
    fn defaults_are_applied() {
        let cli = parse(&["hoover", "list"]);
        assert_eq!(cli.datadir, PathBuf::from("~/.hoover"));
        assert_eq!(cli.chain, Chain::Main);
        assert_eq!(cli.amount, 546);
        assert_eq!(cli.rpc_url, "http://127.0.0.1:8332");
        assert!(cli.fingerprint.is_none());
        assert!(cli.rpc_user.is_none());
        assert!(cli.rpc_pass.is_none());
        assert_eq!(cli.verbose, 0);
    }

    // --- global flags ---

    #[test]
    fn global_datadir_short() {
        let cli = parse(&["hoover", "-d", "/tmp/hoover", "list"]);
        assert_eq!(cli.datadir, PathBuf::from("/tmp/hoover"));
    }

    #[test]
    fn global_chain_signet() {
        let cli = parse(&["hoover", "--chain", "signet", "list"]);
        assert_eq!(cli.chain, Chain::Signet);
    }

    #[test]
    fn global_chain_invalid_rejected() {
        assert!(try_parse(&["hoover", "--chain", "mainnet", "list"]).is_err());
    }

    #[test]
    fn global_amount_override() {
        let cli = parse(&["hoover", "--amount", "1000", "list"]);
        assert_eq!(cli.amount, 1000);
    }

    #[test]
    fn global_fingerprint() {
        let cli = parse(&["hoover", "--fingerprint", "deadbeef", "list"]);
        assert_eq!(cli.fingerprint.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn global_rpc_credentials() {
        let cli = parse(&[
            "hoover",
            "--rpc-user",
            "alice",
            "--rpc-pass",
            "s3cr3t",
            "list",
        ]);
        assert_eq!(cli.rpc_user.as_deref(), Some("alice"));
        assert_eq!(cli.rpc_pass.as_deref(), Some("s3cr3t"));
    }

    #[test]
    fn verbose_count() {
        let cli = parse(&["hoover", "-vvv", "list"]);
        assert_eq!(cli.verbose, 3);
    }

    // --- subcommands ---

    #[test]
    fn add_required_descriptor() {
        let cli = parse(&["hoover", "add", "--descriptor", "wpkh(xpub123/0/*)"]);
        match cli.command {
            Commands::Add {
                descriptor,
                change_descriptor,
                start_height,
            } => {
                assert_eq!(descriptor, "wpkh(xpub123/0/*)");
                assert!(change_descriptor.is_none());
                assert_eq!(start_height, 481_824); // default for mainnet
            }
            _ => panic!("expected Add"),
        }
    }

    #[test]
    fn add_with_change_descriptor() {
        let cli = parse(&[
            "hoover", "add",
            "--descriptor", "wpkh(xpub123/0/*)",
            "--change-descriptor", "wpkh(xpub123/1/*)",
        ]);
        match cli.command {
            Commands::Add { change_descriptor, .. } => {
                assert_eq!(change_descriptor.as_deref(), Some("wpkh(xpub123/1/*)"));
            }
            _ => panic!("expected Add"),
        }
    }

    #[test]
    fn add_with_start_height() {
        let cli = parse(&[
            "hoover",
            "add",
            "--descriptor",
            "wpkh(xpub123/0/*)",
            "--start-height",
            "800000",
        ]);
        match cli.command {
            Commands::Add { start_height, .. } => assert_eq!(start_height, 800000),
            _ => panic!("expected Add"),
        }
    }

    #[test]
    fn add_missing_descriptor_rejected() {
        assert!(try_parse(&["hoover", "add"]).is_err());
    }

    #[test]
    fn list_subcommand() {
        let cli = parse(&["hoover", "list"]);
        assert!(matches!(cli.command, Commands::List));
    }

    #[test]
    fn sweep_no_output_dir() {
        let cli = parse(&["hoover", "clean"]);
        match cli.command {
            Commands::Clean { output_dir, .. } => assert!(output_dir.is_none()),
            _ => panic!("expected Clean"),
        }
    }

    #[test]
    fn sweep_with_output_dir() {
        let cli = parse(&["hoover", "clean", "--output-dir", "/tmp/psbts"]);
        match cli.command {
            Commands::Clean { output_dir, .. } => {
                assert_eq!(output_dir, Some(PathBuf::from("/tmp/psbts")))
            }
            _ => panic!("expected Clean"),
        }
    }

    #[test]
    fn broadcast_with_psbt_path() {
        let cli = parse(&["hoover", "broadcast", "--psbt", "tx.psbt"]);
        match cli.command {
            Commands::Broadcast { psbt, .. } => {
                assert_eq!(psbt, Some(PathBuf::from("tx.psbt")));
            }
            _ => panic!("expected Broadcast"),
        }
    }

    #[test]
    fn broadcast_no_args_is_valid() {
        // No psbt required — broadcasts all files in output dir
        let cli = parse(&["hoover", "broadcast"]);
        assert!(matches!(cli.command, Commands::Broadcast { psbt: None, .. }));
    }

    #[test]
    fn broadcast_with_output_dir() {
        let cli = parse(&["hoover", "broadcast", "--output-dir", "/tmp/psbts"]);
        match cli.command {
            Commands::Broadcast { output_dir, .. } => {
                assert_eq!(output_dir, Some(PathBuf::from("/tmp/psbts")));
            }
            _ => panic!("expected Broadcast"),
        }
    }

    #[test]
    fn status_with_txid() {
        let txid = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let cli = parse(&["hoover", "status", txid]);
        match cli.command {
            Commands::Status { txid: t } => assert_eq!(t, txid),
            _ => panic!("expected Status"),
        }
    }

    #[test]
    fn status_missing_txid_rejected() {
        assert!(try_parse(&["hoover", "status"]).is_err());
    }

    #[test]
    fn no_subcommand_rejected() {
        assert!(try_parse(&["hoover"]).is_err());
    }
}
