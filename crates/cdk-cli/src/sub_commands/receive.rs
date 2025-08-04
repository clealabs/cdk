use std::collections::HashSet;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{anyhow, Result};
use cairo_prove::execute::execute;
use cairo_prove::prove::{prove, prover_input_from_runner};
use cdk::nuts::nutxx::secure_pcs_config;
use cdk::nuts::{SecretKey, Token};
use cdk::util::unix_time;
use cdk::wallet::multi_mint_wallet::MultiMintWallet;
use cdk::wallet::types::WalletKey;
use cdk::wallet::ReceiveOptions;
use cdk::Amount;
use clap::Args;
use nostr_sdk::nips::nip04;
use nostr_sdk::{Filter, Keys, Kind, Timestamp};
use starknet_types_core::felt::Felt;

use crate::nostr_storage;
use crate::utils::get_or_create_wallet;

#[derive(Args)]
pub struct ReceiveSubCommand {
    /// Cashu Token
    token: Option<String>,
    /// Signing Key
    #[arg(short, long, action = clap::ArgAction::Append)]
    signing_key: Vec<String>,
    /// Nostr key
    #[arg(short, long)]
    nostr_key: Option<String>,
    /// Nostr relay
    #[arg(short, long, action = clap::ArgAction::Append)]
    relay: Vec<String>,
    /// Unix time to query nostr from
    #[arg(long)]
    since: Option<u64>,
    /// Preimage
    #[arg(short, long,  action = clap::ArgAction::Append)]
    preimage: Vec<String>,
    /// Path to Cairo executable JSON file + program arguments
    /// Multiple executables and arguments can be passed as follows:
    /// --cairo ./program1.json 1 1 2 ./program2.json 0
    #[arg(long, action = clap::ArgAction::Append)]
    cairo: Vec<String>,
}

fn cairo_prove(executable_path: String, args: Vec<String>) -> String {
    let executable = serde_json::from_reader(
        rdr::File::open(executable_path).expect("Failed to open Cairo executable file"),
    )
    .expect("Failed to parse Cairo executable JSON");

    let runner = execute(executable, args);
    let prover_input = prover_input_from_runner(&runner);

    let pcs_config = secure_pcs_config();
    let cairo_proof = prove(prover_input, pcs_config);

    return serde_json::to_string(&cairo_proof); // returns a json serialized CairoProof
}

pub async fn receive(
    multi_mint_wallet: &MultiMintWallet,
    sub_command_args: &ReceiveSubCommand,
    work_dir: &Path,
) -> Result<()> {
    let mut signing_keys = Vec::new();

    if !sub_command_args.signing_key.is_empty() {
        let mut s_keys: Vec<SecretKey> = sub_command_args
            .signing_key
            .iter()
            .map(|s| {
                if s.starts_with("nsec") {
                    let nostr_key = nostr_sdk::SecretKey::from_str(s).expect("Invalid secret key");

                    SecretKey::from_str(&nostr_key.to_secret_hex())
                } else {
                    SecretKey::from_str(s)
                }
            })
            .collect::<Result<Vec<SecretKey>, _>>()?;
        signing_keys.append(&mut s_keys);
    }

    let mut cairo_proofs_json = Vec::new();

    // TODO : cleaner parser
    if !sub_command_args.cairo.is_empty() {
        // if let Some(mint_info) = multi_mint_wallet.().await? {}
        let wallets = multi_mint_wallet.get_wallets().await;
        if wallets.len() != 1 {
            panic!("Only one wallet is supported for now");
            // TODO: if we want to support multiple wallets,
            // either check that they all have the same mint info,
            // or somehow find a way to generate proofs for each wallet
        }
        let mint_info = wallets[0].get_mint_info().await?.unwrap();
        if !mint_info.nuts.nutxx.supported {
            panic!("Mint does not support NUT-XX");
        }
        // TODO: assert cairo[0] is the path of a json file
        let mut executable_path = sub_command_args.cairo[0].clone();
        let mut args = Vec::new();
        for arg in sub_command_args.cairo[1..].iter() {
            // check if arg is a file path
            if arg.ends_with(".json") {
                // check if the file exists
                if !std::path::Path::new(&executable_path).exists() {
                    panic!("Cairo executable file not found: {}", executable_path);
                }
                // add arg to current_args
                cairo_proofs_json.push(cairo_prove(executable_path.clone(), args.clone()));
                executable_path = arg.clone();
                args = Vec::new();
            } else {
                // try to parse arg as a Felt
                // TODO: if it fails, throw error
                if let Err(_) = Felt::from_str(arg) {
                    panic!("Invalid argument for Cairo proof: {}", arg);
                }
                // add arg to current_args
                args.push(arg.clone());
            }
        }
        cairo_proofs_json.push(cairo_prove(executable_path.clone(), args.clone()));
    }

    let amount = match &sub_command_args.token {
        Some(token_str) => {
            receive_token(
                multi_mint_wallet,
                token_str,
                &signing_keys,
                &sub_command_args.preimage,
                &cairo_proofs_json,
            )
            .await?
        }
        None => {
            //wallet.add_p2pk_signing_key(nostr_signing_key).await;
            let nostr_key = match sub_command_args.nostr_key.as_ref() {
                Some(nostr_key) => {
                    let secret_key = nostr_sdk::SecretKey::from_str(nostr_key)?;
                    let secret_key = SecretKey::from_str(&secret_key.to_secret_hex())?;
                    Some(secret_key)
                }
                None => None,
            };

            let nostr_key =
                nostr_key.ok_or(anyhow!("Nostr key required if token is not provided"))?;

            signing_keys.push(nostr_key.clone());

            let relays = sub_command_args.relay.clone();
            let since =
                nostr_storage::get_nostr_last_checked(work_dir, &nostr_key.public_key()).await?;

            let tokens = nostr_receive(relays, nostr_key.clone(), since).await?;

            // Store the current time as last checked
            nostr_storage::store_nostr_last_checked(
                work_dir,
                &nostr_key.public_key(),
                unix_time() as u32,
            )
            .await?;

            let mut total_amount = Amount::ZERO;
            for token_str in &tokens {
                match receive_token(
                    multi_mint_wallet,
                    token_str,
                    &signing_keys,
                    &sub_command_args.preimage,
                    &cairo_proofs_json,
                )
                .await
                {
                    Ok(amount) => {
                        total_amount += amount;
                    }
                    Err(err) => {
                        println!("{err}");
                    }
                }
            }

            total_amount
        }
    };

    println!("Received: {amount}");

    Ok(())
}

async fn receive_token(
    multi_mint_wallet: &MultiMintWallet,
    token_str: &str,
    signing_keys: &[SecretKey],
    preimage: &[String],
    cairo_proofs_json: &[String],
) -> Result<Amount> {
    let token: Token = Token::from_str(token_str)?;

    let mint_url = token.mint_url()?;
    let unit = token.unit().unwrap_or_default();

    if multi_mint_wallet
        .get_wallet(&WalletKey::new(mint_url.clone(), unit.clone()))
        .await
        .is_none()
    {
        get_or_create_wallet(multi_mint_wallet, &mint_url, unit).await?;
    }

    let amount = multi_mint_wallet
        .receive(
            token_str,
            ReceiveOptions {
                p2pk_signing_keys: signing_keys.to_vec(),
                preimages: preimage.to_vec(),
                cairo_proofs_json: cairo_proofs_json.to_vec(),
                ..Default::default()
            },
        )
        .await?;
    Ok(amount)
}

/// Receive tokens sent to nostr pubkey via dm
async fn nostr_receive(
    relays: Vec<String>,
    nostr_signing_key: SecretKey,
    since: Option<u32>,
) -> Result<HashSet<String>> {
    let verifying_key = nostr_signing_key.public_key();

    let x_only_pubkey = verifying_key.x_only_public_key();

    let nostr_pubkey = nostr_sdk::PublicKey::from_hex(&x_only_pubkey.to_string())?;

    let since = since.map(|s| Timestamp::from(s as u64));

    let filter = match since {
        Some(since) => Filter::new()
            .pubkey(nostr_pubkey)
            .kind(Kind::EncryptedDirectMessage)
            .since(since),
        None => Filter::new()
            .pubkey(nostr_pubkey)
            .kind(Kind::EncryptedDirectMessage),
    };

    let client = nostr_sdk::Client::default();

    client.connect().await;

    let events = client
        .fetch_events_from(relays, filter, Duration::from_secs(30))
        .await?;

    let mut tokens: HashSet<String> = HashSet::new();

    let keys = Keys::from_str(&(nostr_signing_key).to_secret_hex())?;

    for event in events {
        if event.kind == Kind::EncryptedDirectMessage {
            if let Ok(msg) = nip04::decrypt(keys.secret_key(), &event.pubkey, event.content) {
                if let Some(token) = cdk::wallet::util::token_from_text(&msg) {
                    tokens.insert(token.to_string());
                }
            } else {
                tracing::error!("Impossible to decrypt direct message");
            }
        }
    }

    Ok(tokens)
}
