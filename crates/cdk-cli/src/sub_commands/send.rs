use std::str::FromStr;

use anyhow::{anyhow, Result};
use cdk::nuts::{Conditions, CurrencyUnit, PublicKey, SpendingConditions};
use cdk::wallet::types::SendKind;
use cdk::wallet::{MultiMintWallet, SendMemo, SendOptions};
use cdk::Amount;
use clap::Args;

use crate::sub_commands::balance::mint_balances;
use crate::utils::{
    check_sufficient_funds, get_number_input, get_wallet_by_index, get_wallet_by_mint_url,
};

#[derive(Args)]
pub struct SendSubCommand {
    /// Token Memo
    #[arg(short, long)]
    memo: Option<String>,
    /// Preimage
    #[arg(long, conflicts_with = "hash")]
    preimage: Option<String>,
    /// Hash for HTLC (alternative to preimage)
    #[arg(long, conflicts_with = "preimage")]
    hash: Option<String>,
    /// Required number of signatures
    #[arg(long)]
    required_sigs: Option<u64>,
    /// Locktime before refund keys can be used
    #[arg(short, long)]
    locktime: Option<u64>,

    /// Pubkey to lock proofs to
    #[arg(short, long, action = clap::ArgAction::Append)]
    pubkey: Vec<String>,

    /// Vec["path_to_executable.json", output_len, outputs]
    #[arg(long, conflicts_with = "cairo_program_hash")]
    cairo_executable: Option<String>,

    // Hash of the cairo program bytecode - alternative to cairo_executable
    /// Vec[program hash, output_len, outputs]
    #[arg(long, conflicts_with = "cairo_executable")]
    cairo_program_hash: Option<String>,

    /// Refund keys that can be used after locktime
    #[arg(long, action = clap::ArgAction::Append)]
    refund_keys: Vec<String>,
    /// Token as V3 token
    #[arg(short, long)]
    v3: bool,
    /// Should the send be offline only
    #[arg(short, long)]
    offline: bool,
    /// Include fee to redeem in token
    #[arg(short, long)]
    include_fee: bool,
    /// Amount willing to overpay to avoid a swap
    #[arg(short, long)]
    tolerance: Option<u64>,
    /// Mint URL to use for sending
    #[arg(long)]
    mint_url: Option<String>,
    /// Currency unit e.g. sat
    #[arg(default_value = "sat")]
    unit: String,
}

pub async fn send(
    multi_mint_wallet: &MultiMintWallet,
    sub_command_args: &SendSubCommand,
) -> Result<()> {
    let unit = CurrencyUnit::from_str(&sub_command_args.unit)?;
    let mints_amounts = mint_balances(multi_mint_wallet, &unit).await?;

    // Get wallet either by mint URL or by index
    let wallet = if let Some(mint_url) = &sub_command_args.mint_url {
        // Use the provided mint URL
        get_wallet_by_mint_url(multi_mint_wallet, mint_url, unit).await?
    } else {
        // Fallback to the index-based selection
        let mint_number: usize = get_number_input("Enter mint number to create token")?;
        get_wallet_by_index(multi_mint_wallet, &mints_amounts, mint_number, unit).await?
    };

    let token_amount = Amount::from(get_number_input::<u64>("Enter value of token in sats")?);

    // Find the mint amount for the selected wallet to check if we have sufficient funds
    let mint_url = &wallet.mint_url;
    let mint_amount = mints_amounts
        .iter()
        .find(|(url, _)| url == mint_url)
        .map(|(_, amount)| *amount)
        .ok_or_else(|| anyhow!("Could not find balance for mint: {}", mint_url))?;

    check_sufficient_funds(mint_amount, token_amount)?;

    // refactoring this
    // let conditions = match (&sub_command_args.preimage, &sub_command_args.hash) {
    //     (Some(_), Some(_)) => {
    //         // This case shouldn't be reached due to Clap's conflicts_with attribute
    //         unreachable!("Both preimage and hash were provided despite conflicts_with attribute")
    //     }
    //     (Some(preimage), None) => {
    //         let pubkeys = match sub_command_args.pubkey.is_empty() {
    //             true => None,
    //             false => Some(
    //                 sub_command_args
    //                     .pubkey
    //                     .iter()
    //                     .map(|p| PublicKey::from_str(p).unwrap())
    //                     .collect(),
    //             ),
    //         };
    //         let refund_keys = match sub_command_args.refund_keys.is_empty() {
    //             true => None,
    //             false => Some(
    //                 sub_command_args
    //                     .refund_keys
    //                     .iter()
    //                     .map(|p| PublicKey::from_str(p).unwrap())
    //                     .collect(),
    //             ),
    //         };

    //         let conditions = Conditions::new(
    //             sub_command_args.locktime,
    //             pubkeys,
    //             refund_keys,
    //             sub_command_args.required_sigs,
    //             None,
    //             None,
    //         )
    //         .unwrap();

    //         Some(SpendingConditions::new_htlc(
    //             preimage.clone(),
    //             Some(conditions),
    //         )?)
    //     }
    //     (None, Some(hash)) => {
    //         let pubkeys: Option<Vec<PublicKey>> = match sub_command_args.pubkey.is_empty() {
    //             true => None,
    //             false => Some(
    //                 sub_command_args
    //                     .pubkey
    //                     .iter()
    //                     .map(|p| PublicKey::from_str(p).unwrap())
    //                     .collect(),
    //             ),
    //         };

    //         let refund_keys = match sub_command_args.refund_keys.is_empty() {
    //             true => None,
    //             false => Some(
    //                 sub_command_args
    //                     .refund_keys
    //                     .iter()
    //                     .map(|p| PublicKey::from_str(p).unwrap())
    //                     .collect(),
    //             ),
    //         };

    //         let conditions = Conditions::new(
    //             sub_command_args.locktime,
    //             pubkeys,
    //             refund_keys,
    //             sub_command_args.required_sigs,
    //             None,
    //             None,
    //         )?;

    //         Some(SpendingConditions::new_htlc_hash(hash, Some(conditions))?)
    //     }
    //     (None, None) => match sub_command_args.pubkey.is_empty() {
    //         true => None,
    //         false => {
    //             let pubkeys: Vec<PublicKey> = sub_command_args
    //                 .pubkey
    //                 .iter()
    //                 .map(|p| PublicKey::from_str(p).unwrap())
    //                 .collect();

    //             let refund_keys: Vec<PublicKey> = sub_command_args
    //                 .refund_keys
    //                 .iter()
    //                 .map(|p| PublicKey::from_str(p).unwrap())
    //                 .collect();

    //             let refund_keys = (!refund_keys.is_empty()).then_some(refund_keys);

    //             let data_pubkey = pubkeys[0];
    //             let pubkeys = pubkeys[1..].to_vec();
    //             let pubkeys = (!pubkeys.is_empty()).then_some(pubkeys);

    //             let conditions = Conditions::new(
    //                 sub_command_args.locktime,
    //                 pubkeys,
    //                 refund_keys,
    //                 sub_command_args.required_sigs,
    //                 None,
    //                 None,
    //             )?;

    //             Some(SpendingConditions::P2PKConditions {
    //                 data: data_pubkey,
    //                 conditions: Some(conditions),
    //             })
    //         }
    //     },
    // };

    fn parse_pubkeys(pubkeys: &[String]) -> Result<Option<Vec<PublicKey>>> {
        if pubkeys.is_empty() {
            return Ok(None);
        }

        let parsed: Result<Vec<_>, _> = pubkeys.iter().map(|p| PublicKey::from_str(p)).collect();

        Ok(Some(parsed?))
    }

    fn create_base_conditions(args: &SendSubCommand) -> Result<Conditions> {
        let pubkeys = parse_pubkeys(&args.pubkey)?;
        let refund_keys = parse_pubkeys(&args.refund_keys)?;

        Conditions::new(
            args.locktime,
            pubkeys,
            refund_keys,
            args.required_sigs,
            None,
            None,
        )
    }

    // TODO: support Cairo conditions from executable -> match on args.cairo_executable
    let conditions = match (
        &args.preimage,
        &args.hash,
        &args.cairo_program_hash,
        &args.cairo_executable,
    ) {
        // HTLC with preimage
        (Some(preimage), None, None, None) => {
            let conditions = create_base_conditions(args)?;
            Ok(Some(SpendingConditions::new_htlc(
                preimage.clone(),
                Some(conditions),
            )?))
        }

        // HTLC with hash
        (None, Some(hash), None, None) => {
            let conditions = create_base_conditions(args)?;
            Ok(Some(SpendingConditions::new_htlc_hash(
                hash,
                Some(conditions),
            )?))
        }

        // Cairo conditions
        (None, None, Some(program_hash), None) => {
            //let conditions = create_base_conditions(args)?;
            let program_hash = Felt::from_hex(program_hash)?;
            Ok(Some(SpendingConditions::new_cairo(
                program_hash,
                Some(conditions),
            )))
        }

        //from executable
        (None, None, None, Some(executable)) => {
            match sub_command_args.cairo_executable.is_empty() {
                True => None,
                False => {}
            }
            // here we want to parse the executable JSON, and hash its bytecode
            let executable_json = include_str!("example_executable.json");
            let executable: Executable = serde_json::from_str(executable_json).unwrap();
            let program_hash = Poseidon::hash_array(&executable.program.bytecode);
        }

        (None, None, None, None) => {
            if args.pubkey.is_empty() {
                return Ok(None);
            }

            let pubkeys = parse_pubkeys(&args.pubkey)?;
            let data_pubkey = pubkeys.as_ref().unwrap()[0]; // First key is data key
            let remaining_pubkeys = pubkeys.unwrap()[1..].to_vec();

            let conditions = Conditions::new(
                args.locktime,
                (!remaining_pubkeys.is_empty()).then_some(remaining_pubkeys),
                parse_pubkeys(&args.refund_keys)?,
                args.required_sigs,
                None,
                None,
            )?;

            Ok(Some(SpendingConditions::P2PKConditions {
                data: data_pubkey,
                conditions: Some(conditions),
            }))
        }

        _ => Err(anyhow!("Conflicting spending condition arguments provided")),
    };

    /// maybe we could have a builder such that it returns an error if more than one condition is set.. because as it seems with the current code
    /// we can't have both and htlc condition and a p2pk condition
    let send_kind = match (sub_command_args.offline, sub_command_args.tolerance) {
        (true, Some(amount)) => SendKind::OfflineTolerance(Amount::from(amount)),
        (true, None) => SendKind::OfflineExact,
        (false, Some(amount)) => SendKind::OnlineTolerance(Amount::from(amount)),
        (false, None) => SendKind::OnlineExact,
    };

    let prepared_send = wallet
        .prepare_send(
            token_amount,
            SendOptions {
                memo: sub_command_args.memo.clone().map(|memo| SendMemo {
                    memo,
                    include_memo: true,
                }),
                send_kind,
                include_fee: sub_command_args.include_fee,
                conditions,
                ..Default::default()
            },
        )
        .await?;
    let token = wallet.send(prepared_send, None).await?;

    match sub_command_args.v3 {
        true => {
            let token = token;

            println!("{}", token.to_v3_string());
        }
        false => {
            println!("{token}");
        }
    }

    Ok(())
}
