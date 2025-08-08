use std::fs; // Add this line
use std::str::FromStr;

use anyhow::{anyhow, Result};
use cashu::NutXXConditions;
use cdk::nuts::nutxx::Executable;
use cdk::nuts::{Conditions, CurrencyUnit, PublicKey, SpendingConditions};
use cdk::wallet::types::SendKind;
use cdk::wallet::{MultiMintWallet, SendMemo, SendOptions};
use cdk::Amount;
use clap::Args;
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Poseidon, StarkHash};

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

    /// ["path_to_executable.json", output_len, outputs]
    #[arg(long, conflicts_with = "cairo_program_hash")]
    cairo_executable: Option<Vec<String>>,

    // Hash of the cairo program bytecode - alternative to cairo_executable
    /// [program hash, output_len, outputs]
    #[arg(long, conflicts_with = "cairo_executable")]
    cairo_program_hash: Option<Vec<String>>,

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
    // let conditions: Option<SpendingConditions> = match (&sub_command_args.preimage, &sub_command_args.hash) {
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

    // TODO: support Cairo conditions from executable -> match on args.cairo_executable
    let conditions = match (
        &sub_command_args.preimage,
        &sub_command_args.hash,
        &sub_command_args.cairo_program_hash,
        &sub_command_args.cairo_executable,
    ) {
        // HTLC with preimage
        (Some(preimage), None, None, None) => {
            let pubkeys = match sub_command_args.pubkey.is_empty() {
                true => None,
                false => Some(
                    sub_command_args
                        .pubkey
                        .iter()
                        .map(|p| PublicKey::from_str(p).unwrap())
                        .collect(),
                ),
            };
            let refund_keys = match sub_command_args.refund_keys.is_empty() {
                true => None,
                false => Some(
                    sub_command_args
                        .refund_keys
                        .iter()
                        .map(|p| PublicKey::from_str(p).unwrap())
                        .collect(),
                ),
            };

            let conditions = Conditions::new(
                sub_command_args.locktime,
                pubkeys,
                refund_keys,
                sub_command_args.required_sigs,
                None,
                None,
            )
            .unwrap();

            Some(SpendingConditions::new_htlc(
                preimage.clone(),
                Some(conditions),
            )?)
        }

        // HTLC with hash
        (None, Some(hash), None, None) => {
            let pubkeys: Option<Vec<PublicKey>> = match sub_command_args.pubkey.is_empty() {
                true => None,
                false => Some(
                    sub_command_args
                        .pubkey
                        .iter()
                        .map(|p| PublicKey::from_str(p).unwrap())
                        .collect(),
                ),
            };

            let refund_keys = match sub_command_args.refund_keys.is_empty() {
                true => None,
                false => Some(
                    sub_command_args
                        .refund_keys
                        .iter()
                        .map(|p| PublicKey::from_str(p).unwrap())
                        .collect(),
                ),
            };

            let conditions = Conditions::new(
                sub_command_args.locktime,
                pubkeys,
                refund_keys,
                sub_command_args.required_sigs,
                None,
                None,
            )?;

            Some(SpendingConditions::new_htlc_hash(hash, Some(conditions))?)
        }

        // Cairo conditions from program hash directly
        (None, None, Some(program_hash_args), None) => {
            let program_hash = Felt::from_hex(&program_hash_args[0])
                .map_err(|_| anyhow!("Invalid program hash"))?;
            let narg_output = program_hash_args[1]
                .parse::<usize>()
                .map_err(|_| anyhow!("Invalid output length argument"))?;
            let output_conditions = program_hash_args[2..]
                .iter()
                .map(|o| Felt::from_hex(o))
                .collect::<Result<Vec<Felt>, _>>()?;

            if output_conditions.len() > 1 {
                return Err(anyhow!(
                    "Multiple outputs are not supported yet, found: {}",
                    output_conditions.len()
                ));
            }
            if output_conditions.len() != narg_output {
                return Err(anyhow!(
                    "Number of outputs does not match the expected output length"
                ));
            }

            let output_condition = Some(NutXXConditions {
                output: Some(Poseidon::hash_array(&output_conditions)),
            });

            Some(SpendingConditions::CairoConditions {
                data: program_hash,
                conditions: output_condition,
            })
        }

        //from executable
        (None, None, None, Some(cairo_executable_args)) => {
            match cairo_executable_args.is_empty() {
                true => None,
                false => {
                    // find the executable file
                    let exec_path = std::path::Path::new(&cairo_executable_args[0]);
                    if !exec_path.exists() {
                        return Err(anyhow!(
                            "Cairo executable file not found: {}",
                            exec_path.display()
                        ));
                    }
                    // parse the output arguments -> output_len, iterate over outputs
                    let narg_output = cairo_executable_args[1]
                        .parse::<usize>()
                        .map_err(|_| anyhow!("Invalid output length argument"))?;

                    let output_conditions = cairo_executable_args[2..]
                        .iter()
                        .map(|o| Felt::from_hex(o))
                        .collect::<Result<Vec<Felt>, _>>()?;

                    //TODO: remove this once we support multiple output hashes
                    if output_conditions.len() > 1 {
                        return Err(anyhow!(
                            "Multiple outputs are not supported yet, found: {}",
                            output_conditions.len()
                        ));
                    }
                    if output_conditions.len() != narg_output {
                        return Err(anyhow!(
                            "Number of outputs does not match the expected output length"
                        ));
                    }

                    // parse the executable and hash the bytecode
                    let executable: Executable =
                        serde_json::from_str::<Executable>(&std::fs::read_to_string(exec_path)?)
                            .map_err(|e| anyhow!("Failed to parse Cairo executable: {}", e))?;

                    let program_hash: Felt = Poseidon::hash_array(&executable.program.bytecode);

                    // TODO: support multiple outputs
                    let output_condition = Some(NutXXConditions {
                        output: Some(Poseidon::hash_array(&output_conditions)),
                    });

                    Some(SpendingConditions::CairoConditions {
                        data: program_hash,
                        conditions: output_condition,
                    })
                }
            }
        }

        (None, None, None, None) => match sub_command_args.pubkey.is_empty() {
            true => None,
            false => {
                let pubkeys: Vec<PublicKey> = sub_command_args
                    .pubkey
                    .iter()
                    .map(|p| PublicKey::from_str(p).unwrap())
                    .collect();

                let refund_keys: Vec<PublicKey> = sub_command_args
                    .refund_keys
                    .iter()
                    .map(|p| PublicKey::from_str(p).unwrap())
                    .collect();

                let refund_keys = (!refund_keys.is_empty()).then_some(refund_keys);

                let data_pubkey = pubkeys[0];
                let pubkeys = pubkeys[1..].to_vec();
                let pubkeys = (!pubkeys.is_empty()).then_some(pubkeys);

                let conditions = Conditions::new(
                    sub_command_args.locktime,
                    pubkeys,
                    refund_keys,
                    sub_command_args.required_sigs,
                    None,
                    None,
                )?;

                Some(SpendingConditions::P2PKConditions {
                    data: data_pubkey,
                    conditions: Some(conditions),
                })
            }
        },

        _ => None, // TODO : gracefully handle this case
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
        }
        false => {
            println!("{token}");
        }
    }

    Ok(())
}
