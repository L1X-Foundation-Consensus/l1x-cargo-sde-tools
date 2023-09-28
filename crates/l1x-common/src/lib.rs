use anyhow::{anyhow, Context, Result};
use l1x_rpc::rpc_model::SubmitTransactionRequest;
use libp2p::PeerId;
use primitives::*;
use secp256k1::{hashes::sha256, Message, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs::File;
use std::io::Read;

mod account;
// mod json;
mod primitives;
pub mod toolkit_config;
pub mod types;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TransactionTypeNativeTX {
    NativeTokenTransfer(Address, String),
}
#[derive(Debug, Serialize, Deserialize)]
pub struct NativeTokenTransferPayload {
    pub nonce: Nonce,
    pub transaction_type: TransactionTypeNativeTX,
    pub fee_limit: Balance,
}

/// Functionality to both json and grpc clis
pub fn load_submit_txn_req(
    payload_file_path: &str,
    private_key: &str,
    fee_limit: Balance,
    nonce: Nonce,
) -> Result<SubmitTransactionRequest, Box<dyn Error>> {
    let mut file = File::open(payload_file_path)
        .with_context(|| "Failed to open payload file")?;
    let mut file_content = String::new();
    file.read_to_string(&mut file_content)
        .with_context(|| "Failed to read the file")?;
    let txn: types::Transaction = serde_json::from_str(&file_content)
        .with_context(|| "Failed to deserialize transaction payload")?;

    get_submit_txn_req(txn, private_key, fee_limit, nonce)
}

pub fn get_submit_txn_req(
    txn: types::Transaction,
    private_key: &str,
    fee_limit: Balance,
    nonce: Nonce,
) -> Result<SubmitTransactionRequest, Box<dyn Error>> {
    let secret_key = SecretKey::from_slice(&hex::decode(private_key)?)
        .with_context(|| "Failed to parse provided private_key")?;
    let secp = Secp256k1::new();
    let verifying_key = secret_key.public_key(&secp);

    let txn_type: l1x_rpc::rpc_model::submit_transaction_request::TransactionType =
        txn.clone().try_into()?;

    let is_native_token_transfer = match txn_type {
        l1x_rpc::rpc_model::submit_transaction_request::TransactionType::NativeTokenTransfer(_) => {
            true
        }
        _ => false,
    };

    // TODO: Refactor this
    if is_native_token_transfer {
        let txn_type2 = txn_type.clone();
        let native_token = match txn_type {
            l1x_rpc::rpc_model::submit_transaction_request::TransactionType::NativeTokenTransfer(l1x_rpc::rpc_model::NativeTokenTransfer { address, amount }) => {
                TransactionTypeNativeTX::NativeTokenTransfer(address.try_into().map_err(|_| anyhow::anyhow!("Failed to convert NativeTokenAddress Address vec<u8> to array"))?, amount.to_string())
            }

            _ => TransactionTypeNativeTX::NativeTokenTransfer(Address::default(), "0".to_string()),
        };

        let obj = NativeTokenTransferPayload {
            nonce,
            transaction_type: native_token,
            fee_limit,
        };
        println!("is_native_token_transfer: {:?}", is_native_token_transfer);
        let json_str = serde_json::to_string(&obj)?;
        let message =
            Message::from_hashed_data::<sha256::Hash>(json_str.as_bytes());
        let sig = secret_key.sign_ecdsa(message);

        Ok(SubmitTransactionRequest {
            nonce: nonce.to_string(),
            fee_limit: fee_limit.to_string(), // FIXME,
            signature: sig.serialize_compact().to_vec(),
            verifying_key: verifying_key.serialize().to_vec(),
            transaction_type: Some(txn_type2),
        })
    } else {
        Ok(SubmitTransactionRequest {
            nonce: nonce.to_string(),
            fee_limit: fee_limit.to_string(), // FIXME,
            signature: l1x_rpc::sign(
                secret_key,
                txn_type.clone(),
                fee_limit,
                nonce,
            )?,
            verifying_key: verifying_key.serialize().to_vec(),
            transaction_type: Some(txn_type),
        })
    }
}

pub fn secp256k1_creds(
    privkey: Option<String>,
) -> Result<(String, String, PeerId), Box<dyn Error>> {
    let (keypair, privkey) = match privkey {
        Some(privkey) => {
            let mut keypair_bytes: Vec<u8> = hex::decode(&privkey)?;

            let keypair = libp2p::identity::secp256k1::SecretKey::from_bytes(
                &mut keypair_bytes,
            )
            .map(|sk| {
                libp2p::identity::Keypair::Secp256k1(
                    libp2p::identity::secp256k1::Keypair::from(sk),
                )
            })?;
            (keypair, privkey)
        }
        None => {
            let keypair = libp2p::identity::Keypair::generate_secp256k1();
            let privkey_bytes =
                keypair.clone().try_into_secp256k1()?.secret().to_bytes();
            let privkey = hex::encode(privkey_bytes);
            (keypair, privkey)
        }
    };

    let pubkey = match keypair.public() {
        libp2p::identity::PublicKey::Secp256k1(pubkey) => pubkey,
        _ => return Err(anyhow!("Invalid key").into()),
    };
    let pubkey_bytes = pubkey.to_bytes().to_vec();
    let pubkey = hex::encode(&pubkey_bytes);
    let peer_id = keypair.public().to_peer_id();

    Ok((privkey, pubkey, peer_id))
}

pub fn read_file(payload_file_path: String) -> String {
    let mut file =
        File::open(payload_file_path).expect("Failed to open payload file");
    let mut file_content = String::new();
    file.read_to_string(&mut file_content).expect("Failed to read the file");

    file_content
}
