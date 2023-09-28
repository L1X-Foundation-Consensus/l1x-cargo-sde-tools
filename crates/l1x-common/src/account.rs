use crate::primitives::*;
use anyhow::{anyhow, Error as AError};
use ethers::signers::Signer;
use ethers::utils::keccak256;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::PublicKey as K256PublicKey;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Account {
    pub address: Address,
    pub balance: Balance,
    pub nonce: Nonce,
    pub account_type: AccountType,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AccountType {
    System,
    User,
}

impl Account {
    pub fn new(address: Address) -> Account {
        Account {
            address,
            balance: 0,
            nonce: 0,
            account_type: AccountType::User,
        }
    }

    pub fn new_system(address: Address) -> Account {
        Account {
            address,
            balance: 0,
            nonce: 0,
            account_type: AccountType::System,
        }
    }

    pub fn address(
        verifying_key_bytes: &VerifyingKeyBytes,
    ) -> Result<Address, AError> {
        let public_key = match secp256k1::PublicKey::from_slice(
            verifying_key_bytes.as_slice(),
        ) {
            Ok(public_key) => public_key,
            Err(err) => {
                return Err(anyhow!("Unable to construct public key {:?}", err))
            }
        };

        let k_pub_bytes = K256PublicKey::from_sec1_bytes(
            &public_key.serialize_uncompressed(),
        )
        .unwrap();

        let k_pub_bytes = k_pub_bytes.to_encoded_point(false);
        let k_pub_bytes = k_pub_bytes.as_bytes();

        let hash = keccak256(&k_pub_bytes[1..]);
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&hash[12..]);
        Ok(bytes)
    }

    // pub fn address(verifying_key_bytes: &VerifyingKeyBytes) -> Address {
    //     let verifying_key_bytes = verifying_key_bytes.clone();
    //     let hash = Keccak256::digest(verifying_key_bytes);
    //     let mut address = [0u8; 20];
    //     address.copy_from_slice(&hash[12..]);
    //     address
    // }

    pub fn contract_address(
        account_address: &Address,
        cluster_address: &Address,
        nonce: Nonce,
    ) -> Address {
        let mut input: Vec<u8> = Vec::new();
        //input.extend_from_slice(contract_code);
        input.extend_from_slice(account_address);
        input.extend_from_slice(cluster_address);
        input.extend_from_slice(&nonce.to_be_bytes());

        let hash = Keccak256::digest(&input);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);
        address
    }

    pub fn contract_instance_address(
        account_address: &Address,
        contract_address: &Address,
        cluster_address: &Address,
        nonce: Nonce,
    ) -> Address {
        let mut input: Vec<u8> = Vec::new();
        input.extend_from_slice(account_address);
        input.extend_from_slice(contract_address);
        input.extend_from_slice(cluster_address);
        input.extend_from_slice(&nonce.to_be_bytes());

        let hash = Keccak256::digest(&input);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);
        address
    }

    pub fn pool_address(
        account_address: &Address,
        cluster_address: &Address,
        nonce: Nonce,
    ) -> Address {
        let mut input: Vec<u8> = Vec::new();
        input.extend_from_slice(account_address);
        input.extend_from_slice(cluster_address);
        input.extend_from_slice(&nonce.to_be_bytes());

        let hash = Keccak256::digest(&input);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);
        address
    }
}
