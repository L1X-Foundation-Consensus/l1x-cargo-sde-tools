use l1x_common::toolkit_config;
use l1x_rpc::{
    json as l1x_rpc_json,
    rpc_model::{
        GetEventsRequest, GetEventsResponse, SmartContractReadOnlyCallRequest,
        SmartContractReadOnlyCallResponse, SubmitTransactionRequest,
        SubmitTransactionResponse,
    },
};

use anyhow::Result;
use reqwest::{Client, RequestBuilder};
use secp256k1::{Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    env, error::Error, fmt::Display, fs::File, io::Read, process::Command,
    sync::Arc,
};
use tokio::sync::RwLock;

#[derive(Debug, thiserror::Error)]
pub enum L1XVmSubTxnError {
    #[error("Hex parse error: {0}")]
    HexParseError(String),
    #[error("Request Creation error: {0}")]
    RequestCreationError(String),
    #[error("Post JSON RPC error: {0}")]
    PostJsonRpcError(String),
    #[error("JSON Parse error: {0}")]
    JsonParseError(String),
    #[error("Invalid Nonce error: {0}")]
    InValidNonceError(String),
    #[error("Contract Deployment error: {0}")]
    ContractDeploymentError(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct L1XVmTxnResponse {
    pub status: u8,
    pub message: String,
}

#[derive(Debug)]
struct L1XVmTxnExecutorInternal {
    cfg_ws_home: String,
    cfg_cli_scripts_base: String,
    json_client: RequestBuilder,
    private_key: String,
    secret_key: SecretKey,
}

impl L1XVmTxnExecutorInternal {
    fn new(txn_cmd: &L1XVmSubTxnCmd) -> Self {
        let cfg_ws_home = env::var("L1X_CFG_WS_HOME")
            .expect("The L1X_CFG_WS_HOME environment variable must be set");

        let cfg_cli_scripts_base = env::var("L1X_CFG_CLI_SCRIPTS")
            .expect("The L1X_CFG_CLI_SCRIPTS environment variable must be set");

        let end_point = toolkit_config::get_active_chain_json_rpc_endpoint();

        let json_client = Client::new().post(&end_point);

        let private_key = toolkit_config::get_wallet_priv_key(&txn_cmd.owner);

        let secret_key = SecretKey::from_slice(
            &hex::decode(&private_key)
            .map_err(|err_code| {
                log::error!("L1X eBPF Deployment Failed: Unable to hex decode private_key :: {:#?} err :: {:#?}",
                    &private_key, err_code
                );
                err_code
            }).unwrap()
        )
        .map_err(|err_code| {
            log::error!("L1X eBPF Deployment Failed: Failed to parse provided private_key :: {:#?} err :: {:#?}",
                &private_key, err_code
            )
        }).unwrap();

        Self {
            cfg_ws_home,
            cfg_cli_scripts_base,
            json_client,
            private_key,
            secret_key,
        }
    }
}

#[derive(Debug)]
struct L1XVmTxnExecutor {
    txn_cmd: L1XVmSubTxnCmd,
    internal_installer: Arc<RwLock<L1XVmTxnExecutorInternal>>,
}

impl L1XVmTxnExecutor {
    fn new(txn_cmd: &L1XVmSubTxnCmd) -> Self {
        let install_init = L1XVmTxnExecutorInternal::new(txn_cmd);
        let internal_installer = Arc::new(RwLock::new(install_init));
        L1XVmTxnExecutor { txn_cmd: txn_cmd.clone(), internal_installer }
    }

    fn clean_string(address_to_clean: &str) -> String {
        // Trim the string and remove any leading or trailing quotes.
        let trimmed_address = address_to_clean.trim().trim_matches('"');

        // Remove the "0x" prefix from the address, if it exists.
        let clean_address =
            trimmed_address.strip_prefix("0x").unwrap_or(trimmed_address);

        // Return the clean address.
        clean_address.to_string()
    }

    fn create_txn_function_call(
        contract_address: &str,
        function_payload: &str,
    ) -> Result<l1x_common::types::Transaction, L1XVmSubTxnError> {
        Ok(l1x_common::types::Transaction::SmartContractFunctionCall {
            contract_instance_address: l1x_common::types::U8s::Hex(
                contract_address.parse().map_err(|err_code| {
                    L1XVmSubTxnError::HexParseError(format!(
                        "Sub Txn Failed: Hex File Parse Error :: {:#?}",
                        err_code
                    ))
                })?,
            ),
            function: l1x_common::types::U8s::Text(Default::default()),
            arguments: l1x_common::types::U8s::Hex(
                function_payload.parse().map_err(|err_code| {
                    L1XVmSubTxnError::HexParseError(format!(
                        "Sub Txn Failed: Hex File Parse Error :: {:#?}",
                        err_code
                    ))
                })?,
            ),
        })
    }

    fn create_ronly_txn_function_call(
        contract_address: &str,
        function_payload: &str,
    ) -> Result<l1x_common::types::SmartContractReadOnlyFunctionCall, L1XVmSubTxnError> {
        Ok(l1x_common::types::SmartContractReadOnlyFunctionCall {
            contract_instance_address: l1x_common::types::U8s::Hex(
                contract_address.parse().map_err(|err_code| {
                    L1XVmSubTxnError::HexParseError(format!(
                        "Read-Only Txn Failed: Hex File Parse Error :: {:#?}",
                        err_code
                    ))
                })?,
            ),
            function: l1x_common::types::U8s::Text(Default::default()),
            arguments: l1x_common::types::U8s::Hex(
                function_payload.parse().map_err(|err_code| {
                    L1XVmSubTxnError::HexParseError(format!(
                        "Read-Only Txn Failed: Hex File Parse Error :: {:#?}",
                        err_code
                    ))
                })?,
            ),
        })
    }

    fn create_submit_txn_request(
        private_key: &str,
        fee_limit: u128,
        nonce: u128,
        txn_function_call: l1x_common::types::Transaction,
    ) -> Result<SubmitTransactionRequest, L1XVmSubTxnError> {
        l1x_common::get_submit_txn_req(
            txn_function_call,
            private_key,
            fee_limit,
            nonce + 1,
        )
        .map_err(|err_code| {
            L1XVmSubTxnError::RequestCreationError(format!(
                "Sub Txn Failed: Unable to get_submit_txn_req :: {:#?}",
                err_code
            ))
        })
    }

    async fn post_submit_txn_request(
        json_client: &RequestBuilder,
        method: &str,
        request_json: &serde_json::Value,
    ) -> Result<l1x_rpc_json::JsonRpcResponse, L1XVmSubTxnError> {
        l1x_rpc_json::post_json_rpc(
            json_client
                .try_clone()
                .expect("Sub Txn Failed: Unable to clone RequestBuilder"),
            "l1x_submitTransaction",
            json!({ "request": request_json }),
        )
        .await
        .map_err(|err_code| {
            L1XVmSubTxnError::PostJsonRpcError(format!(
                "Sub Txn Failed: Unable to post_json_rpc {:#?}",
                err_code
            ))
        })
    }

    fn print_transaction_status(txn_response_message: &[u8]) {
        println!(
            "{}",
            json!({ "l1x-forge-txn-status":  L1XVmTxnResponse{
                status: 0,
                message: format!("{}", hex::encode(txn_response_message)),
            }})
        );
    }

    async fn post_get_events_request(
        json_client: &RequestBuilder,
        method: &str,
        tx_hash: &str,
    ) -> Result<l1x_rpc_json::JsonRpcResponse, L1XVmSubTxnError> {
        l1x_rpc_json::post_json_rpc(
            json_client.try_clone().expect(
                "Sub Txn Failed: Unable to clone RequestBuilder",
            ),
            "l1x_getEvents",
            json!({"request": GetEventsRequest{tx_hash: tx_hash.to_string(), timestamp: 0u64}}),
        )
        .await
        .map_err(|err_code| {
            L1XVmSubTxnError::JsonParseError(format!(
            "Sub Txn Failed: l1x_submitTransaction request failed {:#?}",
            err_code
            ))
        })
    }

    pub async fn l1x_vm_submit_txn(
        &self,
        contract_address: &str,
    ) -> Result<(), L1XVmSubTxnError> {
        let self_internal = self.internal_installer.read().await;

        let clean_hex_contract_address = Self::clean_string(contract_address);

        let clean_hex_function_payload =
            Self::clean_string(&self.txn_cmd.function_payload);

        let txn_function_call = Self::create_txn_function_call(
            &clean_hex_contract_address,
            &clean_hex_function_payload,
        )?;

        log::info!(
            "Sub Txn Req for {:#?} => {:#?}",
            &self.txn_cmd.artifact_id,
            &txn_function_call
        );

        let nonce = l1x_rpc_json::get_nonce(
            self_internal
                .json_client
                .try_clone()
                .expect("Sub Txn Failed: Unable to clone RequestBuilder"),
            &self_internal.secret_key,
        )
        .await
        .map_err(|err_code| {
            L1XVmSubTxnError::InValidNonceError(format!(
                "Sub Txn Failed: Unable to get nounce {:#?}",
                err_code
            ))
        })?;

        let request = Self::create_submit_txn_request(
            &self_internal.private_key,
            self.txn_cmd.fee_limit,
            nonce + 1,
            txn_function_call,
        )?;

        let request_json =
            serde_json::to_value(&request).map_err(|err_code| {
                L1XVmSubTxnError::JsonParseError(format!(
                "Sub Txn Failed: Can't serialize transaction to JSON :: {:#?}",
                err_code
                ))
            })?;

        let txn_response_result = Self::post_submit_txn_request(
            &self_internal.json_client,
            "l1x_submitTransaction",
            &request_json,
        )
        .await?;

        log::info!(
            "Sub Txn Resp B4 Parsing for {:#?} => txn_response_result :: {:#?}",
            &self.txn_cmd.artifact_id,
            txn_response_result
        );

        let txn_response = l1x_rpc_json::parse_response::<
            SubmitTransactionResponse,
        >(txn_response_result)
        .map_err(|err_code| {
            L1XVmSubTxnError::JsonParseError(format!(
                "Sub Txn Failed: Unable to parse the response {:#?}",
                err_code
            ))
        })?;

        log::info!(
            "Sub Txn Resp for {:#?} => {:#?}",
            &self.txn_cmd.artifact_id,
            txn_response
        );

        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

        let txn_event_response = Self::post_get_events_request(
            &self_internal.json_client,
            "l1x_getEvents",
            &txn_response.hash,
        )
        .await?;

        log::info!(
            "Sub Txn Event Resp B4 Parsing for {:#?} => txn_event_response :: {:#?}",
            &self.txn_cmd.artifact_id,
            txn_event_response
        );

        let txn_event_response_message: Vec<u8> =
            serde_json::from_value(txn_event_response.result.unwrap()["events_data"].clone())
                .map_err(|err_code| {
                    L1XVmSubTxnError::JsonParseError(format!(
                        "Sub Txn Resp Failed: Unable to parse JSON Value {:#?}",
                        err_code
                    ))
                })?;

		Self::print_transaction_status(&txn_event_response_message);

        Ok(())
    }

    pub async fn l1x_vm_read_only_call(
        &self,
        contract_address: &str,
    ) -> Result<(), L1XVmSubTxnError> {
        let self_internal = self.internal_installer.read().await;

        let clean_hex_contract_address = Self::clean_string(contract_address);

        let clean_hex_function_payload =
            Self::clean_string(&self.txn_cmd.function_payload);

        let ronly_function_call = Self::create_ronly_txn_function_call(
            &clean_hex_contract_address,
            &clean_hex_function_payload,
        )?;

        log::info!(
            "Read-Only Txn Req for {:#?} => {:#?}",
            &self.txn_cmd.artifact_id,
            &ronly_function_call,
        );

        let ronly_function_call: l1x_rpc::rpc_model::SmartContractReadOnlyCallRequest =
                ronly_function_call.try_into()
                .map_err(|err_code| {
                    L1XVmSubTxnError::RequestCreationError(format!(
                        "Read-Only Txn Failed: Unable to create request :: {:#?}",
                        err_code
                    ))
                })?;

        let txn_result = l1x_rpc_json::post_json_rpc(
            self_internal
                .json_client
                .try_clone()
                .expect("Read-Only Txn Failed: Unable to clone RequestBuilder"),
            "l1x_smartContractReadOnlyCall",
            json!({ "request": ronly_function_call }),
        )
        .await
        .map_err(|err_code| {
            L1XVmSubTxnError::PostJsonRpcError(format!(
                "Read-Only Txn Failed: Unable to post_json_rpc {:#?}",
                err_code
            ))
        })?;

        match txn_result.result {
            Some(response_inner) => {

                let response_message: Vec<u8> = serde_json::from_value(
                    response_inner["result"].clone(),
                )
                .map_err(|err_code| {
                    L1XVmSubTxnError::JsonParseError(format!(
                                "Read-Only Txn Failed: Unable to parse JSON Value {:#?}",
                                err_code
                            ))
                })?;

                Self::print_transaction_status(&response_message);
            }
            None => {
                println!(
                    "{}",
                    json!({ "l1x-forge-txn-status":  L1XVmTxnResponse{
                        status: 1,
                        message: format!("InValid Inner Response"),
                    }})
                );
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum L1XVMType {
    #[clap(name = "ebpf")]
    L1xVmEbpf,
    #[clap(name = "evm")]
    L1xVmEvm,
}

impl std::fmt::Display for L1XVMType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::L1xVmEbpf => write!(f, "L1xVmEbpf"),
            Self::L1xVmEvm => write!(f, "L1xVmEvm"),
        }
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum L1XCallType {
    #[clap(name = "sub-txn")]
    L1xCallTypeSubTxn,
    #[clap(name = "ronly")]
    L1xCallTypeReadOnly,
}

impl std::fmt::Display for L1XCallType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::L1xCallTypeSubTxn => write!(f, "L1xCallTypeSubTxn"),
            Self::L1xCallTypeReadOnly => write!(f, "L1xCallTypeReadOnly"),
        }
    }
}

/// Deploy and initialize the contract to l1x-vm
#[derive(Clone, Debug, clap::Args)]
#[clap(name = "vm-sub-txn")]
pub struct L1XVmSubTxnCmd {
    #[clap(long = "vm-type")]
    vm_type: L1XVMType,

    #[clap(long = "owner")]
    owner: String,

    #[clap(long = "artifact-id")]
    artifact_id: String,

    #[clap(long = "contract-id")]
    contract_id: String,

    #[clap(long = "call-type")]
    call_type: L1XCallType,

    #[clap(long = "function-payload")]
    function_payload: String,

    #[clap(long = "fee_limit", default_value_t = 100)]
    fee_limit: u128,

    #[clap(long = "req_id", default_value_t = 1)]
    req_id: u64,
}

impl L1XVmSubTxnCmd {
    pub async fn exec(&self) -> Result<()> {
        log::info!("Calling Submit Transactions With Args :: {:#?}!", &self);
        self.l1x_vm_sub_txn().await?;
        Ok(())
    }
}

impl L1XVmSubTxnCmd {
    // Function to deploy and initialize a contract on ebpf VM
    async fn l1x_vm_sub_txn(&self) -> Result<(), L1XVmSubTxnError> {
        // Load executor settings
        let txn_executor = L1XVmTxnExecutor::new(self);

        let artifact_deploy_status = match self.vm_type {
            L1XVMType::L1xVmEbpf => {
                toolkit_config::get_toolkit_ebpf_contract_address_for(
                    &self.artifact_id,
                    Some(&self.contract_id),
                )
            }
            L1XVMType::L1xVmEvm => {
                toolkit_config::get_toolkit_evm_contract_address_for(
                    &self.artifact_id,
                    None,
                )
            }
        };

        if artifact_deploy_status.is_err() {
            return Err(L1XVmSubTxnError::ContractDeploymentError(format!(
                "L1X Submit TransactionFailed: Unknown Contract Address"
            )));
        } else {
            match self.call_type {
                L1XCallType::L1xCallTypeSubTxn => {
                    txn_executor
                        .l1x_vm_submit_txn(&artifact_deploy_status.unwrap())
                        .await?;
                }
                L1XCallType::L1xCallTypeReadOnly => {
                    txn_executor
                        .l1x_vm_read_only_call(&artifact_deploy_status.unwrap())
                        .await?;
                }
            }
        }
        Ok(())
    }
}
