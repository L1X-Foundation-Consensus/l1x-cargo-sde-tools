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
use serde_json::json;
use std::{
    env, error::Error, fmt::Display, fs::File, io::Read, process::Command,
    sync::Arc,
};
use tokio::sync::RwLock;

#[derive(Debug)]
pub struct L1XVmSubTxnError(String);

impl L1XVmSubTxnError {
    pub fn new(message: String) -> Self {
        L1XVmSubTxnError(message)
    }
}

impl Display for L1XVmSubTxnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for L1XVmSubTxnError {}

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

    pub async fn l1x_vm_submit_txn(
        &self,
        contract_address: &str,
    ) -> Result<String, L1XVmSubTxnError> {
        let self_internal = self.internal_installer.read().await;

        let clean_hex_contract_address = if contract_address.starts_with("0x") {
            &contract_address[2..]
        } else {
            &contract_address
        };

        let function_payload = &self.txn_cmd.function_payload;
        let clean_hex_function_payload = if function_payload.starts_with("0x") {
            &function_payload[2..]
        } else {
            &function_payload
        };

        let txn_function_call =
            l1x_common::types::Transaction::SmartContractFunctionCall {
                contract_instance_address: l1x_common::types::U8s::Hex(
                    clean_hex_contract_address.parse().map_err(|err_code| {
                        L1XVmSubTxnError::new(format!(
                            "Sub Txn Failed: Hex File Parse Error :: {:#?}",
                            err_code
                        ))
                    })?,
                ),
                function: l1x_common::types::U8s::Text(Default::default()),
                arguments: l1x_common::types::U8s::Hex(
                    clean_hex_function_payload.parse().map_err(|err_code| {
                        L1XVmSubTxnError::new(format!(
                            "Sub Txn Failed: Hex File Parse Error :: {:#?}",
                            err_code
                        ))
                    })?,
                ),
            };

        let nonce = l1x_rpc_json::get_nonce(
            self_internal
                .json_client
                .try_clone()
                .expect("Sub Txn Failed: Unable to clone RequestBuilder"),
            &self_internal.secret_key,
        )
        .await
        .map_err(|err_code| {
            L1XVmSubTxnError::new(format!(
                "Sub Txn Failed: Unable to get nounce {:#?}",
                err_code
            ))
        })?;

        log::info!(
            "Sub Txn Req for {:#?} => {:#?}",
            &self.txn_cmd.artifact_id,
            &txn_function_call
        );

        let request = l1x_common::get_submit_txn_req(
            txn_function_call,
            &self_internal.private_key,
            self.txn_cmd.fee_limit,
            nonce + 1,
        )
        .map_err(|err_code| {
            L1XVmSubTxnError::new(format!(
                "Sub Txn Failed: Unable to get_submit_txn_req :: {:#?}",
                err_code
            ))
        })?;

        let request_json =
            serde_json::to_value(&request).map_err(|err_code| {
                L1XVmSubTxnError::new(format!(
					"Sub Txn Failed: Can serialize transaction to JSON :: {:#?}",
					err_code
				))
            })?;

        let result = l1x_rpc_json::post_json_rpc(
            self_internal
                .json_client
                .try_clone()
                .expect("Sub Txn Failed: Unable to clone RequestBuilder"),
            "l1x_submitTransaction",
            json!({ "request": request_json }),
        )
        .await
        .map_err(|err_code| {
            L1XVmSubTxnError::new(format!(
                "Sub Txn Failed: Unable to post_json_rpc {:#?}",
                err_code
            ))
        })?;

        let txn_response =
            l1x_rpc_json::parse_response::<SubmitTransactionResponse>(result)
                .map_err(|err_code| {
                L1XVmSubTxnError::new(format!(
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

        let txn_event_response = l1x_rpc_json::post_json_rpc(
				self_internal.json_client.try_clone().expect(
					"Sub Txn Failed: Unable to clone RequestBuilder",
				),
                "l1x_getEvents",
                json!({"request": GetEventsRequest{tx_hash: txn_response.hash.clone(), timestamp: 0u64}}),
            )
			.await
            .map_err(|err_code| {
				L1XVmSubTxnError::new(format!(
				"Sub Txn Failed: l1x_submitTransaction request failed {:#?}",
				err_code
				))
			})?;

        let txn_event_response = l1x_rpc_json::parse_response::<
            GetEventsResponse,
        >(txn_event_response)
        .map_err(|err_code| {
            L1XVmSubTxnError::new(format!(
                "Sub Txn Failed: Unable to parse the response {:#?}",
                err_code
            ))
        })?;

        log::info!(
            "Sub Txn GetEventsResponse :: {:#?} | Num Events: {:#?}",
            &self.txn_cmd.artifact_id,
            txn_event_response.events_data.len()
        );

        let event_data_iter = txn_event_response.events_data.iter().enumerate();

        let mut txn_event_data_rval: Option<String> = None;

        for (index, event_item) in event_data_iter {
            let event_data =
                serde_json::from_slice::<serde_json::Value>(&event_item)
                    .map_err(|err_code| {
                        L1XVmSubTxnError::new(format!(
								"Sub Txn Failed: Unable to parse the response {:#?}",
								err_code
							))
                    })?;

            if txn_event_data_rval.is_none() {
                let r_val = format!(
                    "address : {:#?},  json_data: {:#?}",
                    event_data["address"].to_string(),
                    event_data["json data"].to_string(),
                );
                txn_event_data_rval = Some(r_val);
            }
            log::info!(
                "Evt[{:#?}] | address :: {:#?} | json data :: {:#?}",
                index,
                event_data["address"],
                event_data
            );
        }

        if txn_event_data_rval.is_none() {
            Ok(String::from("No Event Data"))
        } else {
            Ok(txn_event_data_rval.unwrap())
        }
    }

    pub async fn l1x_vm_read_only_call(
        &self,
        contract_address: &str,
    ) -> Result<String, L1XVmSubTxnError> {
        let self_internal = self.internal_installer.read().await;

        let clean_hex_contract_address = if contract_address.starts_with("0x") {
            &contract_address[2..]
        } else {
            &contract_address
        };

        let function_payload = &self.txn_cmd.function_payload;
        let clean_hex_function_payload = if function_payload.starts_with("0x") {
            &function_payload[2..]
        } else {
            &function_payload
        };

        let ronly_function_call =
			l1x_common::types::SmartContractReadOnlyFunctionCall {
                contract_instance_address: l1x_common::types::U8s::Hex(
                    clean_hex_contract_address.parse().map_err(|err_code| {
                        L1XVmSubTxnError::new(format!(
                            "Read-Only Txn Failed: Hex File Parse Error :: {:#?}",
                            err_code
                        ))
                    })?,
                ),
                function: l1x_common::types::U8s::Text(Default::default()),
                arguments: l1x_common::types::U8s::Hex(
                    clean_hex_function_payload.parse().map_err(|err_code| {
                        L1XVmSubTxnError::new(format!(
                            "Read-Only Txn Failed: Hex File Parse Error :: {:#?}",
                            err_code
                        ))
                    })?,
                ),
            };

        log::info!(
            "Read-Only Txn Req for {:#?} => {:#?}",
            &self.txn_cmd.artifact_id,
            &ronly_function_call,
        );

        let ronly_function_call: l1x_rpc::rpc_model::SmartContractReadOnlyCallRequest =
				ronly_function_call.try_into()
				        .map_err(|err_code| {
            L1XVmSubTxnError::new(format!(
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
            L1XVmSubTxnError::new(format!(
                "Read-Only Txn Failed: Unable to post_json_rpc {:#?}",
                err_code
            ))
        })?;

        let ronly_txn_rval = match txn_result.result {
            Some(response_inner) => {
                let data: SmartContractReadOnlyCallResponse = serde_json::from_value(response_inner)
					.map_err(|err_code| {

						log::error!("Read-Only Txn Failed: Unable to parse the json_value {:#?}", err_code);

						L1XVmSubTxnError::new(format!(
							"Read-Only Txn Failed: Unable to parse the json_value {:#?}",
							err_code
						))
					})?;

                if data.status == 0 {

					// Attempt to convert the event to a String
					if let Ok(result_str) = String::from_utf8(data.result.clone()) {
						log::info!("Read-Only Txn Success UTF-8:\n{:#?}", result_str);
					}

					// Attempt to deserialize the event as a JSON value
					if let Ok(result_str) = serde_json::from_slice::<serde_json::Value>(data.result.clone()) {
						log::info!("Read-Only Txn Success JSON Value:\n{:#?}", result_str);
					}

					// If neither String nor JSON, print as raw bytes
					println!("Event data as Raw Bytes:\n{:?}", hex::encode(event));
					}



					let result = String::from_utf8(data.result.clone())
						.map_err(|err_code| {
							log::error!("Read-Only Txn Failed: Unable to parse the response {:#?}", err_code);
							L1XVmSubTxnError::new(format!(
								"Read-Only Txn Failed: Unable to parse the response {:#?}",
								err_code
							))
						});

					log::info!("Read-Only Txn Success [UTF8]:\n{:#?}", &result);

					log::info!("Read-Only Txn Success [hex encoded]:\n{:#?}", hex::encode(&data.result));

					let result = String::from(hex::encode(&data.result));
                    Some(result)
                } else {
                    Some(String::from("Invalid response"))
                }
            }
            None => Some(String::from("Invalid response")),
        };

        ronly_txn_rval.ok_or(L1XVmSubTxnError(String::from("Invalid response")))
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
    pub async fn exec(&self) -> Result<String> {
        log::info!("Calling Submit Transactions With Args :: {:#?}!", &self);
        Ok(self.l1x_vm_sub_txn().await?)
    }
}

impl L1XVmSubTxnCmd {
    // Function to deploy and initialize a contract on ebpf VM
    async fn l1x_vm_sub_txn(&self) -> Result<String, L1XVmSubTxnError> {
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
            return Err(L1XVmSubTxnError::new(format!(
                "L1X Submit TransactionFailed: Unknown Contract Address"
            )));
        } else {
            match self.call_type {
                L1XCallType::L1xCallTypeSubTxn => Ok(txn_executor
                    .l1x_vm_submit_txn(&artifact_deploy_status.unwrap())
                    .await?),
                L1XCallType::L1xCallTypeReadOnly => Ok(txn_executor
                    .l1x_vm_read_only_call(&artifact_deploy_status.unwrap())
                    .await?),
            }
        }
    }
}
