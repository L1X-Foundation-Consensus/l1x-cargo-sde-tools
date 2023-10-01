use l1x_common::toolkit_config;
use l1x_rpc::{
    json as l1x_rpc_json,
    rpc_model::{
        GetEventsRequest, GetEventsResponse, SubmitTransactionRequest,
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
pub struct L1XVmContractInstallError(String);

impl L1XVmContractInstallError {
    pub fn new(message: String) -> Self {
        L1XVmContractInstallError(message)
    }
}

impl Display for L1XVmContractInstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for L1XVmContractInstallError {}

#[derive(Debug)]
struct L1XVmContractInstallInternal {
    cfg_ws_home: String,
    cfg_cli_scripts_base: String,
    json_client: RequestBuilder,
    private_key: String,
    secret_key: SecretKey,
}

impl L1XVmContractInstallInternal {
    fn new(install_cmd: &L1XVmInstallContractCmd) -> Self {
        let cfg_ws_home = env::var("L1X_CFG_WS_HOME")
            .expect("The L1X_CFG_WS_HOME environment variable must be set");

        let cfg_cli_scripts_base = env::var("L1X_CFG_CLI_SCRIPTS")
            .expect("The L1X_CFG_CLI_SCRIPTS environment variable must be set");

        let end_point = toolkit_config::get_active_chain_json_rpc_endpoint();

        let json_client = Client::new().post(&end_point);

        let private_key =
            toolkit_config::get_wallet_priv_key(&install_cmd.owner);

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

    async fn submit_transaction(
        &self,
        install_cmd: &L1XVmInstallContractCmd,
        json_payload_file_path: &str,
    ) -> Result<SubmitTransactionResponse, L1XVmContractInstallError> {
        let nonce = l1x_rpc_json::get_nonce(
            self.json_client.try_clone().expect(
                "L1X Submit Transaction Failed: Unable to clone RequestBuilder",
            ),
            &self.secret_key,
        )
        .await
        .map_err(|err_code| {
            L1XVmContractInstallError::new(format!(
                "L1X Submit Transaction Failed: Unable to get nounce {:#?}",
                err_code
            ))
        })?;

        let request: SubmitTransactionRequest =
            l1x_common::load_submit_txn_req(
                json_payload_file_path,
                &self.private_key,
                install_cmd.fee_limit,
                nonce + 1,
            )
            .map_err(|err_code| {
                L1XVmContractInstallError::new(format!(
                    "L1X Submit Transaction Failed: Unable to create SubmitTransactionRequest {:#?}",
                    err_code
                    ))
            })?;

        let request_json =
            serde_json::to_value(&request).map_err(|err_code| {
                L1XVmContractInstallError::new(format!(
                        "L1X Submit Transaction Failed: Unable to serialize transaction to JSON {:#?}",
                        err_code
                        ))
            })?;

        let result = l1x_rpc_json::post_json_rpc(
            self.json_client.try_clone().expect(
                "L1X Submit Transaction Failed: Unable to clone RequestBuilder",
            ),
            "l1x_submitTransaction",
            json!({ "request": request_json }),
        )
        .await
        .map_err(|err_code| {
            L1XVmContractInstallError::new(format!(
            "L1X Submit Transaction Failed: l1x_submitTransaction request failed {:#?}",
            err_code
            ))
        })?;

        let response =
            l1x_rpc_json::parse_response::<SubmitTransactionResponse>(result)
                .map_err(|err_code| {
                L1XVmContractInstallError::new(format!(
                        "L1X Submit Transaction Failed: Unable to parse the response {:#?}",
                        err_code
                    ))
            })?;

        Ok(response)
    }
}

#[derive(Debug)]
struct L1XVmContractInstaller {
    install_cmd: L1XVmInstallContractCmd,
    internal_installer: Arc<RwLock<L1XVmContractInstallInternal>>,
}

impl L1XVmContractInstaller {
    fn new(install_cmd: &L1XVmInstallContractCmd) -> Self {
        let install_init = L1XVmContractInstallInternal::new(install_cmd);
        let internal_installer = Arc::new(RwLock::new(install_init));
        L1XVmContractInstaller {
            install_cmd: install_cmd.clone(),
            internal_installer,
        }
    }

    pub async fn l1x_ebpf_init_contract(
        &self,
        deploy_address: &str,
    ) -> Result<SubmitTransactionResponse, L1XVmContractInstallError> {
        let self_internal = self.internal_installer.read().await;

        let json_payload_file_path = format!(
            "{}/l1x-forge-cli/cli-uc-init-{}.json",
            self_internal.cfg_cli_scripts_base, &self.install_cmd.contract_id
        );

        // Create a JSON payload using serde_json
        let init_json_payload = json!({
            "smart_contract_init": [
                { "hex": format!("{}", deploy_address) },
                { "text": "{}" }
            ]
        });

        // Serialize the JSON payload to a string
        let init_json_string = serde_json::to_string(&init_json_payload)
            .expect("Failed to serialize JSON");

        log::info!(
            "eBPF Contract Init :: {:#?} | JSON Payload :: {:#?}",
            &self.install_cmd.contract_id,
            init_json_string
        );

        // Write the JSON payload to the specified file path
        std::fs::write(&json_payload_file_path, init_json_string)
            .unwrap_or_else(|_| {
                panic!(
                    "Failed to write JSON to file :: {:#?}",
                    &json_payload_file_path
                )
            });

        let init_response = self_internal
            .submit_transaction(&self.install_cmd, &json_payload_file_path)
            .await?;

        log::info!(
            "eBPF Contract Init :: {:#?} | Resp :: {:#?}",
            &self.install_cmd.contract_id,
            init_response
        );

        log::info!(
            "eBPF Contract Init :: {:#?} | Waiting for Event Data ...",
            &self.install_cmd.contract_id,
        );

        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

        let init_event_response = l1x_rpc_json::post_json_rpc(
				self_internal.json_client.try_clone().expect(
					"L1X Submit Transaction Failed: Unable to clone RequestBuilder",
				),
                "l1x_getEvents",
                json!({"request": GetEventsRequest{tx_hash: init_response.hash.clone(), timestamp: 0u64}}),
            )
			.await
            .map_err(|err_code| {
				L1XVmContractInstallError::new(format!(
				"L1X Submit Transaction Failed: l1x_submitTransaction request failed {:#?}",
				err_code
				))
			})?;

        let init_event_response = l1x_rpc_json::parse_response::<
            GetEventsResponse,
        >(init_event_response)
        .map_err(|err_code| {
            L1XVmContractInstallError::new(format!(
				"L1X Submit Transaction Failed: Unable to parse the response {:#?}",
				err_code
			))
        })?;

        log::info!(
            "eBPF Contract GetEventsResponse :: {:#?} | Num Events: {:#?}",
            &self.install_cmd.contract_id,
            init_event_response.events_data.len()
        );

        init_event_response.events_data.iter().enumerate().for_each(
            |(index, event_item)| {
                log::info!(
                    "Evt[{:#?}] :: {:#?}",
                    index,
                    hex::encode(event_item)
                );
            },
        );

        let _ = toolkit_config::update_toolkit_contract_address_registry(
            toolkit_config::L1XVMContractAddressUpdateType::L1XEBPF_INIT {
                artifact_id: self.install_cmd.artifact_id.clone(),
                contract_id: self.install_cmd.contract_id.clone(),
                response_hash: init_response.hash.clone(),
                response_address: init_response
                    .contract_address
                    .clone()
                    .unwrap_or_default(),
            },
        );

        Ok(init_response)
    }

    pub async fn l1x_ebpf_deploy_contract(
        &self,
    ) -> Result<SubmitTransactionResponse, L1XVmContractInstallError> {
        let self_internal = self.internal_installer.read().await;

        let json_payload_file_path = format!(
            "{}/l1x-forge-cli/cli-uc-deploy-{}.json",
            self_internal.cfg_cli_scripts_base, &self.install_cmd.contract_id
        );

        // Create a JSON payload using serde_json
        let deploy_json_payload = json!({
            "smart_contract_deployment": [
                "PRIVATE",
                "L1XVM",
                { "file": format!("{}/l1x-artifacts/{}", self_internal.cfg_ws_home, &self.install_cmd.artifact_id) }
            ]
        });

        // Serialize the JSON payload to a string
        let deploy_json_string = serde_json::to_string(&deploy_json_payload)
            .expect("Failed to serialize JSON");

        log::info!(
            "eBPF Contract Deploy :: {:#?} | JSON Payload :: {:#?}",
            &self.install_cmd.artifact_id,
            deploy_json_string
        );

        // Write the JSON payload to the specified file path
        std::fs::write(&json_payload_file_path, deploy_json_string)
            .unwrap_or_else(|_| {
                panic!(
                    "Failed to write JSON to file :: {:#?}",
                    &json_payload_file_path
                )
            });

        let deploy_response = self_internal
            .submit_transaction(&self.install_cmd, &json_payload_file_path)
            .await?;

        log::info!(
            "eBPF Contract Deploy :: {:#?} | Resp :: {:#?}",
            &self.install_cmd.artifact_id,
            deploy_response
        );

        log::info!(
            "eBPF Contract Deploy :: {:#?} | Waiting for Event Data ...",
            &self.install_cmd.artifact_id,
        );

        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

        let init_event_response = l1x_rpc_json::post_json_rpc(
				self_internal.json_client.try_clone().expect(
					"L1X Submit Transaction Failed: Unable to clone RequestBuilder",
				),
                "l1x_getEvents",
                json!({"request": GetEventsRequest{tx_hash: deploy_response.hash.clone(), timestamp: 0u64}}),
            )
			.await
            .map_err(|err_code| {
				L1XVmContractInstallError::new(format!(
				"L1X Submit Transaction Failed: l1x_submitTransaction request failed {:#?}",
				err_code
				))
			})?;

        let init_event_response = l1x_rpc_json::parse_response::<
            GetEventsResponse,
        >(init_event_response)
        .map_err(|err_code| {
            L1XVmContractInstallError::new(format!(
				"L1X Submit Transaction Failed: Unable to parse the response {:#?}",
				err_code
			))
        })?;

        log::info!(
            "eBPF Contract Deploy GetEventsResponse :: {:#?} | Num Events: {:#?}",
            &self.install_cmd.artifact_id,
			init_event_response.events_data.len()
        );

        init_event_response.events_data.iter().enumerate().for_each(
            |(index, event_item)| {
                log::info!(
                    "Evt[{:#?}] :: {:#?}",
                    index,
                    hex::encode(event_item)
                );
            },
        );

        let _ = toolkit_config::update_toolkit_contract_address_registry(
            toolkit_config::L1XVMContractAddressUpdateType::L1XEBPF_DEPLOY {
                artifact_id: self.install_cmd.artifact_id.clone(),
                response_hash: deploy_response.hash.clone(),
                response_address: deploy_response
                    .contract_address
                    .clone()
                    .unwrap_or_default(),
            },
        );

        Ok(deploy_response)
    }

    pub async fn l1x_evm_deploy_contract(
        &self,
    ) -> Result<SubmitTransactionResponse, L1XVmContractInstallError> {
        let self_internal = self.internal_installer.read().await;

        let sol_file = format!(
            "{}/l1x-evm-artifacts/{}",
            self_internal.cfg_ws_home, &self.install_cmd.artifact_id
        );

        let mut file = File::open(sol_file).unwrap();
        let mut hex_code = String::new();
        file.read_to_string(&mut hex_code).unwrap();

        let clean_hex_string =
            if hex_code.starts_with("0x") { &hex_code[2..] } else { &hex_code };

        let txn = l1x_common::types::Transaction::SmartContractDeployment(
            l1x_common::types::AccessType::PUBLIC,
            l1x_common::types::ContractType::EVM,
            l1x_common::types::U8s::Hex(clean_hex_string.parse().map_err(
                |err_code| {
                    L1XVmContractInstallError::new(format!(
						"EVM Contract Deploy Failed: Hex File Parse Error :: {:#?}",
						err_code
					))
                },
            )?),
        );

        let nonce = l1x_rpc_json::get_nonce(
            self_internal.json_client.try_clone().expect(
                "EVM Contract Deploy Failed: Unable to clone RequestBuilder",
            ),
            &self_internal.secret_key,
        )
        .await
        .map_err(|err_code| {
            L1XVmContractInstallError::new(format!(
                "EVM Contract Deploy Failed: Unable to get nounce {:#?}",
                err_code
            ))
        })?;

        let request = l1x_common::get_submit_txn_req(
			txn,
			&self_internal.private_key,
			self.install_cmd.fee_limit,
			nonce + 1
		)
        .map_err(|err_code| {
            L1XVmContractInstallError::new(format!(
                "EVM Contract Deploy Failed: Unable to get_submit_txn_req :: {:#?}",
                err_code
            ))
        })?;

        let request_json =
            serde_json::to_value(&request).map_err(|err_code| {
                L1XVmContractInstallError::new(format!(
					"EVM Contract Deploy Failed: Can serialize transaction to JSON :: {:#?}",
					err_code
				))
            })?;

        let result = l1x_rpc_json::post_json_rpc(
            self_internal.json_client.try_clone().expect(
                "EVM Contract Deploy Failed: Unable to clone RequestBuilder",
            ),
            "l1x_submitTransaction",
            json!({ "request": request_json }),
        )
        .await
        .map_err(|err_code| {
            L1XVmContractInstallError::new(format!(
                "EVM Contract Deploy Failed: Unable to post_json_rpc {:#?}",
                err_code
            ))
        })?;

		log::info!("EVM Contract Deploy: Txn Respo {:#?}", &result);

        let deploy_response =
            l1x_rpc_json::parse_response::<SubmitTransactionResponse>(result)
                .map_err(|err_code| {
                L1XVmContractInstallError::new(format!(
					"EVM Contract Deploy Failed: Unable to parse the response {:#?}",
					err_code
				))
            })?;

        log::info!(
            "EVM Contract Deploy :: {:#?} | Resp :: {:#?}",
            &self.install_cmd.artifact_id,
            deploy_response
        );

        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

        let init_event_response = l1x_rpc_json::post_json_rpc(
				self_internal.json_client.try_clone().expect(
					"EVM Contract Deploy Failed: Unable to clone RequestBuilder",
				),
                "l1x_getEvents",
                json!({"request": GetEventsRequest{tx_hash: deploy_response.hash.clone(), timestamp: 0u64}}),
            )
			.await
            .map_err(|err_code| {
				L1XVmContractInstallError::new(format!(
				"EVM Contract Deploy Failed: l1x_submitTransaction request failed {:#?}",
				err_code
				))
			})?;

        let init_event_response = l1x_rpc_json::parse_response::<
            GetEventsResponse,
        >(init_event_response)
        .map_err(|err_code| {
            L1XVmContractInstallError::new(format!(
				"EVM Contract Deploy Failed: Unable to parse the response {:#?}",
				err_code
			))
        })?;

        log::info!(
            "EVM Contract Deploy GetEventsResponse :: {:#?} | Num Events: {:#?}",
            &self.install_cmd.artifact_id,
			init_event_response.events_data.len()
        );

        let mut deployed_address_from_event: Option<String> = None;

        let event_data_iter =
            init_event_response.events_data.iter().enumerate();

        for (index, event_item) in event_data_iter {
            let event_data =
                serde_json::from_slice::<serde_json::Value>(&event_item)
                    .map_err(|err_code| {
                        L1XVmContractInstallError::new(format!(
								"EVM Contract Deploy Failed: Unable to parse the response {:#?}",
								err_code
							))
                    })?;

            if deployed_address_from_event.is_none() {
                deployed_address_from_event =
                    Some(event_data["address"].to_string());
            }

            log::info!(
                "Evt[{:#?}] | address :: {:#?} | json data :: {:#?}",
                index,
                event_data["address"],
                event_data
            );
        }

        let _ = toolkit_config::update_toolkit_contract_address_registry(
            toolkit_config::L1XVMContractAddressUpdateType::L1XEVM_DEPLOY {
                artifact_id: self.install_cmd.artifact_id.clone(),
                response_hash: deploy_response.hash.clone(),
                response_address: deployed_address_from_event
                    .unwrap_or_default(),
            },
        );

        Ok(deploy_response)
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

/// Deploy and initialize the contract to l1x-vm
#[derive(Clone, Debug, clap::Args)]
#[clap(name = "vm-install-contract")]
pub struct L1XVmInstallContractCmd {
    #[clap(long = "vm-type")]
    vm_type: L1XVMType,

    #[clap(long = "force", default_value_t = false)]
    force: bool,

    #[clap(long = "contract-id")]
    contract_id: String,

    #[clap(long = "artifact-id")]
    artifact_id: String,

    #[clap(long = "owner")]
    owner: String,

    #[clap(long = "fee_limit", default_value_t = 100)]
    fee_limit: u128,

    #[clap(long = "req_id", default_value_t = 1)]
    req_id: u64,
}

impl L1XVmInstallContractCmd {
    pub async fn exec(&self) -> Result<()> {
        log::info!("L1X VM Contract Install With Args :: {:#?}!", &self);

        match self.vm_type {
            L1XVMType::L1xVmEbpf => {
                self.l1x_ebpf_install_contract().await?;
            }
            L1XVMType::L1xVmEvm => {
                self.l1x_evm_install_contract().await?;
            }
        }

        Ok(())
    }
}

impl L1XVmInstallContractCmd {
    // Function to deploy and initialize a contract on ebpf VM
    async fn l1x_ebpf_install_contract(
        &self,
    ) -> Result<(), L1XVmContractInstallError> {
        // Load install settings
        let installer = L1XVmContractInstaller::new(self);
        let artifact_deploy_status = if self.force == false {
            toolkit_config::get_toolkit_ebpf_contract_address_for(
                &self.artifact_id,
                None,
            )
        } else {
            Err(format!(
                "L1X eBPF Deployment Failed: Unknown Contract Deployment Address"
            ))
        };

        let contract_deploy_address = match (self.force, artifact_deploy_status)
        {
            (true, _) | (false, Err(_)) => {
                let deploy_response =
                    installer.l1x_ebpf_deploy_contract().await?;
                Some(deploy_response.contract_address.unwrap_or_default())
            }
            (false, Ok(address)) => Some(address),
            _ => None,
        };

        if let Some(deploy_address) = contract_deploy_address {
            installer.l1x_ebpf_init_contract(&deploy_address).await?;
            Ok(())
        } else {
            Err(L1XVmContractInstallError::new(format!(
                "L1X eBPF Deployment Failed: Unknown Contract Deployment Address"
            )))
        }
    }

    // Function to deploy and initialize a contract on evm VM
    async fn l1x_evm_install_contract(
        &self,
    ) -> Result<(), L1XVmContractInstallError> {
        // Load install settings
        let installer = L1XVmContractInstaller::new(self);
        let artifact_deploy_status = if self.force == false {
            toolkit_config::get_toolkit_evm_contract_address_for(
                &self.artifact_id,
                None,
            )
        } else {
            Err(format!(
                "L1X EVM Deployment Failed: Unknown Contract Deployment Address"
            ))
        };

        let contract_deploy_address = match (self.force, artifact_deploy_status)
        {
            (true, _) | (false, Err(_)) => {
                let deploy_response =
                    installer.l1x_evm_deploy_contract().await?;
                Some(deploy_response.contract_address.unwrap_or_default())
            }
            (false, Ok(address)) => Some(address),
            _ => None,
        };

        Ok(())
    }
}
