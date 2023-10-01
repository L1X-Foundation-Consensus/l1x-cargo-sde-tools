use std::{
    collections::{BTreeMap, HashMap},
    env,
    error::Error,
    fs,
    io::Write,
    path::Path,
};

use config::{Config, File};
use serde::{Deserialize, Serialize};

// Define structs to represent the configuration files.

#[derive(Clone, Debug, Deserialize)]
pub struct WalletConfig {
    dev_accounts: HashMap<String, DevAccount>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DevAccount {
    priv_key: String,
    pub_key: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct NetworkConfig {
    networks: HashMap<String, Network>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Network {
    chain_id: u32,
    host_ip: String,
    rpc_port: u32,
    rpc_endpoint: String,
}

pub fn get_toolkit_network_config() -> Result<NetworkConfig, config::ConfigError>
{
    let l1x_cfg_ws_home = env::var("L1X_CFG_WS_HOME")
        .expect("The L1X_CFG_WS_HOME environment variable must be set");

    let network_config_file_path =
        format!("{}/l1x-conf/l1x_chain_config.yaml", l1x_cfg_ws_home);

    // Create a new configuration object.
    let mut settings = Config::builder()
        // Load the YAML configuration files.
        .add_source(File::with_name(&network_config_file_path))
        .build()?;

    let network_settings: NetworkConfig = settings.try_deserialize()
        .map_err(|err_code| {
            log::error!("Failed to deserialize YAML configuration file :: {:#?} :: err {:#?}", network_config_file_path, err_code );
            err_code
        })?;

    Ok(network_settings)
}

pub fn get_toolkit_wallet_config() -> Result<WalletConfig, config::ConfigError>
{
    // Create a new configuration object.
    let l1x_cfg_ws_home = env::var("L1X_CFG_WS_HOME")
        .expect("The L1X_CFG_WS_HOME environment variable must be set");

    let default_wallet_config_file_path =
        format!("{}/l1x-conf/l1x_dev_wallets.yaml", l1x_cfg_ws_home);

    let mut settings = Config::builder()
        // Load the YAML configuration files.
        .add_source(File::with_name(&default_wallet_config_file_path))
        .build()?;

    let wallet_settings: WalletConfig = settings.try_deserialize()
        .map_err(|err_code| {
            log::error!("Failed to deserialize YAML configuration file :: {:#?} :: err {:#?}", default_wallet_config_file_path, err_code );
            err_code
        })?;

    Ok(wallet_settings)
}

pub fn get_active_chain_json_rpc_endpoint() -> String {
    let l1x_cfg_chain_type = env::var("L1X_CFG_CHAIN_TYPE")
        .expect("The L1X_CFG_CHAIN_TYPE environment variable must be set");

    let config_network: NetworkConfig = get_toolkit_network_config().expect(
        &format!("Failed to get yaml network config for the active chain"),
    );

    let config_network_params: Network = config_network
        .networks
        .get(&l1x_cfg_chain_type)
        .unwrap_or_else(|| {
            panic!(
            "Failed to get default network config params for chain type :: {}",
            l1x_cfg_chain_type
        )
        })
        .clone();

    config_network_params.rpc_endpoint
}

pub fn get_wallet_priv_key(owner_id: &str) -> String {
    let config_wallet: WalletConfig = get_toolkit_wallet_config()
        .expect(&format!("Failed to get yaml wallet config"));

    let account_info: DevAccount = config_wallet
        .dev_accounts
        .get(owner_id)
        .unwrap_or_else(|| {
            panic!(
                "Failed to get default account info for owner ID :: {}",
                owner_id
            )
        })
        .clone();

    account_info.priv_key
}

// ================================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum L1XVMContractAddressUpdateType {
    L1XEBPF_DEPLOY {
        artifact_id: String,
        response_hash: String,
        response_address: String,
    },
    L1XEBPF_INIT {
        artifact_id: String,
        contract_id: String,
        response_hash: String,
        response_address: String,
    },
    L1XEVM_DEPLOY {
        artifact_id: String,
        response_hash: String,
        response_address: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct L1XVMContractAddressRegistry {
    l1x_vm: BTreeMap<String, L1XVMContractInfo>,
    l1x_evm: BTreeMap<String, L1XVMContractInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct L1XVMContractInfo {
    deploy_hash: String,
    deploy_address: String,
    instance: BTreeMap<String, L1XVMInstanceInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct L1XVMInstanceInfo {
    inst_hash: String,
    inst_address: String,
}

/// Load the contract address registry from a YAML configuration file.
fn load_contract_address_registry(
) -> Result<L1XVMContractAddressRegistry, config::ConfigError> {
    // Create a new configuration object.
    let l1x_cfg_ws_home = env::var("L1X_CFG_WS_HOME")
        .expect("The L1X_CFG_WS_HOME environment variable must be set");

    // Define the file path for the contract address registry
    let config_address_registry_file_path = format!(
        "{}/l1x-conf/config-contract-address-registry.yaml",
        l1x_cfg_ws_home
    );

    let mut settings = Config::builder()
        // Load the YAML configuration files.
        .add_source(File::with_name(&config_address_registry_file_path))
        .build()?;

    let contract_address_registry: L1XVMContractAddressRegistry = settings.try_deserialize()
        .map_err(|err_code| {
            log::error!(
                "Failed to deserialize YAML configuration file :: {:#?} :: err {:#?}",
                config_address_registry_file_path,
                err_code
            );
            err_code
        })?;

    Ok(contract_address_registry)
}

/// Get the EBPF contract address for the given artifact and contract ID.
pub fn get_toolkit_ebpf_contract_address_for(
    artifact_id: &str,
    contract_id: Option<&str>,
) -> Result<String, String> {
    let config_address_registry =
        load_contract_address_registry().map_err(|err| {
            format!("Failed to load contract registry yaml file: {:?}", err)
        })?;

    if let Some(contract_info) = config_address_registry.l1x_vm.get(artifact_id)
    {
        if let Some(cid) = contract_id {
            if let Some(contract_instance_info) =
                contract_info.instance.get(cid)
            {
                let clean_hex_string =
                    clean_address_string(&contract_instance_info.inst_address);
                log::info!("S1 => {}", &clean_hex_string);
                Ok(clean_hex_string.to_string())
            } else {
                Err(format!(
                    "Contract instance '{}' not found for artifact '{}'",
                    cid, artifact_id
                ))
            }
        } else {
            let clean_hex_string =
                clean_address_string(&contract_info.deploy_address);
            log::info!("S2 => {}", &clean_hex_string);
            Ok(clean_hex_string)
        }
    } else {
        Err(format!(
            "Artifact '{}' not found in the contract registry",
            artifact_id
        ))
    }
}

/// Get the EVM contract address for the given artifact and contract ID.
pub fn get_toolkit_evm_contract_address_for(
    artifact_id: &str,
    contract_id: Option<&str>,
) -> Result<String, String> {
    let config_address_registry =
        load_contract_address_registry().map_err(|err| {
            format!("Failed to load contract registry yaml file: {:?}", err)
        })?;

    if let Some(contract_info) =
        config_address_registry.l1x_evm.get(artifact_id)
    {
        let clean_hex_string =
            clean_address_string(&contract_info.deploy_address);
        Ok(clean_hex_string)
    } else {
        Err(format!(
            "Artifact '{}' not found in the contract registry",
            artifact_id
        ))
    }
}

fn clean_address_string(address_to_clean: &str) -> String {
    // Trim the string and remove any leading or trailing quotes.
    let trimmed_address = address_to_clean.trim().trim_matches('"');

    // Remove the "0x" prefix from the address, if it exists.
    let clean_address =
        trimmed_address.strip_prefix("0x").unwrap_or(trimmed_address);

    // Return the clean address.
    clean_address.to_string()
}

pub fn update_toolkit_contract_address_registry(
    update_type: L1XVMContractAddressUpdateType,
) -> Result<(), String> {
    // Ensure L1X_CFG_WS_HOME environment variable is set
    let l1x_cfg_ws_home = env::var("L1X_CFG_WS_HOME")
        .expect("The L1X_CFG_WS_HOME environment variable must be set");

    // Define the file path for the contract address registry
    let config_address_registry_file_path = format!(
        "{}/l1x-conf/config-contract-address-registry.yaml",
        l1x_cfg_ws_home
    );

    // Read the existing YAML file or create a new empty config if it doesn't exist
    let mut config: L1XVMContractAddressRegistry =
        match fs::read_to_string(&config_address_registry_file_path) {
            Ok(yaml_content) => serde_yaml::from_str(&yaml_content)
                .map_err(|err_code| {
                    log::error!(
                    "Failed! Yaml to L1XVMContractAddressRegistry obj :: {}",
                    err_code
                );
                    err_code
                })
                .unwrap_or_else(|_| {
                    panic!("Failed! Yaml to L1XVMContractAddressRegistry obj!")
                }),
            Err(_) => L1XVMContractAddressRegistry {
                l1x_vm: BTreeMap::new(),
                l1x_evm: BTreeMap::new(),
            },
        };

    match update_type {
        L1XVMContractAddressUpdateType::L1XEBPF_DEPLOY {
            artifact_id,
            response_hash,
            response_address,
        } => {
            log::info!("L1XEBPF_DEPLOY :: {:#?}", response_address.clone());
            // Update the YAML structure with the response data
            let contract_info = L1XVMContractInfo {
                deploy_hash: response_hash.clone(),
                deploy_address: format!("\"0x{}\"", response_address.clone()),
                instance: BTreeMap::new(),
            };

            // Add or update the contract info in the YAML structure
            config.l1x_vm.insert(artifact_id.clone(), contract_info); // Use artifact_id as a key
        }
        L1XVMContractAddressUpdateType::L1XEBPF_INIT {
            artifact_id,
            contract_id,
            response_hash,
            response_address,
        } => {
            if let Some(contract_info) = config.l1x_vm.get_mut(&artifact_id) {
                log::info!("L1XEBPF_INIT :: {:#?}", response_address.clone());
                // Update the YAML structure with the response data
                let instance_info = L1XVMInstanceInfo {
                    inst_hash: response_hash.clone(),
                    inst_address: format!("\"0x{}\"", response_address.clone()),
                };

                contract_info
                    .instance
                    .insert(contract_id.clone(), instance_info);
            } else {
                panic!("Failed to update Contract Address Registry :: Contract Deploy Info is missing for :: {}", artifact_id);
            }
        }
        L1XVMContractAddressUpdateType::L1XEVM_DEPLOY {
            artifact_id,
            response_hash,
            response_address,
        } => {
            let response_address_clean =
                clean_address_string(&response_address);

            log::info!("L1XEVM_DEPLOY :: {:#?}", response_address_clean);
            // Update the YAML structure with the response data
            let contract_info = L1XVMContractInfo {
                deploy_hash: response_hash.to_string(),
                deploy_address: format!("\"0x{}\"", response_address_clean),
                instance: BTreeMap::new(),
            };

            // Add or update the contract info in the YAML structure
            config.l1x_evm.insert(artifact_id.clone(), contract_info); // Use artifact_id as a key
        }
    }

    // Serialize the updated YAML structure back to the file
    let yaml_file_handle = fs::File::create(&config_address_registry_file_path)
        .expect("Unable to Create The file");

    let mut buff_writer = std::io::BufWriter::new(yaml_file_handle);
    serde_yaml::to_writer(&mut buff_writer, &config)
        .expect("Unable to update Yaml File");

    buff_writer.flush().expect("Failed to flush BufWriter");

    // Close the file handle to release resources
    let _ = buff_writer.into_inner().map(|file| file.sync_all()).unwrap();

    Ok(())
}

// ================================================================================
