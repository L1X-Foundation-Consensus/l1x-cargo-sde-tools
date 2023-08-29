use std::{
    collections::HashMap, env, error::Error, ffi::OsStr, fmt::Display, fs,
    path::PathBuf, process::Command, str::FromStr,
};

use anyhow::Result;

#[derive(Debug)]
pub struct CloneError(String);

impl CloneError {
    pub fn new(message: String) -> Self {
        CloneError(message)
    }
}

impl Display for CloneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for CloneError {}

#[derive(Clone, Debug)]
struct Template {
    url: String,
}

impl FromStr for Template {
    type Err = CloneError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match L1XContractTemplateHub::default().repo.get(s) {
            Some(url) => Ok(Template { url: url.to_string() }),
            None => {
                Err(CloneError::new(format!("Invalid project template: {}", s)))
            }
        }
    }
}

// Define a struct to represent the L1X smart contract template hosted in GitHub structure
struct L1XContractTemplateHub {
    repo: HashMap<String, String>,
}

impl Default for L1XContractTemplateHub {
    fn default() -> Self {
        let mut repo = HashMap::new();

        repo.insert(
            "l1x-cross-chain-swap".to_string(),
            "https://github.com/L1X-Foundation-VM/l1x-templ-cross-chain-swap.git"
                .to_string(),
        );

        repo.insert(
            "l1x-ft".to_string(),
            "https://github.com/L1X-Foundation-VM/l1x-templ-ft.git".to_string(),
        );

        repo.insert(
            "l1x-nft".to_string(),
            "https://github.com/L1X-Foundation-VM/l1x-templ-nft.git"
                .to_string(),
        );
        Self { repo }
    }
}

impl L1XContractTemplateHub {
    pub fn get_template(&self, template_name: &str) -> Result<Template> {
        self.repo
            .get(template_name)
            .map(|url| Template { url: url.clone() })
            .ok_or_else(|| {
                CloneError::new(format!(
                    "Template not found: {}",
                    template_name
                ))
                .into()
            })
    }

    pub fn copy_template(
        &self,
        project_template: Template,
        out_path: PathBuf,
    ) -> Result<()> {
        log::info!(
            "Cloning template '{}' to '{}'",
            project_template.url,
            out_path.display()
        );

        Command::new("git")
            .args([
                OsStr::new("clone"),
                OsStr::new("--depth"),
                OsStr::new("1"),
                OsStr::new(&project_template.url),
                out_path.as_os_str(),
            ])
            .output()
            .map_err(|e| {
                CloneError::new(format!(
                    "Failed to clone template repository: {:?}",
                    e
                ))
            })?;

        // Remove the `.git` folder and initialize a new git repository.
        log::info!("Removing `.git` folder");
        fs::remove_dir_all(out_path.join(".git"))?;
        log::info!("Initializing new git repository");
        Command::new("git")
            .args([OsStr::new("-C"), out_path.as_os_str(), OsStr::new("init")])
            .output()
            .map_err(|_| {
                CloneError::new(format!(
                    "Failed to init repo '{:#?}'",
                    out_path.as_os_str(),
                ))
            })?;

        Ok(())
    }
}

/// Creates a new contract project from the template.
pub fn new_contract_project<P>(
    name: &str,
    template_name: Option<String>,
    proj_base_path: Option<P>,
) -> Result<()>
where
    P: AsRef<std::path::Path>,
{
    // Get the contract template hub.
    let l1x_template_hub = L1XContractTemplateHub::default();

    // Get the project template name. If no template name is specified, use the default template name.
    let project_template_name =
        template_name.unwrap_or_else(|| String::from("l1x-ft"));

    // Get the contract template from the template hub.
    let project_template =
        l1x_template_hub.get_template(&project_template_name)?;

    // Check if the contract name is valid. A contract name can only contain alphanumeric characters
    // and underscores, and it must begin with an alphabetic character.
    if !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        anyhow::bail!(
            "Contract names can only contain alphanumeric characters and underscores"
        );
    }

    if !name.chars().next().map(|c| c.is_alphabetic()).unwrap_or(false) {
        anyhow::bail!("Contract names must begin with an alphabetic character");
    }

    // Get the output directory. If no project base path is specified, use the current working directory
    // as the project base path.
    let out_dir = proj_base_path
        .map_or(env::current_dir()?, |p| p.as_ref().to_path_buf())
        .join(name);

    // Check if the output directory already exists. If it does, bail out.
    if out_dir.join("Cargo.toml").exists() {
        anyhow::bail!("A Cargo package already exists in {}", name);
    }

    // If the output directory does not exist, create it.
    if !out_dir.exists() {
        fs::create_dir(&out_dir)?;
    }

    // Copy the contract template to the output directory.
    l1x_template_hub.copy_template(project_template, out_dir)?;

    Ok(())
}

/// Setup and create a new L1X smart contract project
#[derive(Debug, clap::Args)]
#[clap(name = "new")]
pub struct NewCommand {
    /// The name of the newly created smart contract
    #[clap(long = "name")]
    name: String,
    /// The optional source contract template name
    #[clap(long = "template", value_parser)]
    template_name: Option<String>,
    /// The optional target directory for the contract project
    #[clap(long = "base-path", value_parser)]
    target_dir: Option<PathBuf>,
}

impl NewCommand {
    pub fn exec(&self) -> Result<()> {
        super::new_contract_project(
            &self.name,
            self.template_name.clone(),
            self.target_dir.as_ref(),
        )?;
        println!("Created contract {}", self.name);
        Ok(())
    }
}
