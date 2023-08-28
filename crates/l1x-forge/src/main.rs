#![deny(unused_crate_dependencies)]

mod cmd;

use clap::Parser;
use std::{fmt::Debug, str::FromStr};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct HexData(pub Vec<u8>);

impl FromStr for HexData {
    type Err = hex::FromHexError;

    fn from_str(input: &str) -> std::result::Result<Self, Self::Err> {
        hex::decode(input).map(HexData)
    }
}

#[derive(Debug, clap::Parser)]
#[clap(bin_name = "l1x-forge")]
pub(crate) enum Opts {
    /// Utilities to develop Wasm smart contracts.
    #[command(
        name = "new",
        about = "Create new project workspace from template."
    )]
    New(cmd::NewCommand),
}

fn main() {
    tracing_subscriber::fmt::init();
    let exec_status = match Opts::parse() {
        Opts::New(new_cmd) => new_cmd.exec(),
    };

    match exec_status {
        Ok(()) => {}
        Err(err) => {
            eprintln!("{err:?}");
            std::process::exit(1);
        }
    }
}
