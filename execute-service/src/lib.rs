mod execute;
use execute::*;

pub mod query;
pub use query::*;

pub mod request;
pub use request::*;

pub mod routes;
pub use routes::*;

use snarkvm::circuit::AleoV0;
use snarkvm::ledger::block::Transaction;
use snarkvm::prelude::{
    Authorization, FromBytes, Locator, Network, Process, StatePath, Testnet3, ToBytes,
};

use anyhow::{anyhow, Result};

pub type CurrentNetwork = Testnet3;
pub type CurrentAleo = AleoV0;
