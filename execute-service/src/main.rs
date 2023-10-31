mod execute;
use execute::*;

pub mod query;
pub use query::*;

pub mod request;
pub use request::*;

use snarkvm::circuit::{Aleo, AleoV0};
use snarkvm::ledger::block::Transaction;
use snarkvm::prelude::{
    Authorization, Deserialize, Locator, Network, Process, Serialize, StatePath, Testnet3,
};

use anyhow::{anyhow, Result};

pub type CurrentNetwork = Testnet3;
pub type CurrentAleo = AleoV0;

fn main() {
    println!("Hello, world!");
}
