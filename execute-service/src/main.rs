pub mod query;
pub use query::*;

use snarkvm::prelude::{Deserialize, Network, Serialize, StatePath, Testnet3};

use anyhow::{anyhow, Result};

type CurrentNetwork = Testnet3;

fn main() {
    println!("Hello, world!");
}
