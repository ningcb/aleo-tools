use super::*;

use anyhow::Result;
use snarkvm::prelude::Environment;
use snarkvm::prelude::Field;

pub fn private_key_from_seed<N: Network>(seed: &str) -> Result<PrivateKey<N>> {
    let seed = Field::new(<N as Environment>::Field::from_str(seed)?);
    PrivateKey::try_from(seed)
}
