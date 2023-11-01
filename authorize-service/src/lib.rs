pub mod authorize;
pub use authorize::*;

pub mod keygen;
pub use keygen::*;

pub mod request;
pub use request::*;

pub mod response;
pub use response::*;

pub mod routes;
pub use routes::*;

use snarkvm::prelude::{FromBytes, Network, PrivateKey, Testnet3, ToBytes};
use std::str::FromStr;

pub type CurrentNetwork = Testnet3;
