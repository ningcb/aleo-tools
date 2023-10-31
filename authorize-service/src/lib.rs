pub mod authorize;
pub use authorize::*;

pub mod keygen;
pub use keygen::*;

mod request;
pub use request::*;

mod utils;
pub use utils::*;

use snarkvm::prelude::{Deserialize, Network, PrivateKey, Serialize, Testnet3};
use std::str::FromStr;
use warp::reject::Rejection;
use warp::Reply;

pub type CurrentNetwork = Testnet3;
