mod execute;
use execute::*;

pub mod query;
pub use query::*;

pub mod request;
pub use request::*;

use snarkvm::circuit::AleoV0;
use snarkvm::ledger::block::Transaction;
use snarkvm::prelude::{
    Authorization, Deserialize, Locator, Network, Process, Serialize, StatePath, Testnet3,
};

use anyhow::{anyhow, Result};
use warp::Filter;

pub type CurrentNetwork = Testnet3;
pub type CurrentAleo = AleoV0;

#[tokio::main]
async fn main() {
    pretty_env_logger::init();

    // POST /execute
    let authorize = warp::post()
        .and(warp::path("execute"))
        .and(warp::path::end())
        .and(warp::body::content_length_limit(32 * 1024)) // 32 kilobytes TODO (@d0cd): Check
        .and(warp::body::json())
        .and_then(|request: ExecutionRequest| async move { handle_request(request).await });

    let routes = authorize.with(warp::trace(
        |info| tracing::debug_span!("Debugging headers", headers = ?info.request_headers()),
    ));

    warp::serve(routes).run(([127, 0, 0, 1], 3031)).await;
}
