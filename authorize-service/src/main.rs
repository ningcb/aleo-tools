mod authorize;
use authorize::*;

mod keygen;
use keygen::*;

mod utils;
use utils::*;

use snarkvm::prelude::{Deserialize, Network, PrivateKey, Serialize, Testnet3};
use std::str::FromStr;
use warp::reject::Rejection;
use warp::{Filter, Reply};

type CurrentNetwork = Testnet3;

#[derive(Deserialize, Serialize)]
struct AuthorizeRequest {
    private_key: String,
    recipient: String,
    amount_in_microcredits: u64,
    priority_fee_in_microcredits: u64,
}

#[tokio::main]
async fn main() {
    pretty_env_logger::init();

    // GET /keygen
    let keygen = warp::get()
        .and(warp::path("keygen"))
        .and(warp::path::param::<String>())
        .and(warp::path::end())
        .and_then(|seed: String| async move {
            let private_key = private_key_from_seed::<CurrentNetwork>(&seed);
            convert_to_response(private_key)
        });

    // POST /authorize
    let authorize = warp::post()
        .and(warp::path("authorize"))
        .and(warp::path::end())
        .and(warp::body::content_length_limit(1024)) // 1 kilobyte
        .and(warp::body::json())
        .and_then(|request: AuthorizeRequest| async move {
            let authorization = authorize_transfer_public::<CurrentNetwork>(
                &request.private_key,
                &request.recipient,
                request.amount_in_microcredits,
                request.priority_fee_in_microcredits,
            );
            convert_to_response(authorization)
        });

    let routes = keygen.or(authorize).with(warp::trace(
        |info| tracing::debug_span!("Debugging headers", headers = ?info.request_headers()),
    ));

    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}
