use super::*;

use snarkvm::prelude::{FromBytes, ToBytes};
use tokio::sync::oneshot;
use warp::{Rejection, Reply};

struct ExecutionRequest {
    function_authorization: Vec<u8>,
    fee_authorization: Vec<u8>,
    state_root: Vec<u8>,
    state_path: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
struct ExecutionResponse {
    transaction: Vec<u8>,
}

fn deserialize_request(
    request: ExecutionRequest,
) -> Result<(
    Authorization<CurrentNetwork>,
    Authorization<CurrentNetwork>,
    StaticQuery<CurrentNetwork>,
)> {
    let function_authorization = Authorization::from_bytes_le(&request.function_authorization)?;
    let fee_authorization = Authorization::from_bytes_le(&request.fee_authorization)?;
    let state_root = match &request.state_root.is_empty() {
        true => None,
        false => Some(<CurrentNetwork as Network>::StateRoot::from_bytes_le(
            &request.state_root,
        )?),
    };
    let state_path = match &request.state_path.is_empty() {
        true => None,
        false => Some(StatePath::from_bytes_le(&request.state_path)?),
    };
    let query = StaticQuery {
        state_root,
        state_path,
    };

    Ok((function_authorization, fee_authorization, query))
}

fn serialize_response(transaction: Transaction<CurrentNetwork>) -> Result<ExecutionResponse> {
    let transaction = transaction.to_bytes_le()?;
    Ok(ExecutionResponse { transaction })
}

async fn handle_request(request: ExecutionRequest) -> Result<impl Reply, Rejection> {
    let (function_authorization, fee_authorization, query) = match deserialize_request(request) {
        Ok(result) => result,
        Err(_) => return Err(warp::reject()),
    };

    let (tx, rx) = oneshot::channel();

    rayon::spawn(move || {
        let _result = tx.send(execute(function_authorization, fee_authorization, query));
    });

    let transaction = match rx.await {
        Ok(Ok(transaction)) => transaction,
        _ => return Err(warp::reject()),
    };

    match serialize_response(transaction) {
        Ok(result) => Ok(warp::reply::json(&result)),
        Err(_) => Err(warp::reject()),
    }
}
