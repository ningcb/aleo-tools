use super::*;

use warp::{http::Response, hyper::body::Bytes, Filter, Rejection, Reply};

// GET /keygen
pub fn keygen_route() -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::get()
        .and(warp::path("keygen"))
        .and(warp::path::param::<String>())
        .and(warp::path::end())
        .and_then(|seed: String| async move {
            let private_key = match private_key_from_seed::<CurrentNetwork>(&seed) {
                Ok(private_key) => private_key,
                Err(_) => return Err(warp::reject()),
            };
            let bytes = match private_key.to_bytes_le() {
                Ok(bytes) => bytes,
                Err(_) => return Err(warp::reject()),
            };
            let response = match Response::builder()
                .header("content-type", "application/octet-stream")
                .body(bytes)
            {
                Ok(response) => response,
                Err(_) => return Err(warp::reject()),
            };
            Ok(response)
        })
}

// POST /authorize
pub fn authorize_route() -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::post()
        .and(warp::path("authorize"))
        .and(warp::path::end())
        .and(warp::body::content_length_limit(1024)) // 1 kilobyte
        .and(warp::body::bytes())
        .and_then(|bytes: Bytes| async move {
            let request = match AuthorizeRequest::from_bytes_le(&bytes) {
                Ok(request) => request,
                Err(_) => return Err(warp::reject()),
            };
            let authorization = match authorize_transfer_public::<CurrentNetwork>(request) {
                Ok(authorization) => authorization,
                Err(_) => return Err(warp::reject()),
            };
            let bytes = match authorization.to_bytes_le() {
                Ok(bytes) => bytes,
                Err(_) => return Err(warp::reject()),
            };
            let response = match Response::builder()
                .header("content-type", "application/octet-stream")
                .body(bytes)
            {
                Ok(response) => response,
                Err(_) => return Err(warp::reject()),
            };
            Ok(response)
        })
}
