use super::*;

use warp::{http::Response, hyper::body::Bytes, Filter, Rejection, Reply};

// POST /execute
pub fn execute_route() -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::post()
        .and(warp::path("execute"))
        .and(warp::path::end())
        .and(warp::body::content_length_limit(32 * 1024)) // 32 kilobytes TODO (@d0cd): Check
        .and(warp::body::bytes())
        .and_then(|bytes: Bytes| async move {
            let request = match ExecuteRequest::from_bytes_le(&bytes) {
                Ok(request) => request,
                Err(_) => return Err(warp::reject()),
            };
            let execution = match execute(request) {
                Ok(execution) => execution,
                Err(_) => return Err(warp::reject()),
            };
            let bytes = match execution.to_bytes_le() {
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
