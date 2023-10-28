use super::*;

pub fn convert_to_response<T: Serialize>(
    result: anyhow::Result<T>,
) -> Result<impl Reply, Rejection> {
    match result {
        Ok(result) => Ok(warp::reply::json(&result)),
        Err(_) => Err(warp::reject()),
    }
}
