use super::*;

#[derive(Deserialize, Serialize)]
pub struct AuthorizeRequest {
    pub private_key: String,
    pub recipient: String,
    pub amount_in_microcredits: u64,
    pub priority_fee_in_microcredits: u64,
}
