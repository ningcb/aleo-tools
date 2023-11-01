use authorize_service::*;
use execute_service::*;
use std::str::FromStr;

use anyhow::{bail, Result};
use reqwest::Client;
use snarkvm::ledger::block::Transaction;
use snarkvm::prelude::{
    Address, Field, FromBytes, Network, PrivateKey, Testnet3, ToBytes, Uniform, U64,
};

const KEYGEN_URL: &str = "http://localhost:8080/keygen";
const AUTHORIZE_URL: &str = "http://localhost:8080/authorize";
const EXECUTE_URL: &str = "http://localhost:8081/execute";

const BROADCAST_URL: &str = "http://localhost:3033/testnet3/transaction/broadcast";
const STATE_ROOT_URL: &str = "http://localhost:3033/testnet3/stateRoot/latest";

const DEVNET_PRIVATE_KEY: &str = "APrivateKey1zkp8CZNn3yeCseEtxuVPbDCwSyhGW6yZKUYKfgXmcpoGPWH";

type CurrentNetwork = Testnet3;

#[tokio::main]
async fn main() -> Result<()> {
    // Create a `Client` instance.
    let client = Client::new();

    // Initialize a random number generator.
    let rng = &mut rand::thread_rng();

    // Generate a seed.
    let seed = Field::<CurrentNetwork>::rand(rng);

    // Construct the url for the keygen request.
    let url = format!("{}/{}", KEYGEN_URL, *seed);

    // Send the request.
    let response = client.get(url).send().await?;

    // If the request was successful, deserialize the response bytes as a `PrivateKey`.
    let _private_key = match response.status().is_success() {
        true => {
            let bytes = response.bytes().await?;
            PrivateKey::<CurrentNetwork>::from_bytes_le(&bytes)?
        }
        false => bail!("Keygen request failed with status: {}", response.status()),
    };

    // Use the `DEVNET_PRIVATE_KEY`, if desired.
    let private_key = PrivateKey::<CurrentNetwork>::from_str(DEVNET_PRIVATE_KEY)?;

    println!("Using private key: {}", private_key);

    // Construct the recipient address.
    let recipient =
        Address::from_str("aleo16y9l270rdyun3tpfqjppj7hmvtwc03tl852q4v7fddfrus9ansrqsv35x7")?;
    // Construct the amount.
    let amount_in_microcredits = U64::new(1000);
    // Construct the priority fee.
    let priority_fee_in_microcredits = U64::new(10);

    // Construct an `AuthorizeRequest`.
    let authorize_request = AuthorizeRequest {
        private_key,
        recipient,
        amount_in_microcredits,
        priority_fee_in_microcredits,
    };

    // Send the request.
    let response = client
        .post(AUTHORIZE_URL)
        .body(authorize_request.to_bytes_le()?)
        .header("Content-Type", "application/octet-stream")
        .send()
        .await?;

    // If the request was successful, deserialize the response bytes as an `AuthorizeResponse`.
    let authorize_response = match response.status().is_success() {
        true => {
            let bytes = response.bytes().await?;
            AuthorizeResponse::<CurrentNetwork>::from_bytes_le(&bytes)?
        }
        false => bail!(
            "Authorization request failed with status: {}",
            response.status()
        ),
    };

    // Get the latest state root.
    let response = client.get(STATE_ROOT_URL).send().await?;

    // If the request was successful, deserialize the response JSON as a `StateRoot`.
    let state_root = match response.status().is_success() {
        true => {
            response
                .json::<<CurrentNetwork as Network>::StateRoot>()
                .await?
        }
        false => bail!(
            "State root request failed with status: {}",
            response.status()
        ),
    };

    println!("Using state root: {}", state_root);

    // Construct an `ExecuteRequest`.
    let execute_request = ExecuteRequest {
        function_authorization: authorize_response.function_authorization,
        fee_authorization: authorize_response.fee_authorization,
        state_root: Some(state_root),
        state_path: None,
    };

    // Send the request.
    let response = client
        .post(EXECUTE_URL)
        .body(execute_request.to_bytes_le()?)
        .header("Content-Type", "application/octet-stream")
        .send()
        .await?;

    // If the request was successful, deserialize the response bytes as a `Transaction`.
    let transaction = match response.status().is_success() {
        true => {
            let bytes = response.bytes().await?;
            Transaction::<CurrentNetwork>::from_bytes_le(&bytes)?
        }
        false => bail!(
            "Execution request failed with status: {}",
            response.status()
        ),
    };

    // Send the transaction as a broadcast request as JSON.
    let response = client.post(BROADCAST_URL).json(&transaction).send().await?;

    // If the request was successful, print the response and the response body.
    match response.status().is_success() {
        true => {
            println!(
                "Broadcast request succeeded with status: {}",
                response.status()
            );
            println!(
                "Broadcast request response body: {}",
                response.text().await?
            );
        }
        false => bail!(
            "Broadcast request failed with status: {}",
            response.status()
        ),
    }

    Ok(())
}
