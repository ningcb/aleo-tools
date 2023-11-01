use super::*;

use anyhow::Result;
use rand::{CryptoRng, Rng};
use snarkvm::prelude::Address;
use snarkvm::prelude::Authorization;
use snarkvm::prelude::Transition;
use snarkvm::prelude::{
    Argument, Field, Future, Identifier, Literal, Plaintext, ProgramID, Register, Request,
    Response, Value, ValueType, U64,
};

pub fn authorize_transfer_public<N: Network>(
    request: AuthorizeRequest<N>,
) -> Result<AuthorizeResponse<N>> {
    // Initialize the RNG.
    let rng = &mut rand::thread_rng();

    // Get the private key.
    let private_key = request.private_key;
    // Get the recipient.
    let recipient = request.recipient;
    // Get the amount in microcredits.
    let amount_in_microcredits = request.amount_in_microcredits;
    // Get the fee in microcredits.
    // TODO (@d0cd) Use table from `credits` crate once it is up to date with snarkVM.
    let fee_in_microcredits = U64::new(263388);
    // Get the priority fee in microcredits.
    let priority_fee_in_microcredits = request.priority_fee_in_microcredits;

    // Construct the program ID and function name.
    let (program_id, function_name) = ("credits.aleo", "transfer_public");
    // Construct the inputs.
    let inputs = vec![
        Value::<N>::from(Literal::Address(recipient)),
        Value::from(Literal::U64(amount_in_microcredits)),
    ];
    // Construct the input types.
    let input_types = vec![
        ValueType::from_str("address.public")?,
        ValueType::from_str("u64.public")?,
    ];

    // Construct the request.
    let request = sign_request(
        &private_key,
        program_id,
        function_name,
        inputs,
        input_types,
        rng,
    )?;

    // Construct the outputs.
    let outputs = vec![Value::Future(Future::new(
        ProgramID::from_str(program_id)?,
        Identifier::from_str(function_name)?,
        vec![
            Argument::Plaintext(Plaintext::from(Literal::Address(Address::try_from(
                private_key,
            )?))),
            Argument::Plaintext(Plaintext::from(Literal::Address(recipient))),
            Argument::Plaintext(Plaintext::from(Literal::U64(amount_in_microcredits))),
        ],
    ))];
    // Construct the output types.
    let output_types = vec![ValueType::from_str("credits.aleo/transfer_public.future")?];
    // Construct the output registers.
    let output_registers = vec![Some(Register::from_str("r2")?)];

    // Construct the authorization.
    let (execution_id, function_authorization) =
        authorize(request, outputs, output_types, output_registers)?;

    // Construct the inputs.
    let inputs = vec![
        Value::Plaintext(Plaintext::from(Literal::U64(fee_in_microcredits))),
        Value::Plaintext(Plaintext::from(Literal::U64(priority_fee_in_microcredits))),
        Value::Plaintext(Plaintext::from(Literal::Field(execution_id))),
    ];
    // Construct the input types.
    let input_types = vec![
        ValueType::from_str("u64.public")?,
        ValueType::from_str("u64.public")?,
        ValueType::from_str("field.public")?,
    ];

    // Construct the request.
    let request = sign_request(
        &private_key,
        program_id,
        "fee_public",
        inputs,
        input_types,
        rng,
    )?;

    // Construct the outputs.
    let outputs = vec![Value::Future(Future::new(
        ProgramID::from_str(program_id)?,
        Identifier::from_str(function_name)?,
        vec![
            Argument::Plaintext(Plaintext::from(Literal::Address(Address::try_from(
                private_key,
            )?))),
            Argument::Plaintext(Plaintext::from(Literal::U64(
                fee_in_microcredits + priority_fee_in_microcredits,
            ))),
        ],
    ))];
    // Construct the output types.
    let output_types = vec![ValueType::from_str("credits.aleo/fee_public.future")?];
    // Construct the output registers.
    let output_registers = vec![Some(Register::from_str("r4")?)];
    // Construct the authorization.
    let (_, fee_authorization) = authorize(request, outputs, output_types, output_registers)?;

    // Construct the response.
    let response = AuthorizeResponse {
        function_authorization,
        fee_authorization,
    };

    // Return the response.
    Ok(response)
}

// Constructs a request from the given inputs.
// This function is to be invoked by the client.
fn sign_request<N: Network>(
    private_key: &PrivateKey<N>,
    program_id: &str,
    function_name: &str,
    inputs: Vec<Value<N>>,
    input_types: Vec<ValueType<N>>,
    rng: &mut (impl Rng + CryptoRng),
) -> Result<Request<N>> {
    // Check that the number of inputs and input types match.
    assert_eq!(inputs.len(), input_types.len());

    // Construct the program ID.
    let program_id = ProgramID::from_str(program_id)?;

    // Construct the function name.
    let function_name = Identifier::from_str(function_name)?;

    // Compute the request.
    Request::sign(
        private_key,
        program_id,
        function_name,
        inputs.into_iter(),
        &input_types,
        rng,
    )
}

// Constructs a valid authorization from a request.
// This function is to be invoked by the prover.
fn authorize<N: Network>(
    request: Request<N>,
    outputs: Vec<Value<N>>,
    output_types: Vec<ValueType<N>>,
    output_registers: Vec<Option<Register<N>>>,
) -> Result<(Field<N>, Authorization<N>)> {
    // Construct the response.
    let response = Response::new(
        request.network_id(),
        request.program_id(),
        request.function_name(),
        request.inputs().len(),
        request.tvk(),
        request.tcm(),
        outputs,
        &output_types,
        &output_registers,
    )?;

    // Construct the transition manually.
    let transition = Transition::from(&request, &response, &output_types, &output_registers)?;

    // Initialize the authorization.
    let authorization = Authorization::new(request);

    // Add the transition to the authorization.
    authorization.insert_transition(transition)?;

    // Return the execution ID and authorization.
    Ok((authorization.to_execution_id()?, authorization))
}
