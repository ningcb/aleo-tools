use snarkvm::console::{
    account::{Address, PrivateKey},
    network::Network,
    program::{Literal, Value},
    types::U64,
};
use snarkvm::prelude::{
    Argument, Authorization, Field, Future, Identifier, Plaintext, ProgramID, Register, Request,
    Response, Transition, ValueType, Zero,
};

use anyhow::Result;
use core::str::FromStr;
use rand::{CryptoRng, Rng};

/// Returns a transaction that transfers public credits from the sender to the recipient.
pub fn transfer_public<N: Network>(
    private_key: &str,
    recipient: &str,
    amount_in_microcredits: u64,
    fee_in_microcredits: u64,
    rng: &mut (impl Rng + CryptoRng),
) -> Result<(Authorization<N>, Option<Authorization<N>>)> {
    // Initialize the private key.
    let private_key = PrivateKey::<N>::from_str(private_key)?;
    // Initialize the recipient.
    let recipient = Address::<N>::from_str(recipient)?;
    // Initialize the amount in microcredits.
    let amount_in_microcredits = U64::<N>::new(amount_in_microcredits);

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
    let authorization = authorize(
        &private_key,
        program_id,
        function_name,
        inputs,
        input_types,
        outputs,
        output_types,
        output_registers,
        rng,
    )?;
    // Get the execution ID.
    let execution_id = authorization.to_execution_id()?;
    // Authorize the fee.
    let fee_authorization = match fee_in_microcredits.is_zero() {
        true => None,
        false => Some(authorize_public_fee(
            &private_key,
            fee_in_microcredits,
            0,
            execution_id,
            rng,
        )?),
    };

    // Return the authorizations.
    Ok((authorization, fee_authorization))
}

/// Authorizes a public fee.
fn authorize_public_fee<N: Network>(
    private_key: &PrivateKey<N>,
    fee_in_microcredits: u64,
    priority_fee_in_microcredits: u64,
    deployment_or_execution_id: Field<N>,
    rng: &mut (impl Rng + CryptoRng),
) -> Result<Authorization<N>> {
    // Construct the program ID and function name.
    let (program_id, function_name) = ("credits.aleo", "fee_public");
    // Construct the inputs.
    let inputs = vec![
        Value::Plaintext(Plaintext::from(Literal::U64(U64::new(fee_in_microcredits)))),
        Value::Plaintext(Plaintext::from(Literal::U64(U64::new(
            priority_fee_in_microcredits,
        )))),
        Value::Plaintext(Plaintext::from(Literal::Field(deployment_or_execution_id))),
    ];
    // Construct the input types.
    let input_types = vec![
        ValueType::from_str("u64.public")?,
        ValueType::from_str("u64.public")?,
        ValueType::from_str("field.public")?,
    ];
    // Construct the outputs.
    let outputs = vec![Value::Future(Future::new(
        ProgramID::from_str(program_id)?,
        Identifier::from_str(function_name)?,
        vec![
            Argument::Plaintext(Plaintext::from(Literal::Address(Address::try_from(
                private_key,
            )?))),
            Argument::Plaintext(Plaintext::from(Literal::U64(U64::new(
                fee_in_microcredits + priority_fee_in_microcredits,
            )))),
        ],
    ))];
    // Construct the output types.
    let output_types = vec![ValueType::from_str("credits.aleo/fee_public.future")?];
    // Construct the output registers.
    let output_registers = vec![Some(Register::from_str("r4")?)];
    // Construct the authorization.
    authorize(
        private_key,
        program_id,
        function_name,
        inputs,
        input_types,
        outputs,
        output_types,
        output_registers,
        rng,
    )
}

/// An internal method that authorizes a function call with a corresponding fee.
#[allow(clippy::too_many_arguments)]
fn authorize<N: Network>(
    private_key: &PrivateKey<N>,
    program_id: &str,
    function_name: &str,
    inputs: Vec<Value<N>>,
    input_types: Vec<ValueType<N>>,
    outputs: Vec<Value<N>>,
    output_types: Vec<ValueType<N>>,
    output_registers: Vec<Option<Register<N>>>,
    rng: &mut (impl Rng + CryptoRng),
) -> Result<Authorization<N>> {
    // Check that the number of inputs and input types match.
    assert_eq!(inputs.len(), input_types.len());
    let num_inputs = inputs.len();

    // Check that the number of outputs, output types, and output registers match.
    assert_eq!(outputs.len(), output_types.len());
    assert_eq!(outputs.len(), output_registers.len());

    // Construct the program ID.
    let program_id = ProgramID::from_str(program_id)?;

    // Construct the function name.
    let function_name = Identifier::from_str(function_name)?;

    // Compute the request.
    let request = Request::sign(
        private_key,
        program_id,
        function_name,
        inputs.into_iter(),
        &input_types,
        rng,
    )?;

    // Initialize the authorization.
    let authorization = Authorization::new(request.clone());

    // Construct the response.
    let response = Response::new(
        request.network_id(),
        request.program_id(),
        request.function_name(),
        num_inputs,
        request.tvk(),
        request.tcm(),
        outputs,
        &output_types,
        &output_registers,
    )?;

    // Construct the transition manually.
    let transition = Transition::from(&request, &response, &output_types, &output_registers)?;

    // Add the transition to the authorization.
    authorization.insert_transition(transition)?;

    // Return the authorization.
    Ok(authorization)
}

#[cfg(test)]
mod test {
    use super::*;

    use snarkvm::prelude::store::helpers::memory::ConsensusMemory;
    use snarkvm::prelude::{Testnet3, VM};
    use snarkvm::ledger::store::ConsensusStore;
    use snarkvm::utilities::TestRng;

    type CurrentNetwork = Testnet3;


    #[test]
    fn test_authorize_public() {
        // Initialize an RNG.
        let rng = &mut TestRng::default();
        // Initialize a VM.
        let vm = VM::<CurrentNetwork, ConsensusMemory<CurrentNetwork>>::from(
            ConsensusStore::open(None).unwrap(),
        ).unwrap();
        // Initialize the genesis private key.
        let genesis_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        // Create the genesis block.
        let genesis_block = vm.genesis_beacon(&genesis_private_key, rng).unwrap();
        // Add the genesis block to the VM.
        vm.add_next_block(&genesis_block).unwrap();

        // Initialize a private key for the sender.
        let sender_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        // Initialize a private key for the recipient.
        let recipient_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let recipient_address = Address::try_from(&recipient_private_key).unwrap();

        // Initialize an authorization.
        let (authorization, fee_authorization) = transfer_public(
            &sender_private_key.to_string(),
            &recipient_address.to_string(),
            100,
            10,
            rng,
        ).unwrap();

        // Execute the authorization.
        assert!(vm.execute_authorization(authorization, fee_authorization, None, rng).is_ok());
    }
}
