use snarkvm::console::{
    account::{Address, PrivateKey},
    network::Network,
    program::{Literal, Value},
    types::U64,
};
use snarkvm::prelude::{
    Argument, Authorization, Entry, Field, Future, Group, Identifier, Owner, Plaintext, ProgramID,
    Record, Register, Request, Response, Transition, ValueType,
};

use credits::get_base_fee_in_microcredits;

use anyhow::Result;
use core::str::FromStr;
use indexmap::IndexMap;
use rand::{CryptoRng, Rng};

/// Authorizes a public transfer.
pub fn authorize_transfer_public<N: Network>(
    private_key: &str,
    recipient: &str,
    amount_in_microcredits: u64,
    priority_fee_in_microcredits: u64,
    rng: &mut (impl Rng + CryptoRng),
) -> Result<(Authorization<N>, Authorization<N>)> {
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

    // Construct the request.
    let request = request(
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
    let authorization = authorize(request, outputs, output_types, output_registers)?;
    // Get the execution ID.
    let execution_id = authorization.to_execution_id()?;
    // Authorize the fee.
    let fee_authorization = authorize_public_fee(
        &private_key,
        get_base_fee_in_microcredits("credits.aleo", "transfer_public")?,
        priority_fee_in_microcredits,
        execution_id,
        rng,
    )?;

    // Return the authorizations.
    Ok((authorization, fee_authorization))
}

/// Authorizes a private to public transfer.
#[allow(clippy::too_many_arguments)]
pub fn authorize_transfer_private_to_public<N: Network>(
    private_key: &PrivateKey<N>,
    record_microcredits: u64,
    record_nonce: &str,
    recipient: &str,
    amount_in_microcredits: u64,
    priority_fee_in_microcredits: u64,
    rng: &mut (impl Rng + CryptoRng),
) -> Result<(Authorization<N>, Authorization<N>)> {
    // Construct the program ID and function name.
    let (program_id, function_name) = ("credits.aleo", "transfer_private_to_public");
    // Construct the inputs.
    let inputs = vec![
        Value::Record(Record::<_, Plaintext<N>>::from_plaintext(
            Owner::Private(Plaintext::from(Literal::Address(Address::try_from(
                private_key,
            )?))),
            IndexMap::from([(
                Identifier::from_str("microcredits")?,
                Entry::Private(Plaintext::from(Literal::U64(U64::new(record_microcredits)))),
            )]),
            Group::from_str(record_nonce)?,
        )?),
        Value::from(Literal::Address(Address::from_str(recipient)?)),
        Value::from(Literal::U64(U64::new(amount_in_microcredits))),
    ];
    // Construct the input types.
    let input_types = vec![
        ValueType::from_str("credits.record")?,
        ValueType::from_str("address.public")?,
        ValueType::from_str("u64.public")?,
    ];

    // Construct the request.
    let request = request(
        private_key,
        program_id,
        function_name,
        inputs,
        input_types,
        rng,
    )?;

    // Construct the outputs.
    let outputs = vec![
        Value::Record(Record::<_, Plaintext<N>>::from_plaintext(
            Owner::Private(Plaintext::from(Literal::Address(Address::try_from(
                private_key,
            )?))),
            IndexMap::from([(
                Identifier::from_str("microcredits")?,
                Entry::Private(Plaintext::from(Literal::U64(U64::new(
                    record_microcredits - amount_in_microcredits,
                )))),
            )]),
            {
                // Prepare the index as a field element.
                let index = Field::from_u64(4u64);
                // Compute the randomizer as `HashToScalar(tvk || index)`.
                let randomizer = N::hash_to_scalar_psd2(&[*request.tvk(), index])?;
                // Compute the nonce from the randomizer.
                N::g_scalar_multiply(&randomizer)
            },
        )?),
        Value::Future(Future::new(
            ProgramID::from_str(program_id)?,
            Identifier::from_str(function_name)?,
            vec![
                Argument::Plaintext(Plaintext::from(Literal::Address(Address::from_str(
                    recipient,
                )?))),
                Argument::Plaintext(Plaintext::from(Literal::U64(U64::new(
                    amount_in_microcredits,
                )))),
            ],
        )),
    ];

    // Construct the output types.
    let output_types = vec![
        ValueType::from_str("credits.record")?,
        ValueType::from_str("credits.aleo/transfer_private_to_public.future")?,
    ];
    // Construct the output registers.
    let output_registers = vec![
        Some(Register::from_str("r4")?),
        Some(Register::from_str("r5")?),
    ];

    // Construct the authorization.
    let authorization = authorize(request, outputs, output_types, output_registers)?;

    // Get the execution ID.
    let execution_id = authorization.to_execution_id()?;

    // Authorize the fee.
    let fee_authorization = authorize_public_fee(
        private_key,
        300000, // TODO (@d0cd): Compute a better approximation for the fee.
        priority_fee_in_microcredits,
        execution_id,
        rng,
    )?;

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

    // Construct the request.
    let request = request(
        private_key,
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
    authorize(request, outputs, output_types, output_registers)
}

/// Constructs a request from the given inputs.
fn request<N: Network>(
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

/// Constructs a valid authorization from a request.
fn authorize<N: Network>(
    request: Request<N>,
    outputs: Vec<Value<N>>,
    output_types: Vec<ValueType<N>>,
    output_registers: Vec<Option<Register<N>>>,
) -> Result<Authorization<N>> {
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

    // Return the authorization.
    Ok(authorization)
}

#[cfg(test)]
mod test {
    use super::*;

    use snarkvm::ledger::store::ConsensusStore;
    use snarkvm::prelude::store::helpers::memory::ConsensusMemory;
    use snarkvm::prelude::{Testnet3, ViewKey, VM};
    use snarkvm::utilities::TestRng;

    type CurrentNetwork = Testnet3;

    #[test]
    fn test_authorize_transfer_public() {
        // Initialize an RNG.
        let rng = &mut TestRng::default();
        // Initialize a VM.
        let vm = VM::<CurrentNetwork, ConsensusMemory<CurrentNetwork>>::from(
            ConsensusStore::open(None).unwrap(),
        )
        .unwrap();
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
        let (authorization, fee_authorization) = authorize_transfer_public(
            &sender_private_key.to_string(),
            &recipient_address.to_string(),
            100,
            10,
            rng,
        )
        .unwrap();

        // Execute the authorization.
        assert!(vm
            .execute_authorization(authorization, Some(fee_authorization), None, rng)
            .is_ok());
    }

    #[test]
    fn test_authorize_transfer_private_to_public() {
        // Initialize an RNG.
        let rng = &mut TestRng::default();
        // Initialize a VM.
        let vm = VM::<CurrentNetwork, ConsensusMemory<CurrentNetwork>>::from(
            ConsensusStore::open(None).unwrap(),
        )
        .unwrap();
        // Initialize the genesis private key.
        let genesis_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        // Create the genesis block.
        let genesis_block = vm.genesis_beacon(&genesis_private_key, rng).unwrap();
        // Add the genesis block to the VM.
        vm.add_next_block(&genesis_block).unwrap();

        // Get a valid record.
        let (_, record) = genesis_block.records().next().unwrap();
        let record = record
            .decrypt(&ViewKey::try_from(&genesis_private_key).unwrap())
            .unwrap();

        // Get the number of microcredits in the record and record nonce.
        let record_microcredits = match record
            .data()
            .get(&Identifier::from_str("microcredits").unwrap())
            .unwrap()
        {
            Entry::Private(Plaintext::Literal(Literal::U64(amount), _)) => amount,
            _ => panic!("Invalid amount"),
        };
        let record_nonce = record.nonce();

        // Initialize a private key for the recipient.
        let recipient_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let recipient_address = Address::try_from(&recipient_private_key).unwrap();

        // Initialize an authorization.
        let (authorization, fee_authorization) = authorize_transfer_private_to_public(
            &genesis_private_key,
            **record_microcredits,
            &record_nonce.to_string(),
            &recipient_address.to_string(),
            100,
            10,
            rng,
        )
        .unwrap();

        // Execute the authorization.
        assert!(vm
            .execute_authorization(authorization, Some(fee_authorization), None, rng)
            .is_ok());
    }
}
