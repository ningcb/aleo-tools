use super::*;

use std::cell::RefCell;

// Initialize a thread-local `Process`.
thread_local! {
    static PROCESS: RefCell<Process<CurrentNetwork>> = RefCell::new(Process::load().unwrap());
}

pub fn execute(
    execute_request: ExecuteRequest<CurrentNetwork>,
) -> Result<Transaction<CurrentNetwork>> {
    PROCESS.with(|process| {
        // Initialize an RNG.
        let rng = &mut rand::thread_rng();

        // Get the function authorization.
        let function_authorization = execute_request.function_authorization;
        // Get the fee authorization.
        let fee_authorization = execute_request.fee_authorization;
        // Get the state root.
        let state_root = execute_request.state_root;
        // Get the state path.
        let state_path = execute_request.state_path;

        // Construct the query.
        let query = StaticQuery::new(state_root, state_path);

        // Construct the locator of the main function.
        let locator = {
            let request = function_authorization.peek_next()?;
            Locator::new(*request.program_id(), *request.function_name()).to_string()
        };

        // Execute the function authorization.
        let (_, mut trace) = process
            .borrow()
            .execute::<CurrentAleo>(function_authorization)?;

        // Prepare the trace.
        trace.prepare(query.clone())?;

        // Compute the proof and construct the execution.
        let execution = trace.prove_execution::<CurrentAleo, _>(&locator, rng)?;

        // Execute the fee authorization.
        let (_, mut trace) = process.borrow().execute::<CurrentAleo>(fee_authorization)?;

        // Prepare the trace.
        trace.prepare(query)?;

        // Compute the proof and construct the fee.
        let fee = trace.prove_fee::<CurrentAleo, _>(rng)?;

        // Construct the transaction.
        Transaction::from_execution(execution, Some(fee))
    })
}
