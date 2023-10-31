use super::*;

use std::cell::RefCell;

// Initialize a thread-local `Process`.
thread_local! {
    static PROCESS: RefCell<Process<CurrentNetwork>> = RefCell::new(Process::load().unwrap());
}

fn execute(
    function_authorization: Authorization<CurrentNetwork>,
    fee_authorization: Authorization<CurrentNetwork>,
    query: StaticQuery<CurrentNetwork>,
) -> Result<Transaction<CurrentNetwork>> {
    PROCESS.with(|process| {
        // Initialize an RNG.
        let rng = &mut rand::thread_rng();

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
