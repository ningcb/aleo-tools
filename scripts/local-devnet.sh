#!/bin/bash

# Read the total number of validators from the user or use a default value of 4
read -p "Enter the total number of validators (default: 4): " total_validators
total_validators=${total_validators:-4}

# Ask the user whether to clear the existing ledger logs
read -p "Do you want to clear the existing ledger logs? (y/n, default: n): " clear_logs
clear_logs=${clear_logs:-n}

# Clear the ledger logs for each validator if the user chooses to clear logs
if [[ $clear_logs == "y" ]]; then
  # Create an array to store background processes
  clean_processes=()

  for ((validator_index = 0; validator_index < total_validators; validator_index++)); do
    # Run 'snarkos clean' for each validator in the background
    snarkos clean --dev $validator_index &

    # Store the process ID of the background task
    clean_processes+=($!)
  done

  # Wait for all 'snarkos clean' processes to finish
  for process_id in "${clean_processes[@]}"; do
    wait "$process_id"
  done
fi

# Generate validator indices from 0 to (total_validators - 1)
validator_indices=($(seq 0 $((total_validators - 1))))

# Loop through the list of validator indices and create a new window for each
for validator_index in "${validator_indices[@]}"; do
  # Generate a unique and incrementing log file name based on the validator index
  log_file="$LOG_DIR/validator-$validator_index.log"

  # Send the command to start the validator to the new window and capture output to the log file
  { snarkos start --nodisplay --dev $validator_index --dev-num-validators $total_validators --validator --logfile $log_file 2>&1; } &
done

# Trap the SIGINT signal (Ctrl+C) and kill background jobs
trap 'kill $(jobs -p)' SIGINT

# Wait for all background jobs to finish
wait
