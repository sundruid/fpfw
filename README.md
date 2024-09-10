# fpfw
Fingerprint Firewall

# fpfwd and fpfw Scripts

## Overview

The `fpfwd` and `fpfw` scripts are designed to manage IP blocking based on fingerprints generated by the `muonfp` tool. These scripts use SQLite to store and manage fingerprints and associated IP addresses, and `nftables` to enforce IP blocking rules.

- **fpfwd**: This script runs as a daemon, continuously monitoring for changes in fingerprints and updating `nftables` rules accordingly.
- **fpfw**: This script provides a command-line interface to add or remove fingerprints, show currently blocked fingerprints, and flush all `nftables` rules.

## Dependencies

These scripts require the `muonfp` tool, which can be found at [sundruid/muonfp](https://github.com/sundruid/muonfp).

## Configuration

Before running the scripts, ensure the following configurations are set correctly in both scripts:

- `PART_FILE_DIRECTORY`: Directory containing the `.part` files generated by `muonfp`.
- `LOG_FILE`: Log file for script activity.
- `POLL_INTERVAL`: Polling interval in seconds for the `fpfwd` script.
- `DATABASE_FILE`: SQLite database file used by both scripts.

## Usage

### fpfwd Script

The `fpfwd` script runs as a daemon and performs the following tasks:

- Sets up the SQLite database and creates necessary tables.
- Reconciles `nftables` rules with the database.
- Processes fingerprint changes and updates `nftables` rules.
- Processes fingerprint removals and removes associated IP addresses from `nftables`.

#### Running fpfwd

To run the `fpfwd` script, use the following command:


### fpfw Script

The `fpfw` script provides a command-line interface to manage fingerprints and `nftables` rules. It supports the following commands:

- `add <fingerprint>`: Add a fingerprint to be blocked.
- `remove <fingerprint>`: Remove a fingerprint from being blocked.
- `show`: Show all unique fingerprints currently being blocked.
- `flush`: Flush all `nftables` rules and clear the database.
- `-h, --help`: Show the help message and exit.

#### Running fpfw

To use the `fpfw` script, use the following command format:

  ./fpfwd.py


### fpfw Script

The `fpfw` script provides a command-line interface to manage fingerprints and `nftables` rules. It supports the following commands:

- `add <fingerprint>`: Add a fingerprint to be blocked.
- `remove <fingerprint>`: Remove a fingerprint from being blocked.
- `show`: Show all unique fingerprints currently being blocked.
- `flush`: Flush all `nftables` rules and clear the database.
- `-h, --help`: Show the help message and exit.

#### Running fpfw

To use the `fpfw` script, use the following command format:


  ./fpfw.py <command> [fingerprint]


#### Examples

- Add a fingerprint:
    ```sh
    ./fpfw.py add <fingerprint>
    ```

- Remove a fingerprint:
    ```sh
    ./fpfw.py remove <fingerprint>
    ```

- Show currently blocked fingerprints:
    ```sh
    ./fpfw.py show
    ```

- Flush all `nftables` rules and clear the database:
    ```sh
    ./fpfw.py flush
    ```

## Logging

Both scripts log their activities to the specified log file (`fpfwd.log` by default). Ensure the log file path is writable by the user running the scripts.

## License

These scripts are provided under the MIT License. See the LICENSE file for more information.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes.

## Support

If you encounter any issues or have questions, please open an issue on the GitHub repository.
