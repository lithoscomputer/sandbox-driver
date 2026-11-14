# Diagnostics

The library crates emit `tracing` spans and events. Applications choose the
subscriber and output destination. Operation fields include provider kinds,
resource IDs, states, attempts, counts, and durations. They do not include
commands, environment values, tokens, URLs, file paths, request bodies, or
command output.

The current provider executables configure a stderr subscriber. They use
`RUST_LOG` when set and default to `info`. Protocol messages remain on stdout.
The CLI supplies `warn` when its own `RUST_LOG` is unset; see the
[CLI guide](https://github.com/lithoscomputer/sandbox-driver/blob/main/docs/cli.md#provider-executables).

For the target API, see the
[shared contract](https://github.com/lithoscomputer/sandbox-driver/blob/main/docs/shared-contract.md)
for error handling and uncertain operation outcomes.
