# Diagnostics

The library crates emit `tracing` spans and events. Applications choose the
subscriber and output destination. Operation fields include provider kinds,
resource IDs, states, attempts, counts, and durations. They do not include
commands, environment values, tokens, URLs, file paths, request bodies, or
command output.

The `lithos-sandbox` CLI writes diagnostics to stderr. It uses `RUST_LOG`
when set; otherwise it logs nothing, and `-v`, `-vv`, `-vvv` and `-vvvv` select
warn, info, debug and trace. The Host, Docker, and Daytona provider
executables, which are being removed, also log to stderr, using `RUST_LOG` when
set and `info` otherwise.

For error handling and uncertain operation outcomes, see the
[design](https://github.com/lithoscomputer/sandbox-driver/blob/main/docs/design.md#lifecycle-fences-and-uncertain-outcomes).
