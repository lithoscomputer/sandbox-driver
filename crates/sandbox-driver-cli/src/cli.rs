use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "lithos-sandbox",
    version,
    about = "Manage sandboxes across sandbox-driver providers"
)]
pub(crate) struct Cli {
    /// Provider profile name, or one of: host, docker, daytona.
    #[arg(short, long, global = true)]
    pub provider: Option<String>,

    /// Configuration file. Defaults to the platform config directory.
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    /// Format for command results.
    #[arg(long, value_enum, default_value_t = OutputFormat::Table, global = true)]
    pub output: OutputFormat,

    /// Format for operation progress on stderr.
    #[arg(long, value_enum, default_value_t = EventFormat::Human, global = true)]
    pub events: EventFormat,

    /// Increase diagnostic logging. Repeat for more detail.
    #[arg(short, long, action = ArgAction::Count, global = true)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Inspect providers and their capabilities.
    Provider {
        #[command(subcommand)]
        command: ProviderCommand,
    },
    /// Manage sandboxes and run commands in them.
    Sandbox {
        #[command(subcommand)]
        command: Box<SandboxCommand>,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum ProviderCommand {
    /// List built-in providers and configured profiles.
    List,
    /// Check whether the selected provider is reachable and authorized.
    Health,
    /// Show the selected provider's capabilities.
    Capabilities,
}

#[derive(Debug, Subcommand)]
pub(crate) enum SandboxCommand {
    /// Create a sandbox.
    Create(CreateArgs),
    /// Create a sandbox, run one command, and clean up.
    Run(RunArgs),
    /// List sandboxes.
    List(ListArgs),
    /// Show a sandbox's current status.
    Inspect(SandboxIdArgs),
    /// Start a sandbox.
    Start(StateChangeArgs),
    /// Stop a sandbox.
    Stop(StateChangeArgs),
    /// Pause a sandbox while preserving memory.
    Pause(StateChangeArgs),
    /// Resume a paused sandbox.
    Resume(StateChangeArgs),
    /// Move a stopped sandbox to cold storage.
    Archive(StateChangeArgs),
    /// Ask the provider to repair a sandbox in the error state.
    Recover(StateChangeArgs),
    /// Reset a sandbox's idle timers.
    RefreshActivity(SandboxIdArgs),
    /// Restore a recently deleted sandbox.
    Undelete(SandboxIdArgs),
    /// Delete a sandbox.
    Delete(SandboxIdArgs),
    /// Run a command in a sandbox.
    Exec(ExecArgs),
    /// Open an interactive shell in a sandbox.
    Shell(SandboxIdArgs),
    /// Transfer files to or from a sandbox.
    Fs {
        #[command(subcommand)]
        command: FsCommand,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum OutputFormat {
    Table,
    Json,
    Id,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum EventFormat {
    Human,
    Json,
    Off,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum SandboxKindArg {
    Container,
    VirtualMachine,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum NetworkArg {
    ProviderDefault,
    AllowAll,
    Block,
}

#[derive(Debug, Args)]
pub(crate) struct CreateArgs {
    #[command(flatten)]
    pub spec: CreateSpecArgs,

    /// Wait until the sandbox reaches a stable state.
    #[arg(long)]
    pub wait: bool,
}

#[derive(Debug, Args)]
#[group(id = "source", multiple = false)]
pub(crate) struct CreateSpecArgs {
    /// Read the complete SandboxSpec from a JSON file. Use `-` for stdin.
    #[arg(long)]
    pub spec: Option<PathBuf>,

    /// Create from an OCI image reference.
    #[arg(long, group = "source")]
    pub image: Option<String>,

    /// Create from the contents of a Dockerfile.
    #[arg(long, group = "source")]
    pub dockerfile: Option<PathBuf>,

    /// Create from an existing snapshot ID or name.
    #[arg(long, group = "source")]
    pub snapshot: Option<String>,

    /// Create a Host sandbox backed by a directory.
    #[arg(long, group = "source")]
    pub host_directory: bool,

    #[arg(long)]
    pub name: Option<String>,

    #[arg(long)]
    pub kind: Option<SandboxKindArg>,

    #[arg(long)]
    pub cpu: Option<u32>,

    #[arg(long)]
    pub memory_mb: Option<u64>,

    #[arg(long)]
    pub disk_mb: Option<u64>,

    #[arg(long)]
    pub gpus: Option<u32>,

    /// Set an environment variable as KEY=VALUE. Repeat as needed.
    #[arg(long = "env", value_name = "KEY=VALUE")]
    pub env: Vec<String>,

    /// Set a label as KEY=VALUE. Repeat as needed.
    #[arg(long = "label", value_name = "KEY=VALUE")]
    pub labels: Vec<String>,

    /// Set the sandbox workspace. This designates a caller-owned Host
    /// directory.
    #[arg(long = "workspace")]
    pub working_directory: Option<String>,

    #[arg(long, value_enum)]
    pub network: Option<NetworkArg>,

    #[arg(long)]
    pub region: Option<String>,

    #[arg(long)]
    pub ephemeral: bool,

    /// Provider-specific creation options as a JSON value.
    #[arg(long, value_name = "JSON")]
    pub provider_config: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct RunArgs {
    #[command(flatten)]
    pub spec: CreateSpecArgs,

    #[command(flatten)]
    pub exec: ExecOptions,

    /// Preserve the sandbox after the command exits.
    #[arg(long)]
    pub keep: bool,

    /// Command and arguments to execute. Separate them with `--`.
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

#[derive(Debug, Args)]
pub(crate) struct ListArgs {
    /// Require a label as KEY=VALUE. Repeat to require all labels.
    #[arg(long = "label", value_name = "KEY=VALUE")]
    pub labels: Vec<String>,
}

#[derive(Debug, Args)]
pub(crate) struct SandboxIdArgs {
    pub id: String,
}

#[derive(Debug, Args)]
pub(crate) struct StateChangeArgs {
    pub id: String,

    /// Wait for the requested stable state.
    #[arg(long)]
    pub wait: bool,
}

#[derive(Debug, Args)]
pub(crate) struct ExecArgs {
    pub id: String,

    #[command(flatten)]
    pub options: ExecOptions,

    /// Command and arguments to execute. Separate them with `--`.
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

#[derive(Debug, Args)]
pub(crate) struct ExecOptions {
    /// Run in this sandbox directory.
    #[arg(long)]
    pub working_dir: Option<String>,

    /// Set a command environment variable as KEY=VALUE. Repeat as needed.
    #[arg(long = "exec-env", value_name = "KEY=VALUE")]
    pub exec_env: Vec<String>,

    /// Send local stdin to the command, then close it.
    #[arg(long)]
    pub stdin: bool,

    /// Stop the command after this many seconds.
    #[arg(long, conflicts_with = "no_timeout")]
    pub timeout_seconds: Option<u64>,

    /// Wait for the command without a deadline.
    #[arg(long)]
    pub no_timeout: bool,
}

#[derive(Debug, Subcommand)]
pub(crate) enum FsCommand {
    /// Upload one local file.
    Upload {
        id:     String,
        local:  PathBuf,
        remote: String,
    },
    /// Download one sandbox file.
    Download {
        id:     String,
        remote: String,
        local:  PathBuf,
    },
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::*;

    #[test]
    fn parses_exec_command_after_separator() {
        let cli = Cli::try_parse_from([
            "lithos-sandbox",
            "--provider",
            "docker",
            "sandbox",
            "exec",
            "sb-1",
            "--",
            "bash",
            "-lc",
            "printf hello",
        ])
        .expect("command parses");

        let Command::Sandbox { command } = cli.command else {
            panic!("expected sandbox exec");
        };
        let SandboxCommand::Exec(args) = *command else {
            panic!("expected sandbox exec");
        };
        assert_eq!(args.id, "sb-1");
        assert_eq!(args.command, ["bash", "-lc", "printf hello"]);
    }

    #[test]
    fn rejects_more_than_one_creation_source() {
        let error = Cli::try_parse_from([
            "lithos-sandbox",
            "sandbox",
            "create",
            "--image",
            "ubuntu:24.04",
            "--host-directory",
        ])
        .expect_err("sources conflict");

        assert!(error.to_string().contains("cannot be used with"));
    }
}
