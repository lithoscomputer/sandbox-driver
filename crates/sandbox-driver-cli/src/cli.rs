use std::num::{NonZeroU16, NonZeroU32};
use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use sandbox_driver::NetworkPolicy;

#[derive(Debug, Parser)]
#[command(
    name = "lithos-sandbox",
    version,
    about = "Create, inspect and drive sandboxes through the sandbox-driver catalog",
    after_help = "A SANDBOX is the ref that `create` prints, such as docker/3f2a9c1e, or the \
                  JSON reference from `--output json`."
)]
pub(crate) struct Cli {
    /// Catalog file. Defaults to $SANDBOX_DRIVER_CONFIG, then
    /// $XDG_CONFIG_HOME/sandbox-driver/config.toml.
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    /// Format for command results.
    #[arg(long, value_enum, default_value_t = OutputFormat::Table, global = true)]
    pub output: OutputFormat,

    /// Show provider diagnostics on stderr. Repeat for more detail.
    #[arg(short, long, action = ArgAction::Count, global = true)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// List provider entries.
    Providers,
    /// Inspect one provider entry.
    Provider {
        #[command(subcommand)]
        command: ProviderCommand,
    },
    /// List environments.
    Environments,
    /// Create a sandbox from an environment.
    Create(CreateArgs),
    /// Create a sandbox, run one command in it, and destroy it.
    Run(RunArgs),
    /// Find sandboxes across every provider entry.
    Find(FindArgs),
    /// Show a sandbox's current status.
    Status(SandboxArgs),
    /// Start a stopped sandbox.
    Start(SandboxArgs),
    /// Stop a sandbox, ending every command in it.
    Stop(SandboxArgs),
    /// Run a command in a sandbox.
    Exec(ExecArgs),
    /// Open an interactive shell in a sandbox.
    Shell(SandboxArgs),
    /// Copy one file into or out of a sandbox.
    Cp(CpArgs),
    /// List a sandbox directory.
    Ls(LsArgs),
    /// Make a sandbox port reachable, print its URL, and hold it until
    /// Ctrl-C.
    Expose(ExposeArgs),
    /// Destroy a sandbox.
    Destroy(SandboxArgs),
}

#[derive(Debug, Subcommand)]
pub(crate) enum ProviderCommand {
    /// Show what a provider reports about itself: namespace, durability,
    /// sources, resources and capabilities.
    Describe(ProviderArgs),
    /// Check whether a provider is reachable and authorized.
    Health(ProviderArgs),
}

#[derive(Debug, Args)]
pub(crate) struct ProviderArgs {
    /// Provider entry name.
    pub name: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum OutputFormat {
    Table,
    Json,
    Id,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum NetworkArg {
    ProviderDefault,
    AllowAll,
    Block,
}

impl From<NetworkArg> for NetworkPolicy {
    fn from(network: NetworkArg) -> Self {
        match network {
            NetworkArg::ProviderDefault => Self::ProviderDefault,
            NetworkArg::AllowAll => Self::AllowAll,
            NetworkArg::Block => Self::Block,
        }
    }
}

/// An environment and the changes this sandbox makes to its template.
#[derive(Debug, Args)]
pub(crate) struct CreateArgs {
    /// Environment to create from. See `lithos-sandbox environments`.
    pub environment: String,

    /// Replace the environment's spec with a JSON SandboxSpec. Use `-` for
    /// stdin. The options below still apply on top of it.
    #[arg(long)]
    pub spec: Option<PathBuf>,

    /// Create from an OCI image reference.
    #[arg(long, group = "source")]
    pub image: Option<String>,

    /// Create from a local Dockerfile.
    #[arg(long, group = "source")]
    pub dockerfile: Option<PathBuf>,

    /// Create from a provider snapshot ID or name.
    #[arg(long, group = "source")]
    pub snapshot: Option<String>,

    #[arg(long)]
    pub name: Option<String>,

    /// Whole CPU cores.
    #[arg(long)]
    pub cpu: Option<NonZeroU32>,

    /// Memory with a unit, such as 4GB or 512MiB.
    #[arg(long)]
    pub memory: Option<String>,

    /// Disk with a unit, such as 10GB.
    #[arg(long)]
    pub disk: Option<String>,

    /// Set an environment variable as KEY=VALUE. Repeat as needed.
    #[arg(long = "env", value_name = "KEY=VALUE")]
    pub env: Vec<String>,

    /// Set a label as KEY=VALUE. Repeat as needed.
    #[arg(long = "label", value_name = "KEY=VALUE")]
    pub labels: Vec<String>,

    /// The sandbox's working directory. For a host directory source this
    /// designates a caller-owned directory.
    #[arg(long)]
    pub workspace: Option<String>,

    /// Run commands as this user.
    #[arg(long)]
    pub user: Option<String>,

    #[arg(long, value_enum)]
    pub network: Option<NetworkArg>,

    /// Provider-specific options as a JSON object, merged into the
    /// environment's `provider_config`.
    #[arg(long, value_name = "JSON")]
    pub provider_config: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct RunArgs {
    #[command(flatten)]
    pub create: CreateArgs,

    #[command(flatten)]
    pub exec: ExecOptions,

    /// Keep the sandbox after the command exits and print its ref on stderr.
    #[arg(long)]
    pub keep: bool,

    /// Program and arguments to execute, passed as given (no shell).
    /// Separate them with `--`; wrap them in `sh -c` for shell syntax.
    #[arg(required = true, last = true)]
    pub command: Vec<String>,
}

#[derive(Debug, Args)]
pub(crate) struct FindArgs {
    /// Require a label as KEY=VALUE. Repeat to require all labels.
    #[arg(long = "label", value_name = "KEY=VALUE")]
    pub labels: Vec<String>,
}

#[derive(Debug, Args)]
pub(crate) struct SandboxArgs {
    pub sandbox: String,
}

#[derive(Debug, Args)]
pub(crate) struct ExecArgs {
    pub sandbox: String,

    #[command(flatten)]
    pub options: ExecOptions,

    /// Program and arguments to execute, passed as given (no shell).
    /// Separate them with `--`; wrap them in `sh -c` for shell syntax.
    #[arg(required = true, last = true)]
    pub command: Vec<String>,
}

#[derive(Debug, Args)]
pub(crate) struct ExecOptions {
    /// Run in this sandbox directory.
    #[arg(long, short = 'w')]
    pub workdir: Option<String>,

    /// Set a command environment variable as KEY=VALUE. Repeat as needed.
    #[arg(long = "exec-env", short = 'e', value_name = "KEY=VALUE")]
    pub exec_env: Vec<String>,

    /// Stream local stdin to the command.
    #[arg(long, short = 'i')]
    pub stdin: bool,

    /// Stop the command after this long, such as 30s or 5m.
    #[arg(long, value_name = "DURATION")]
    pub timeout: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct CpArgs {
    /// SANDBOX:PATH to download, or a local file to upload.
    pub source:      String,
    /// SANDBOX:PATH to upload to, or a local file to download to.
    pub destination: String,
}

#[derive(Debug, Args)]
pub(crate) struct LsArgs {
    /// SANDBOX:PATH of a directory.
    pub path:  String,
    /// Extra directory levels to descend into; 0 lists only PATH's
    /// immediate children.
    #[arg(long, default_value_t = 0)]
    pub depth: u32,
}

#[derive(Debug, Args)]
pub(crate) struct ExposeArgs {
    pub sandbox: String,
    pub port:    NonZeroU16,
    /// Ask for a signed URL that needs no extra headers.
    #[arg(long)]
    pub signed:  bool,
    /// How long the exposure lasts, such as 1h.
    #[arg(long, value_name = "DURATION")]
    pub ttl:     Option<String>,
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::*;

    fn parse(args: &[&str]) -> Command {
        Cli::try_parse_from(["lithos-sandbox"].iter().chain(args))
            .expect("command parses")
            .command
    }

    #[test]
    fn exec_takes_the_command_after_the_separator_verbatim() {
        let Command::Exec(args) =
            parse(&["exec", "docker/1", "-w", "/tmp", "--", "sh", "-c", "--help"])
        else {
            panic!("expected exec");
        };
        assert_eq!(args.sandbox, "docker/1");
        assert_eq!(args.options.workdir.as_deref(), Some("/tmp"));
        assert_eq!(args.command, ["sh", "-c", "--help"]);
    }

    #[test]
    fn run_keeps_creation_and_exec_options_apart_from_the_command() {
        let Command::Run(args) = parse(&[
            "run", "docker", "--image", "alpine", "--keep", "-e", "A=1", "--", "env",
        ]) else {
            panic!("expected run");
        };
        assert_eq!(args.create.environment, "docker");
        assert_eq!(args.create.image.as_deref(), Some("alpine"));
        assert_eq!(args.exec.exec_env, ["A=1"]);
        assert!(args.keep);
        assert_eq!(args.command, ["env"]);
    }

    #[test]
    fn rejects_more_than_one_creation_source() {
        let error = Cli::try_parse_from([
            "lithos-sandbox",
            "create",
            "docker",
            "--image",
            "ubuntu:24.04",
            "--snapshot",
            "base",
        ])
        .expect_err("sources conflict");
        assert!(error.to_string().contains("cannot be used with"));
    }
}
