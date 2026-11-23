# lithos-sandbox CLI

The `sandbox-driver-cli` crate builds the `lithos-sandbox` executable, the
command-line client of the library. It uses the same catalog an embedding
application does: provider entries and environments, as
[next-api.md](https://github.com/lithoscomputer/sandbox-driver/blob/main/docs/next-api.md#cli)
describes. Host, Docker and Daytona are linked into the CLI and run in its
process. Every other provider kind is a plugin, launched over protocol
version 3 by the ordinary plugin loader.

It is also the quickest way to try a provider by hand: create a sandbox, run
commands in it, move files, stop and start it, and destroy it.

## Quick start

With no configuration, the CLI has one provider entry and one environment of
the same name for each built-in: `host`, `docker` and `daytona`. The Docker
and Daytona environments start from `ubuntu:24.04`.

```sh
lithos-sandbox providers
lithos-sandbox environments
lithos-sandbox provider health docker

lithos-sandbox run docker -- uname -a
lithos-sandbox run docker --image alpine:3 -- sh -c 'cat /etc/os-release'
```

A persistent sandbox is named by the ref that `create` prints,
`<provider entry>/<id>`:

```sh
sb=$(lithos-sandbox create docker --label job=1842)

lithos-sandbox status "$sb"
lithos-sandbox exec "$sb" -- sh -c 'echo hello > /tmp/greeting'
lithos-sandbox cp "$sb":/tmp/greeting ./greeting
lithos-sandbox cp ./input.txt "$sb":/work/input.txt
lithos-sandbox ls "$sb":/work
lithos-sandbox shell "$sb"
lithos-sandbox stop "$sb"
lithos-sandbox start "$sb"
lithos-sandbox find --label job=1842
lithos-sandbox destroy "$sb"
```

`--output json` on `create` or `status` prints the full status, whose
`reference` is the durable `{provider, namespace, id}` ref. Every command
that takes a sandbox on its own also accepts that JSON object; `cp` and `ls`,
which take `SANDBOX:PATH`, need the short form. The short form takes its
namespace from the entry's provider at the time of the command.

## Commands

| Command | Does |
| --- | --- |
| `providers` | List provider entries |
| `provider describe ENTRY` | Show the descriptor: namespace, durability, sources, resources, network, ports and capabilities |
| `provider health ENTRY` | Check that the provider is reachable and authorized; exits 1 when unhealthy |
| `environments` | List environments with their entry and source |
| `create ENVIRONMENT` | Create a sandbox and print its ref |
| `run ENVIRONMENT -- CMD...` | Create a sandbox, run one command, destroy the sandbox |
| `find --label K=V` | List matching sandboxes across every provider entry |
| `status SANDBOX` | Show the sandbox's status |
| `start SANDBOX`, `stop SANDBOX` | Start or stop it; stop ends every command in it |
| `exec SANDBOX -- CMD...` | Run a command and stream its output |
| `shell SANDBOX` | Open the provider's interactive shell |
| `cp SRC DEST` | Copy one file; one side is `SANDBOX:PATH`, `-` is stdin or stdout |
| `ls SANDBOX:PATH` | List a directory; `--depth N` descends N more levels |
| `expose SANDBOX PORT` | Print a URL for a port and hold it until Ctrl-C |
| `destroy SANDBOX` | Destroy the sandbox |

`shell` runs the shell command the provider reports, such as `docker exec
-it`. Providers without one say so; use `exec` with `sh -c` instead.
Interactive terminals over exec arrive with the providers' tty support.

## Creating

`create` and `run` start from the environment's spec and apply the options
given on the command line:

```sh
lithos-sandbox create docker \
  --image ubuntu:24.04 \
  --name example \
  --cpu 2 \
  --memory 4GB \
  --env RUST_BACKTRACE=1 \
  --label project=example \
  --network block
```

The source is `--image`, `--dockerfile FILE` or `--snapshot ID`, at most one.
Sizes take a unit (`4GB`, `512MiB`). `--workspace PATH` sets the working
directory; for a host directory source it designates a caller-owned
directory. `--provider-config JSON` merges keys into the spec's
`provider_config`, which the provider's `spec_schema` validates.

`--spec FILE` replaces the environment's spec with a JSON `SandboxSpec`
(`-` reads stdin); the options above still apply on top of it.

The descriptor decides what a provider accepts. A request it cannot honour
fails before anything is created, naming the field, such as
`unsupported capability: resources.memory_mb`.

### Host

Host sandboxes last as long as the process that created them, which for the
CLI is one command. `run` works; `create` and `run --keep` are refused
because they would leave nothing behind.

```sh
lithos-sandbox run host --workspace "$PWD" -- cargo test
```

## Exec

```sh
lithos-sandbox exec "$sb" -w /work -e RUST_LOG=debug --timeout 5m -- make test
printf 'data' | lithos-sandbox exec -i "$sb" -- wc -c
```

The command is argv, passed as given; wrap it in `sh -c` for shell syntax.
`-i` streams local stdin to it. `run` takes the same options and `--keep`,
which preserves the sandbox and prints its ref on stderr.

The first Ctrl-C asks the command to terminate; a second kills it.

## Configuration

The CLI reads the first catalog it finds:

1. `--config PATH`
2. `SANDBOX_DRIVER_CONFIG`
3. `$XDG_CONFIG_HOME/sandbox-driver/config.toml`
4. `$HOME/.config/sandbox-driver/config.toml`

A catalog file replaces the built-in defaults. It has the two levels of the
library's catalog:

```toml
[providers.docker]
plugin = "docker"
config = { host = "unix:///var/run/docker.sock" }

[providers.daytona]
plugin  = "daytona"
config  = { api_url = "https://app.daytona.io/api", target = "us" }
secrets = ["DAYTONA_API_KEY"]

[providers.lima]
plugin = "lima"
path   = "~/.local/share/sandbox-driver/plugins/lima/sandbox-driver-lima"
sha256 = "9f2c…"                   # or dev = true while developing it

[environments.ci-linux]
provider = "docker"

[environments.ci-linux.spec]
source  = { image = "ghcr.io/lithoscomputer/ubuntu-24.04:slim-f8bbbfd81934" }
network = { mode = "block" }

[environments.cloud]
provider = "daytona"

[environments.cloud.spec]
source    = { image = "ubuntu:24.04" }
resources = { cpu = 2, memory = "4GB" }
```

Each entry's `config` is checked against its provider's `config_schema` when
the entry is first used, so a typo fails with the field named.
`lithos-sandbox provider describe ENTRY --output json` shows the schemas.

The CLI resolves `secrets` from its own environment. Built-in providers read
nothing else from the environment; the Docker entry's daemon is its
`config.host`, not `DOCKER_HOST`. The default Daytona entry is the one
exception: with no catalog file, it takes `DAYTONA_API_KEY` (or
`DAYTONA_JWT_TOKEN`), `DAYTONA_API_URL`, `DAYTONA_ORGANIZATION_ID` and
`DAYTONA_TARGET` from the environment.

### Plugins

A plugin entry names its executable with an absolute `path` (`~/` is
expanded) and trusts it with a `sha256` pin or `dev = true`, never both. The
CLI hashes the executable before every launch and refuses a mismatch. The
plugin starts with an empty environment plus `PATH`, `HOME`, `TMPDIR` and
`USER` (or exactly the names in `inherit_env`), the entry's `env`, and its
resolved `secrets`.

The kinds `host`, `docker` and `daytona` are the built-ins; an entry of one of
those kinds with a `path` or trust setting is refused, so a plugin picks
another kind.

## Output and exit codes

Results are tables by default. `--output json` prints structured data and
`--output id` prints only refs or names, for scripts. `exec`, `run` and
`shell` reserve stdout and stderr for the command and require the default
output.

`exec` and `run` exit with the command's exit code. They return 124 when the
command timed out, 130 when it was terminated, 137 when it was killed, and
125 when it ended without a usable code, including when its outcome is
unknown. CLI and provider errors exit 1. `-v` shows provider diagnostics on
stderr; repeat it for more.
