use std::io::{IsTerminal as _, stdin as blocking_stdin};
use std::process::Stdio;

use anyhow::{Context as _, Result};
#[cfg(unix)]
use nix::sys::termios::{SetArg, Termios, cfmakeraw, tcgetattr, tcsetattr};
use sandbox_driver::{PtyOptions, PtySession, Sandbox};
use tokio::io::{
    AsyncReadExt as _, AsyncWriteExt as _, stdin as async_stdin, stdout as async_stdout,
};
use tokio::process::Command as TokioCommand;
use tokio::signal::ctrl_c;

use super::{CANCELLED_EXIT, DRIVER_ERROR_EXIT};

pub(super) async fn execute_shell(sandbox: &dyn Sandbox) -> Result<u8> {
    if let Some(access) = sandbox.shell_command() {
        let command = access.shell_command().await?;
        let status = TokioCommand::new("bash")
            .args(["-c", &command])
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .await
            .context("running provider shell command")?;
        return Ok(status
            .code()
            .and_then(|code| u8::try_from(code).ok())
            .unwrap_or(DRIVER_ERROR_EXIT));
    }

    let pty = sandbox
        .pty()
        .context("this sandbox provides neither a shell command nor a PTY")?;
    let session = pty.open(&PtyOptions::default()).await?;
    run_pty(session.as_ref()).await
}

async fn run_pty(session: &dyn PtySession) -> Result<u8> {
    let _terminal_mode = enter_raw_terminal_mode()?;
    let result = {
        let input = forward_terminal_input(session);
        let output = forward_terminal_output(session);
        tokio::pin!(input);
        tokio::pin!(output);
        tokio::select! {
            result = &mut output => result.map(|()| 0),
            result = &mut input => {
                result?;
                output.await.map(|()| 0)
            }
            signal = ctrl_c() => {
                signal.context("listening for Ctrl-C")?;
                Ok(CANCELLED_EXIT)
            }
        }
    };
    let close = session.close().await.context("closing PTY session");
    let exit_code = result?;
    close?;
    Ok(exit_code)
}

async fn forward_terminal_input(session: &dyn PtySession) -> Result<()> {
    let mut input = async_stdin();
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let count = input
            .read(&mut buffer)
            .await
            .context("reading terminal input")?;
        if count == 0 {
            return Ok(());
        }
        session.write_input(&buffer[..count]).await?;
    }
}

async fn forward_terminal_output(session: &dyn PtySession) -> Result<()> {
    let mut output = async_stdout();
    while let Some(bytes) = session.read_output().await? {
        output
            .write_all(&bytes)
            .await
            .context("writing terminal output")?;
        output.flush().await.context("flushing terminal output")?;
    }
    Ok(())
}

#[cfg(unix)]
struct RawTerminal {
    original: Termios,
}

#[cfg(unix)]
impl Drop for RawTerminal {
    fn drop(&mut self) {
        let input = blocking_stdin();
        if let Err(error) = tcsetattr(&input, SetArg::TCSANOW, &self.original) {
            tracing::warn!(error = ?error, "terminal mode restore failed");
        }
    }
}

#[cfg(unix)]
fn enter_raw_terminal_mode() -> Result<Option<RawTerminal>> {
    let input = blocking_stdin();
    if !input.is_terminal() {
        return Ok(None);
    }
    let original = tcgetattr(&input).context("reading terminal mode")?;
    let mut raw = original.clone();
    cfmakeraw(&mut raw);
    tcsetattr(&input, SetArg::TCSANOW, &raw).context("enabling raw terminal mode")?;
    Ok(Some(RawTerminal { original }))
}

#[cfg(not(unix))]
struct RawTerminal;

#[cfg(not(unix))]
fn enter_raw_terminal_mode() -> Result<Option<RawTerminal>> {
    Ok(None)
}
