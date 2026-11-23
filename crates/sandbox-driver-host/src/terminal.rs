//! The pseudo-terminal a command run with `ExecSpec::tty` is attached to.

use std::io;
use std::os::fd::OwnedFd;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use rustix::fs::{Mode, OFlags, open};
use rustix::io::{Errno, ioctl_fionbio, read, write};
#[cfg(not(target_os = "linux"))]
use rustix::io::{FdFlags, fcntl_setfd};
use rustix::process::{ioctl_tiocsctty, setsid};
use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
use rustix::stdio::stdin;
use rustix::termios::{Winsize, tcsetwinsize};
use sandbox_driver::TerminalSize;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::process::Command;

/// The controlling side of a command's terminal: the command's output is
/// read here, its input written here, and the terminal's size set here.
/// Clones share one terminal, which closes when the last clone drops.
#[derive(Clone)]
pub(crate) struct Terminal(Arc<AsyncFd<OwnedFd>>);

impl Terminal {
    /// Opens a terminal of `size` and makes it `command`'s standard input,
    /// output and error, and its controlling terminal: the command leads a
    /// new session, so it is the leader of its own process group too.
    #[expect(
        unsafe_code,
        reason = "only a pre-exec hook can make the terminal the child's controlling terminal"
    )]
    pub(crate) fn lead(command: &mut Command, size: TerminalSize) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        let controller = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC)?;
        #[cfg(not(target_os = "linux"))]
        let controller = {
            let controller = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY)?;
            fcntl_setfd(&controller, FdFlags::CLOEXEC)?;
            controller
        };
        grantpt(&controller)?;
        unlockpt(&controller)?;
        let path = ptsname(&controller, Vec::new())?;
        let terminal = open(
            path.as_c_str(),
            OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        tcsetwinsize(&controller, winsize(size))?;
        command
            .stdin(Stdio::from(terminal.try_clone()?))
            .stdout(Stdio::from(terminal.try_clone()?))
            .stderr(Stdio::from(terminal));
        // SAFETY: the hook runs in the forked child before exec, after its
        // standard streams are the terminal. `setsid` and the `TIOCSCTTY`
        // ioctl are single system calls that neither allocate nor take a
        // lock, so they are safe between fork and exec.
        unsafe {
            command.pre_exec(|| {
                setsid()?;
                ioctl_tiocsctty(stdin())?;
                Ok(())
            });
        }
        ioctl_fionbio(&controller, true)?;
        Ok(Self(Arc::new(AsyncFd::new(controller)?)))
    }

    pub(crate) fn resize(&self, size: TerminalSize) -> io::Result<()> {
        Ok(tcsetwinsize(self.0.get_ref(), winsize(size))?)
    }
}

fn winsize(size: TerminalSize) -> Winsize {
    Winsize {
        ws_row:    size.rows.get(),
        ws_col:    size.columns.get(),
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}

/// Whether the command's side of the terminal is closed: every process that
/// held it has exited or closed it. Linux reports that as `EIO`.
fn hung_up(error: &io::Error) -> bool {
    error.raw_os_error() == Some(Errno::IO.raw_os_error())
}

impl AsyncRead for Terminal {
    /// Ends, like a pipe at EOF, once the command's side is closed.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut ready = ready!(self.0.poll_read_ready(cx))?;
            let read = ready
                .try_io(|controller| Ok(read(controller.get_ref(), buf.initialize_unfilled())?));
            match read {
                Ok(Ok(read)) => {
                    buf.advance(read);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(error)) if hung_up(&error) => return Poll::Ready(Ok(())),
                Ok(Err(error)) => return Poll::Ready(Err(error)),
                Err(_would_block) => {}
            }
        }
    }
}

impl AsyncWrite for Terminal {
    /// Fails as a broken pipe once the command's side is closed.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut ready = ready!(self.0.poll_write_ready(cx))?;
            match ready.try_io(|controller| Ok(write(controller.get_ref(), buf)?)) {
                Ok(Err(error)) if hung_up(&error) => {
                    return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
                }
                Ok(written) => return Poll::Ready(written),
                Err(_would_block) => {}
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// A terminal has no end of input to send, so the end of the caller's
    /// input leaves it open: closing it would hang up the command.
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
