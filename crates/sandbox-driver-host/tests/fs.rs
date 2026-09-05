//! Streaming filesystem behavior through the provider's public facet.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use sandbox_driver::{Error, ResourceKind, SandboxProvider, SandboxSource, SandboxSpec};
use sandbox_driver_host::HostProvider;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[tokio::test]
async fn streaming_writes_create_parents_and_leave_extra_input_unread() {
    let provider = HostProvider::new();
    let sandbox = provider
        .create(&SandboxSpec::new(SandboxSource::HostDirectory), None)
        .await
        .expect("create sandbox");
    let mut input = b"hello\0\xffremaining".as_slice();
    sandbox
        .fs()
        .write_from("nested/file.bin", &mut input, 7)
        .await
        .expect("write exact length");
    assert_eq!(input, b"remaining");
    let mut output = Vec::new();
    sandbox
        .fs()
        .read_to("nested/file.bin", &mut output)
        .await
        .expect("stream file");
    assert_eq!(output, b"hello\0\xff");

    sandbox
        .fs()
        .write_from("nested/file.bin", &mut input, 0)
        .await
        .expect("truncate to an empty file");
    assert_eq!(input, b"remaining");
    assert!(
        sandbox
            .fs()
            .read("nested/file.bin")
            .await
            .expect("read empty file")
            .is_empty()
    );
    sandbox.delete().await.expect("delete sandbox");
}

#[tokio::test]
async fn streaming_writes_reject_short_or_failed_input() {
    let provider = HostProvider::new();
    let sandbox = provider
        .create(&SandboxSpec::new(SandboxSource::HostDirectory), None)
        .await
        .expect("create sandbox");
    let error = sandbox
        .fs()
        .write_from("short.bin", &mut b"short".as_slice(), 10)
        .await
        .expect_err("short source must fail");
    assert!(
        matches!(error, Error::Io { source, .. } if source.kind() == io::ErrorKind::UnexpectedEof)
    );

    let error = sandbox
        .fs()
        .write_from(
            "failed.bin",
            &mut FailingIo(io::ErrorKind::PermissionDenied),
            1,
        )
        .await
        .expect_err("source error must propagate");
    assert!(
        matches!(error, Error::Io { source, .. } if source.kind() == io::ErrorKind::PermissionDenied)
    );
    sandbox.delete().await.expect("delete sandbox");
}

#[tokio::test]
async fn streaming_reads_distinguish_missing_files_from_sink_failures() {
    let provider = HostProvider::new();
    let sandbox = provider
        .create(&SandboxSpec::new(SandboxSource::HostDirectory), None)
        .await
        .expect("create sandbox");
    let error = sandbox
        .fs()
        .read_to("missing.bin", &mut Vec::new())
        .await
        .expect_err("missing file must fail");
    assert!(
        matches!(error, Error::NotFound { resource: ResourceKind::File, id } if id == "missing.bin")
    );

    sandbox
        .fs()
        .write("file.bin", b"bytes")
        .await
        .expect("write file");
    let error = sandbox
        .fs()
        .read_to("file.bin", &mut FailingIo(io::ErrorKind::NotFound))
        .await
        .expect_err("sink error must propagate");
    assert!(matches!(error, Error::Io { source, .. } if source.kind() == io::ErrorKind::NotFound));
    sandbox.delete().await.expect("delete sandbox");
}

struct FailingIo(io::ErrorKind);

impl AsyncRead for FailingIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::new(self.0, "source failed")))
    }
}

impl AsyncWrite for FailingIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::new(self.0, "sink failed")))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
