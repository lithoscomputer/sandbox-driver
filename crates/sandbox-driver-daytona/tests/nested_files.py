"""Exercise the command-local archive helper against a real Alpine container."""

import importlib.util
import contextlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
import tarfile
import unittest
from unittest import mock
import uuid


spec = importlib.util.spec_from_file_location(
    "nested_files", Path(__file__).parents[1] / "src" / "nested_files.py"
)
files = importlib.util.module_from_spec(spec)
spec.loader.exec_module(files)
# Use the test machine's configured daemon; production fixes the outer
# sandbox's local Unix socket independently of workflow environment values.
files.docker_args = lambda *args: ["docker", *args]
files.docker_env = lambda: os.environ.copy()


class EmptyRanges(unittest.TestCase):
    def test_empty_ranges_do_not_read_the_archive_payload(self):
        entry = tarfile.TarInfo("large-file")
        entry.size = 1024 * files.CHUNK

        class HeaderOnly(io.BytesIO):
            def read(self, size=-1):
                if self.tell() == len(self.getvalue()):
                    raise AssertionError("an empty range must not read file payload")
                return super().read(size)

        @contextlib.contextmanager
        def archive_pipe(*_args):
            with HeaderOnly(entry.tobuf()) as stream:
                yield stream

        with tempfile.TemporaryDirectory() as directory:
            staged = Path(directory) / "staged"
            for offset, length in [(entry.size, 10), (entry.size + 1, None), (1, 0)]:
                with self.subTest(offset=offset, length=length):
                    staged.write_bytes(b"replace prior content")
                    with mock.patch.object(files, "docker_pipe", archive_pipe):
                        size = files.read_file("job", "/large-file", str(staged), offset, length)
                    self.assertEqual(size, 0)
                    self.assertEqual(staged.read_bytes(), b"")


class ContainerFiles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            subprocess.run(["docker", "info"], check=True, capture_output=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            if os.environ.get("PETRI_REQUIRE_DOCKER") == "1":
                raise
            raise unittest.SkipTest("Docker is unavailable")
        cls.container = "sandbox-driver-cli-files-" + uuid.uuid4().hex
        subprocess.run([
            "docker", "run", "-d", "--name", cls.container, "alpine:3.20",
            "sh", "-c", "while :; do sleep 3600; done",
        ], check=True, capture_output=True, timeout=60)
        cls.addClassCleanup(lambda: subprocess.run(
            ["docker", "rm", "-f", cls.container], check=True, capture_output=True, timeout=20
        ))

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.source = Path(self.directory.name) / "source"
        self.output = Path(self.directory.name) / "output"

    def command(self, *args):
        return subprocess.check_output(["docker", "exec", self.container, *args])

    def test_binary_ranges_missing_parents_and_existing_directory_modes(self):
        payload = bytes(range(256)) * 10000
        self.source.write_bytes(payload)
        self.command("mkdir", "-p", "/workspace/private")
        self.command("chmod", "0711", "/workspace/private")
        path = "/workspace/private/new/file with 'quotes\nand newline"
        files.write_file(self.container, path, str(self.source), 1000, 1000)
        self.assertEqual(self.command("stat", "-c", "%a", "/workspace/private").strip(), b"711")
        self.assertEqual(self.command("stat", "-c", "%u:%g", path).strip(), b"1000:1000")
        count = files.read_file(self.container, path, str(self.output), 255, 8193)
        self.assertEqual(count, 8193)
        self.assertEqual(self.output.read_bytes(), payload[255:8448])
        self.assertEqual(files.read_file(self.container, path, str(self.output), len(payload) + 1, 10), 0)
        files.read_file(self.container, path, str(self.output), 0, None)
        self.assertEqual(self.output.read_bytes(), payload)

    def test_symlink_empty_file_and_missing_file(self):
        self.source.write_bytes(b"")
        files.write_file(self.container, "/workspace/empty", str(self.source), 0, 0)
        self.command("ln", "-s", "/workspace/empty", "/workspace/link")
        self.assertEqual(files.read_file(self.container, "/workspace/link", str(self.output), 0, None), 0)
        with self.assertRaises(FileNotFoundError):
            files.read_file(self.container, "/missing", str(self.output), 0, 1)
        with self.assertRaises(RuntimeError):
            files.read_file("missing-container-" + uuid.uuid4().hex, "/missing", str(self.output), 0, 1)

    def test_private_runtime_files_have_restricted_modes(self):
        self.source.write_bytes(b"secret")
        files.write_file(self.container, "/tmp/sandbox-driver/runtime/new/token", str(self.source), 0, 0)
        self.assertEqual(self.command("stat", "-c", "%a", "/tmp").strip(), b"1777")
        self.assertEqual(self.command("stat", "-c", "%a", "/tmp/sandbox-driver/runtime/new").strip(), b"700")
        self.assertEqual(self.command("stat", "-c", "%a", "/tmp/sandbox-driver/runtime/new/token").strip(), b"600")


if __name__ == "__main__":
    unittest.main()
