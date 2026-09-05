"""Copy file bytes with the Docker CLI; stdout carries metadata only.

This command runs in the outer Daytona sandbox. It uses no service, port, or
preview URL. The job image needs no Python, Bash, or base64 implementation.
"""

import contextlib
import json
import os
import posixpath
import shutil
import subprocess
import sys
import tarfile
import tempfile


CHUNK = 1024 * 1024


def docker_args(*args):
    return ["docker", "--host", "unix:///var/run/docker.sock", *args]


def docker_env():
    env = os.environ.copy()
    for name in ("DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
        env.pop(name, None)
    return env


def command_error(errors):
    errors.seek(0)
    message = errors.read(65536).decode("utf-8", "replace")
    if "Could not find the file " in message or (message.startswith("destination ") and "must be a directory" in message):
        return FileNotFoundError(message)
    return RuntimeError(message or "Docker returned an invalid file archive")


@contextlib.contextmanager
def docker_pipe(*args, writing=False):
    # A file prevents stderr from blocking a full stdout/stdin pipe. Bound
    # diagnostics when returning an error, without retaining file contents.
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(
            docker_args(*args), env=docker_env(), stderr=errors,
            stdin=subprocess.PIPE if writing else subprocess.DEVNULL,
            stdout=subprocess.DEVNULL if writing else subprocess.PIPE,
        )
        pipe = process.stdin if writing else process.stdout
        try:
            yield pipe
            if writing:
                pipe.close()
                status = process.wait()
                if status:
                    raise command_error(errors)
        except (tarfile.ReadError, BrokenPipeError):
            process.wait()
            raise command_error(errors) from None
        finally:
            with contextlib.suppress(BrokenPipeError):
                pipe.close()
            # Range reads stop as soon as they have enough bytes. End and
            # reap docker cp instead of draining the rest of a large file.
            if process.poll() is None:
                process.terminate()
            process.wait()


def read_file(container, path, staged, offset, length):
    with docker_pipe("cp", "-L", f"{container}:{path}", "-") as stream:
        with tarfile.open(fileobj=stream, mode="r|") as archive:
            entry = archive.next()
            if entry is None or not entry.isfile():
                raise ValueError("path is not a regular file")
            if offset >= entry.size or length == 0:
                open(staged, "wb").close()
                return 0
            content = archive.extractfile(entry)
            remaining = min(offset, entry.size)
            while remaining:
                chunk = content.read(min(CHUNK, remaining))
                if not chunk:
                    raise EOFError("Docker file archive ended before its declared size")
                remaining -= len(chunk)
            remaining = max(0, entry.size - offset)
            if length is not None:
                remaining = min(remaining, length)
            with open(staged, "wb") as output:
                while remaining:
                    chunk = content.read(min(CHUNK, remaining))
                    if not chunk:
                        raise EOFError("Docker file archive ended before its declared size")
                    output.write(chunk)
                    remaining -= len(chunk)
    return os.path.getsize(staged)


def write_file(container, path, staged, uid, gid):
    path = posixpath.normpath(path)
    if path == "/" or not path.startswith("/"):
        raise ValueError("expected an absolute file path")
    private = path.startswith("/tmp/sandbox-driver/runtime/")
    root = posixpath.dirname(path)
    while True:
        try:
            write_under(container, root, path, staged, uid, gid, private)
            return
        except FileNotFoundError:
            if root == "/":
                raise
            root = posixpath.dirname(root)


def write_under(container, root, path, staged, uid, gid, private):
    relative = posixpath.relpath(path, root)
    with docker_pipe("cp", "-a", "-", f"{container}:{root}", writing=True) as stream:
        with tarfile.open(fileobj=stream, mode="w|") as archive:
            parent = posixpath.dirname(relative)
            parts = parent.split("/") if parent else []
            for index in range(len(parts)):
                entry = tarfile.TarInfo("/".join(parts[:index + 1]))
                entry.type = tarfile.DIRTYPE
                entry.mode = 0o700 if private else 0o755
                entry.uid, entry.gid = uid, gid
                archive.addfile(entry)
            entry = tarfile.TarInfo(relative)
            entry.size = os.path.getsize(staged)
            entry.mode = 0o600 if private else 0o644
            entry.uid, entry.gid = uid, gid
            with open(staged, "rb") as content:
                archive.addfile(entry, content)


def main(args):
    operation, *args = args
    if operation == "read":
        container, path, staged, offset, length = args
        try:
            size = read_file(container, path, staged, int(offset), None if length == "all" else int(length))
        except FileNotFoundError:
            return {"missing": True}
        return {"size": size}
    if operation == "write":
        container, path, staged, uid, gid = args
        write_file(container, path, staged, int(uid), int(gid))
    elif operation == "slice":
        source, staged, offset = args
        with open(source, "rb") as content, open(staged, "wb") as output:
            content.seek(int(offset))
            output.write(content.read(CHUNK))
        return {"size": os.path.getsize(staged)}
    elif operation == "append":
        source, destination = args
        with open(source, "rb") as content, open(destination, "ab") as output:
            shutil.copyfileobj(content, output, CHUNK)
    else:
        raise ValueError("unknown file operation")
    return {}


if __name__ == "__main__":
    print(json.dumps(main(sys.argv[1:])))
