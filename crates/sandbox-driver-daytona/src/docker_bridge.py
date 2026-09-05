"""VM-owned, binary-safe bridge from Daytona's private preview to Docker.

The lock prevents duplicate listeners. The VM's lifecycle owns the daemon;
stopping the VM closes all connections, including Docker's upgraded streams.
No package installation or Docker daemon reconfiguration is required.
"""

import asyncio
import fcntl
import os
import socket
import sys


async def relay(reader, writer):
    try:
        while chunk := await reader.read(65536):
            writer.write(chunk)
            await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()
    except (ConnectionError, OSError):
        writer.close()


async def serve(listener, docker_socket):
    active = 0

    async def connect(reader, writer):
        nonlocal active
        if active >= 128:
            writer.close()
            await writer.wait_closed()
            return
        active += 1
        upstream = None
        try:
            incoming, upstream = await asyncio.open_unix_connection(docker_socket)
            await asyncio.gather(relay(reader, upstream), relay(incoming, writer))
        except (ConnectionError, OSError):
            pass
        finally:
            active -= 1
            for connection in (writer, upstream):
                if connection is not None:
                    connection.close()
                    try:
                        await connection.wait_closed()
                    except (ConnectionError, OSError):
                        pass

    server = await asyncio.start_server(connect, sock=listener)
    async with server:
        await server.serve_forever()


def main():
    lock_path, docker_socket, port = sys.argv[1:]
    lock = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", int(port)))
    listener.listen(32)
    listener.setblocking(False)
    if os.fork():
        return
    os.setsid()
    if os.fork():
        os._exit(0)
    with open(os.devnull, "r+b", buffering=0) as null:
        for descriptor in (0, 1, 2):
            os.dup2(null.fileno(), descriptor)
    asyncio.run(serve(listener, docker_socket))


if __name__ == "__main__":
    main()
