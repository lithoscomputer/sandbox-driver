"""Run with Python's standard library. No Daytona account is required."""

import asyncio
import importlib.util
import pathlib
import socket
import tempfile
import unittest

source = pathlib.Path(__file__).parent.parent / "src" / "docker_bridge.py"
spec = importlib.util.spec_from_file_location("docker_bridge", source)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class BridgeTests(unittest.IsolatedAsyncioTestCase):
    async def test_binary_transfer_and_half_close(self):
        with tempfile.TemporaryDirectory(prefix="sd-bridge-") as directory:
            path = str(pathlib.Path(directory) / "docker.sock")
            payload = bytes(range(256)) * 4096
            received = asyncio.get_running_loop().create_future()

            async def docker(reader, writer):
                try:
                    content = await reader.read()
                    received.set_result(content)
                    writer.write(content[::-1])
                    await writer.drain()
                finally:
                    writer.close()
                    await writer.wait_closed()

            daemon = await asyncio.start_unix_server(docker, path)
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
            listener.listen(32)
            listener.setblocking(False)
            relay = asyncio.create_task(bridge.serve(listener, path))
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                try:
                    writer.write(payload)
                    await writer.drain()
                    writer.write_eof()
                    self.assertEqual(await asyncio.wait_for(reader.read(), 10), payload[::-1])
                    self.assertEqual(await received, payload)
                finally:
                    writer.close()
                    await writer.wait_closed()
            finally:
                relay.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await relay
                daemon.close()
                await daemon.wait_closed()


if __name__ == "__main__":
    unittest.main()
