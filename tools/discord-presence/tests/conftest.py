import json
import os
import socket
import struct
import sys
import tempfile
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


class FakeDiscord:
    """Speaks the Discord IPC protocol on a Unix socket and records frames."""

    def __init__(self, mode="ok"):
        self.mode = mode
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "discord-ipc-0")
        self.frames = []
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.path)
        self.sock.listen(4)
        self.closed = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    @staticmethod
    def _read(conn, n):
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise EOFError
            buf += chunk
        return buf

    @staticmethod
    def _send(conn, op, payload):
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        conn.sendall(struct.pack("<II", op, len(body)) + body)

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                while True:
                    op, length = struct.unpack("<II", self._read(conn, 8))
                    data = json.loads(self._read(conn, length))
                    self.frames.append((op, data))
                    if op == 2:
                        break
                    if op == 0:
                        if self.mode == "refuse":
                            self._send(conn, 2, {"code": 4000, "message": "Invalid Client ID"})
                            break
                        if self.mode == "silent":
                            continue
                        if self.mode == "huge":
                            conn.sendall(struct.pack("<II", 1, 10 << 20))
                            continue
                        self._send(
                            conn,
                            1,
                            {"cmd": "DISPATCH", "evt": "READY", "data": {"user": {"username": "hugo"}}},
                        )
                    elif op == 1:
                        if self.mode == "reject":
                            self._send(
                                conn,
                                1,
                                {
                                    "cmd": "SET_ACTIVITY",
                                    "evt": "ERROR",
                                    "nonce": data["nonce"],
                                    "data": {"message": "bad"},
                                },
                            )
                            continue
                        # unrelated event and a ping first, then our reply
                        self._send(conn, 1, {"cmd": "DISPATCH", "evt": "ACTIVITY_JOIN", "nonce": None})
                        self._send(conn, 3, {"x": 1})
                        self._send(
                            conn,
                            1,
                            {
                                "cmd": "SET_ACTIVITY",
                                "nonce": data["nonce"],
                                "data": data["args"].get("activity") or {},
                            },
                        )
            except (EOFError, OSError, ValueError):
                pass
            finally:
                conn.close()
                self.closed.set()

    def activities(self):
        return [
            d["args"].get("activity") for op, d in self.frames if op == 1 and d.get("cmd") == "SET_ACTIVITY"
        ]

    def stop(self):
        self.sock.close()


@pytest.fixture
def discord():
    servers = []

    def make(mode="ok"):
        s = FakeDiscord(mode)
        servers.append(s)
        return s

    yield make
    for s in servers:
        s.stop()
