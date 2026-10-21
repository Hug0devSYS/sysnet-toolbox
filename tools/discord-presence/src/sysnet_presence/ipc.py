"""Minimal client for the Discord desktop RPC (local IPC) protocol.

Frames are ``<opcode:uint32 LE><length:uint32 LE><JSON payload>`` sent over a
Unix domain socket (Linux, macOS) or a named pipe (Windows) exposed by the
running Discord client. Only what Rich Presence needs is implemented:
HANDSHAKE, SET_ACTIVITY and CLOSE. Nothing leaves the machine except through
the local Discord client.
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import struct
import sys
import threading
import uuid
from typing import Any, Dict, Iterator, List, Optional, Tuple

OP_HANDSHAKE, OP_FRAME, OP_CLOSE, OP_PING, OP_PONG = 0, 1, 2, 3, 4
MAX_FRAME = 1 << 20


class IPCError(Exception):
    """Discord is not reachable, or rejected a command."""


def candidate_paths(env: Optional[Dict[str, str]] = None, platform: str = sys.platform) -> List[str]:
    """IPC endpoints to try, in order (native, Flatpak, Snap, Vesktop)."""
    env = dict(os.environ if env is None else env)
    if platform.startswith("win"):
        return [rf"\\.\pipe\discord-ipc-{i}" for i in range(10)]
    bases: List[str] = []
    for var in ("XDG_RUNTIME_DIR", "TMPDIR", "TMP", "TEMP"):
        v = env.get(var)
        if v and v not in bases:
            bases.append(v)
    if "/tmp" not in bases:
        bases.append("/tmp")
    subdirs = ("", "app/com.discordapp.Discord", "snap.discord", ".flatpak/dev.vencord.Vesktop/xdg-run")
    return [os.path.join(b, s, f"discord-ipc-{i}") for i in range(10) for b in bases for s in subdirs]


class _Transport:
    def send(self, data: bytes) -> None:
        raise NotImplementedError

    def recv_exact(self, n: int) -> bytes:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError


class UnixTransport(_Transport):
    def __init__(self, path: str, timeout: float):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        try:
            self.sock.connect(path)
        except OSError:
            self.sock.close()
            raise

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def recv_exact(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise IPCError("Discord closed the connection")
            buf += chunk
        return buf

    def close(self) -> None:
        self.sock.close()


class PipeTransport(_Transport):  # pragma: no cover - Windows only
    def __init__(self, path: str, timeout: float):
        self.timeout = timeout
        self.fh = open(path, "r+b", buffering=0)  # noqa: SIM115

    def send(self, data: bytes) -> None:
        self.fh.write(data)

    def recv_exact(self, n: int) -> bytes:
        # Named-pipe reads cannot time out: read in a helper thread.
        result: List[Any] = []

        def reader() -> None:
            try:
                buf = b""
                while len(buf) < n:
                    chunk = self.fh.read(n - len(buf))
                    if not chunk:
                        raise IPCError("Discord closed the connection")
                    buf += chunk
                result.append(buf)
            except Exception as exc:  # noqa: BLE001
                result.append(exc)

        t = threading.Thread(target=reader, daemon=True)
        t.start()
        t.join(self.timeout)
        if not result:
            raise IPCError(f"no answer from Discord within {self.timeout:g}s")
        if isinstance(result[0], Exception):
            raise result[0]
        return result[0]

    def close(self) -> None:
        self.fh.close()


def _connect(paths: Iterator[str], timeout: float) -> Tuple[_Transport, str]:
    errors = []
    for p in paths:
        try:
            if p.startswith("\\\\.\\pipe\\"):  # pragma: no cover - Windows only
                return PipeTransport(p, timeout), p
            if not os.path.exists(p):
                continue
            return UnixTransport(p, timeout), p
        except OSError as exc:
            errors.append(f"{p}: {exc.strerror or exc}")
    detail = f" ({'; '.join(errors[:3])})" if errors else ""
    raise IPCError("Discord desktop client not found: is it running on this computer?" + detail)


class Client:
    def __init__(self, client_id: str, timeout: float = 2.0, paths: Optional[List[str]] = None):
        if not client_id.isdigit():
            raise IPCError(f"invalid Discord application ID {client_id!r} (expected digits)")
        self.client_id = client_id
        self.timeout = timeout
        self.paths = paths
        self.transport: Optional[_Transport] = None
        self.endpoint = ""
        self.user: Dict[str, Any] = {}

    def connect(self) -> None:
        self.transport, self.endpoint = _connect(iter(self.paths or candidate_paths()), self.timeout)
        try:
            self._send(OP_HANDSHAKE, {"v": 1, "client_id": self.client_id})
            op, data = self._recv()
        except (OSError, IPCError) as exc:
            self.close()
            raise IPCError(f"handshake with Discord failed: {exc}") from exc
        if op == OP_CLOSE or data.get("evt") == "ERROR":
            self.close()
            raise IPCError(f"Discord refused the connection: {data.get('message') or data.get('data')}")
        self.user = (data.get("data") or {}).get("user") or {}

    def set_activity(self, activity: Optional[Dict[str, Any]], pid: Optional[int] = None) -> Dict[str, Any]:
        args: Dict[str, Any] = {"pid": pid if pid is not None else os.getpid()}
        if activity is not None:
            args["activity"] = activity
        nonce = str(uuid.uuid4())
        self._send(OP_FRAME, {"cmd": "SET_ACTIVITY", "args": args, "nonce": nonce})
        while True:
            op, data = self._recv()
            if op == OP_PING:
                self._send(OP_PONG, data)
                continue
            if op == OP_CLOSE:
                raise IPCError(f"Discord closed the connection: {data.get('message')}")
            if data.get("nonce") not in (None, nonce):
                continue  # not our reply
            if data.get("evt") == "ERROR":
                err = data.get("data") or {}
                raise IPCError(f"Discord rejected the activity: {err.get('message', err)}")
            if data.get("cmd") == "SET_ACTIVITY":
                return data.get("data") or {}

    def clear(self) -> None:
        with contextlib.suppress(OSError, IPCError):
            self.set_activity(None)

    def close(self) -> None:
        if self.transport is None:
            return
        with contextlib.suppress(OSError, IPCError):
            self._send(OP_CLOSE, {})
        try:
            self.transport.close()
        finally:
            self.transport = None

    def _send(self, op: int, payload: Dict[str, Any]) -> None:
        assert self.transport is not None
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.transport.send(struct.pack("<II", op, len(body)) + body)

    def _recv(self) -> Tuple[int, Dict[str, Any]]:
        assert self.transport is not None
        try:
            op, length = struct.unpack("<II", self.transport.recv_exact(8))
            if length > MAX_FRAME:
                raise IPCError(f"oversized frame from Discord ({length} bytes)")
            data = json.loads(self.transport.recv_exact(length) or b"{}")
        except socket.timeout as exc:
            raise IPCError(f"no answer from Discord within {self.timeout:g}s") from exc
        except ValueError as exc:
            raise IPCError(f"malformed frame from Discord: {exc}") from exc
        return op, data if isinstance(data, dict) else {}
