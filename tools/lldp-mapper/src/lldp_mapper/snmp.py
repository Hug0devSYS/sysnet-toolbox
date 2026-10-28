"""SNMP walk back-ends.

Every back-end implements ``walk(root) -> list[(oid, Value)]`` returning the
lexicographically ordered varbinds below ``root``. Back-ends never write to
the agent: only GetNext / GetBulk requests are ever sent.

* ``NativeWalker``  — built-in SNMPv1/v2c client over UDP (stdlib only).
* ``NetSnmpWalker`` — runs net-snmp's ``snmpbulkwalk``/``snmpwalk``; used for
  SNMPv3 (USM authentication and privacy). Credentials are handed over in a
  private temporary ``snmp.conf``, never on the command line.
* ``FileWalker``    — serves a saved walk (``snmpbulkwalk -On`` output), for
  offline analysis and reproducible bug reports.
"""

from __future__ import annotations

import bisect
import os
import random
import re
import shutil
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from . import ber
from .ber import OID, Value

Varbinds = List[Tuple[OID, Value]]

MAX_VARBINDS_PER_WALK = 500_000


class SnmpError(Exception):
    """A walk failed (timeout, unreachable agent, protocol error)."""


class SnmpTimeout(SnmpError):
    pass


def in_subtree(oid: OID, root: OID) -> bool:
    return len(oid) > len(root) and oid[: len(root)] == root


# --------------------------------------------------------------------------- native client


@dataclass
class NativeWalker:
    host: str
    community: bytes
    version: str = "2c"  # "1" or "2c"
    port: int = 161
    timeout: float = 2.0
    retries: int = 2
    max_repetitions: int = 25
    deadline: Optional[float] = None  # absolute time.monotonic() budget for the whole device
    _sock: Optional[socket.socket] = field(default=None, init=False, repr=False)
    requests: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        if self.version not in ("1", "2c"):
            raise ValueError("the native client supports SNMP v1 and v2c only")

    # -- transport -------------------------------------------------------------------

    def _socket(self) -> socket.socket:
        if self._sock is None:
            try:
                infos = socket.getaddrinfo(self.host, self.port, type=socket.SOCK_DGRAM)
            except socket.gaierror as exc:
                raise SnmpError(f"cannot resolve {self.host}: {exc.strerror or exc}") from exc
            last: Optional[OSError] = None
            for family, stype, proto, _, addr in infos:
                try:
                    s = socket.socket(family, stype, proto)
                    s.connect(addr)  # connected UDP: ICMP port unreachable surfaces as an error
                    self._sock = s
                    break
                except OSError as exc:
                    last = exc
            if self._sock is None:
                raise SnmpError(f"{self.host}: {last}")
        return self._sock

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def __enter__(self) -> NativeWalker:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _remaining(self) -> float:
        if self.deadline is None:
            return float("inf")
        return self.deadline - time.monotonic()

    def request(self, pdu_tag: int, oids: List[OID], max_repetitions: int = 0) -> ber.Pdu:
        sock = self._socket()
        ver = 0 if self.version == "1" else 1
        for _ in range(self.retries + 1):
            if self._remaining() <= 0:
                raise SnmpTimeout(f"{self.host}: per-device time budget exhausted")
            rid = random.randint(1, 0x7FFFFFFF)
            data = ber.encode_request(ver, self.community, pdu_tag, rid, oids, 0, max_repetitions)
            self.requests += 1
            try:
                sock.send(data)
            except OSError as exc:
                raise SnmpError(f"{self.host}: send failed: {exc}") from exc
            wait_until = time.monotonic() + min(self.timeout, max(self._remaining(), 0.01))
            while True:
                left = wait_until - time.monotonic()
                if left <= 0:
                    break
                sock.settimeout(left)
                try:
                    raw = sock.recv(65535)
                except socket.timeout:
                    break
                except ConnectionRefusedError as exc:
                    raise SnmpError(f"{self.host}:{self.port}: port unreachable (no SNMP agent)") from exc
                except OSError as exc:
                    raise SnmpError(f"{self.host}: receive failed: {exc}") from exc
                try:
                    msg = ber.decode_message(raw)
                except ber.BerError:
                    continue  # garbage or foreign datagram: keep waiting
                if msg.pdu.request_id != rid or msg.pdu.tag != ber.GET_RESPONSE or msg.version != ver:
                    continue  # stale answer to an earlier retry
                return msg.pdu
        raise SnmpTimeout(
            f"{self.host}: no response after {self.retries + 1} attempt(s) of {self.timeout:g}s "
            "(agent down, ACL, wrong community or wrong SNMP version)"
        )

    # -- walk ------------------------------------------------------------------------

    def walk(self, root: OID) -> Varbinds:
        out: Varbinds = []
        current = root
        reps = self.max_repetitions
        bulk = self.version == "2c" and reps > 1
        while True:
            if bulk:
                pdu = self.request(ber.GET_BULK_REQUEST, [current], reps)
            else:
                pdu = self.request(ber.GET_NEXT_REQUEST, [current])
            if pdu.error_status:
                status = ber.ERROR_STATUS.get(pdu.error_status, str(pdu.error_status))
                if pdu.error_status == 1 and bulk and reps > 1:  # tooBig
                    reps = max(1, reps // 2)
                    bulk = reps > 1
                    continue
                if pdu.error_status == 2:  # v1 noSuchName: end of MIB view
                    return out
                raise SnmpError(f"{self.host}: agent returned {status}")
            if not pdu.varbinds:
                return out
            for oid, value in pdu.varbinds:
                if value.tag == ber.END_OF_MIB_VIEW or not in_subtree(oid, root):
                    return out
                if oid <= current:
                    raise SnmpError(
                        f"{self.host}: agent returned a non-increasing OID {ber.format_oid(oid)} "
                        f"after {ber.format_oid(current)} (broken agent)"
                    )
                if not value.is_exception:
                    out.append((oid, value))
                current = oid
                if len(out) > MAX_VARBINDS_PER_WALK:
                    raise SnmpError(
                        f"{self.host}: walk of {ber.format_oid(root)} exceeds {MAX_VARBINDS_PER_WALK} varbinds"
                    )


# --------------------------------------------------------------------------- walk files

_LINE = re.compile(r"^(?:\S+::)?(\.?[0-9][0-9.]*)\s+=\s+(.*)$")
_TYPED = re.compile(r"^([A-Za-z0-9-]+):\s?(.*)$", re.S)
_INT_LABEL = re.compile(r"^-?\w*\((-?\d+)\)$")

TEXT_TYPES = {"STRING", "Network Address"}


def _hex_bytes(text: str) -> bytes:
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", text)
    if len(cleaned) % 2:
        raise ber.BerError(f"odd-length hex string {text!r}")
    return bytes.fromhex(cleaned)


def _unquote(text: str) -> bytes:
    text = text.strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        text = text[1:-1]
        text = re.sub(r'\\(["\\])', r"\1", text)
    return text.encode("utf-8", "surrogateescape")


def parse_value(raw: str) -> Optional[Value]:
    """Parse the right-hand side of a net-snmp output line (any -O options except -OQ/-Ov)."""
    raw = raw.rstrip("\n")
    if raw.startswith(("No Such Object", "No Such Instance", "No more variables")):
        return None
    if raw in ('""', ""):
        return Value(ber.OCTET_STRING, b"")
    m = _TYPED.match(raw)
    if not m:
        return Value(ber.OCTET_STRING, _unquote(raw))
    typ, val = m.group(1), m.group(2).strip()
    if typ == "Hex-STRING":
        return Value(ber.OCTET_STRING, _hex_bytes(val))
    if typ in ("STRING", "BITS"):
        if typ == "BITS":
            # "BITS: 28 00 bridge(2) router(4)" -> leading hex octets
            octets = re.match(r"^((?:[0-9A-Fa-f]{2}\s*)*)", val)
            return Value(ber.OCTET_STRING, _hex_bytes(octets.group(1) if octets else ""))
        return Value(ber.OCTET_STRING, _unquote(val))
    if typ in ("INTEGER", "Counter32", "Gauge32", "Counter64", "Timeticks", "UInteger32", "Unsigned32"):
        tag = {
            "INTEGER": ber.INTEGER,
            "Counter32": ber.COUNTER32,
            "Gauge32": ber.GAUGE32,
            "UInteger32": ber.GAUGE32,
            "Unsigned32": ber.GAUGE32,
            "Counter64": ber.COUNTER64,
            "Timeticks": ber.TIMETICKS,
        }[typ]
        val = val.split()[0] if typ != "Timeticks" else val
        if typ == "Timeticks":
            tm = re.match(r"^\(?(\d+)\)?", val)
            if not tm:
                raise ber.BerError(f"bad Timeticks {val!r}")
            return Value(tag, int(tm.group(1)))
        lm = _INT_LABEL.match(val)
        return Value(tag, int(lm.group(1)) if lm else int(val))
    if typ == "OID":
        if not re.match(r"^\.?[0-9][0-9.]*$", val):
            raise ber.BerError(f"symbolic OID value {val!r}: walk with -On")
        return Value(ber.OBJECT_IDENTIFIER, ber.parse_oid(val))
    if typ in ("IpAddress", "Network Address"):
        if ":" in val and not re.match(r"^\d+\.\d+\.\d+\.\d+$", val):
            return Value(ber.IP_ADDRESS, _hex_bytes(val))
        return Value(ber.IP_ADDRESS, socket.inet_aton(val))
    if typ == "Opaque":
        return Value(ber.OPAQUE, _hex_bytes(val))
    if typ == "NULL":
        return None
    if typ == "Wrong Type (should be OCTET STRING)":  # pragma: no cover - defensive
        return None
    # Untyped string that happens to contain a colon.
    return Value(ber.OCTET_STRING, _unquote(raw))


def parse_walk(text: str, source: str = "<walk>") -> Varbinds:
    """Parse ``snmpwalk``/``snmpbulkwalk`` output produced with ``-On``.

    Accepts the default typed format, ``-Ox`` (hex strings), ``-Oe`` (numeric
    enums) or symbolic enums ``fullDuplex(3)``, and multi-line STRING values.
    """
    out: Varbinds = []
    pending: Optional[Tuple[OID, str]] = None
    lineno = 0

    def flush() -> None:
        nonlocal pending
        if pending is None:
            return
        oid, rhs = pending
        pending = None
        try:
            v = parse_value(rhs)
        except (ber.BerError, ValueError, OSError) as exc:
            raise ber.BerError(f"{source}: {ber.format_oid(oid)}: {exc}") from exc
        if v is not None:
            out.append((oid, v))

    for lineno, line in enumerate(text.splitlines(), 1):
        if line.startswith("iso."):  # net-snmp without MIBs and without -On
            line = "1." + line[4:]
        m = _LINE.match(line)
        if m:
            flush()
            try:
                oid = ber.parse_oid(m.group(1))
            except ber.BerError as exc:
                raise ber.BerError(f"{source}:{lineno}: {exc}") from exc
            pending = (oid, m.group(2))
        elif pending is not None and line.strip():
            oid, rhs = pending
            # Continuation of a multi-line STRING or Hex-STRING value.
            sep = " " if rhs.startswith("Hex-STRING") else "\n"
            pending = (oid, rhs + sep + line.strip())
        elif line.strip() and not line.lstrip().startswith("#"):
            if re.match(r"^[A-Za-z][\w-]*::", line):
                raise ber.BerError(f"{source}:{lineno}: symbolic OID found: re-run the walk with -On")
            if line.startswith(("Timeout", "snmp")):
                raise ber.BerError(f"{source}:{lineno}: not walk data: {line.strip()[:80]}")
    flush()
    out.sort(key=lambda vb: vb[0])
    return out


@dataclass
class FileWalker:
    name: str
    varbinds: Varbinds
    requests: int = 0

    def __post_init__(self) -> None:
        self.varbinds.sort(key=lambda vb: vb[0])
        self._keys = [vb[0] for vb in self.varbinds]

    @classmethod
    def from_file(cls, path: str) -> FileWalker:
        with open(path, encoding="utf-8", errors="surrogateescape") as fh:
            text = fh.read()
        name = os.path.basename(path)
        for ext in (".walk", ".snmpwalk", ".txt"):
            if name.endswith(ext):
                name = name[: -len(ext)]
                break
        return cls(name, parse_walk(text, path))

    def walk(self, root: OID) -> Varbinds:
        self.requests += 1
        i = bisect.bisect_right(self._keys, root)
        out: Varbinds = []
        while i < len(self.varbinds) and in_subtree(self.varbinds[i][0], root):
            out.append(self.varbinds[i])
            i += 1
        return out

    def close(self) -> None:
        pass


def dump_walk(varbinds: Iterable[Tuple[OID, Value]]) -> str:
    """Serialise varbinds in ``snmpbulkwalk -On -Ox`` style (round-trips through parse_walk)."""
    lines = []
    for oid, v in varbinds:
        o = ber.format_oid(oid)
        if v.tag == ber.OCTET_STRING:
            data = bytes(v.value)  # type: ignore[arg-type]
            rhs = "Hex-STRING: " + " ".join(f"{b:02X}" for b in data) if data else '""'
        elif v.tag == ber.INTEGER:
            rhs = f"INTEGER: {v.value}"
        elif v.tag == ber.COUNTER32:
            rhs = f"Counter32: {v.value}"
        elif v.tag == ber.GAUGE32:
            rhs = f"Gauge32: {v.value}"
        elif v.tag == ber.COUNTER64:
            rhs = f"Counter64: {v.value}"
        elif v.tag == ber.TIMETICKS:
            rhs = f"Timeticks: ({v.value})"
        elif v.tag == ber.OBJECT_IDENTIFIER:
            rhs = "OID: " + ber.format_oid(v.value)  # type: ignore[arg-type]
        elif v.tag == ber.IP_ADDRESS:
            raw = bytes(v.value)  # type: ignore[arg-type]
            rhs = "IpAddress: " + (socket.inet_ntoa(raw) if len(raw) == 4 else raw.hex(":"))
        elif v.tag == ber.OPAQUE:
            rhs = "Opaque: " + " ".join(f"{b:02X}" for b in bytes(v.value))  # type: ignore[arg-type]
        else:
            continue
        lines.append(f"{o} = {rhs}")
    return "\n".join(lines) + ("\n" if lines else "")


# --------------------------------------------------------------------------- net-snmp back-end

Runner = Callable[[List[str], Dict[str, str], float], Tuple[int, str, str]]


def default_runner(cmd: List[str], env: Dict[str, str], timeout: float) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, env=env, timeout=timeout, check=False, errors="surrogateescape"
        )
    except subprocess.TimeoutExpired as exc:
        raise SnmpTimeout(f"{cmd[0]} timed out after {timeout:g}s") from exc
    except OSError as exc:
        raise SnmpError(f"{cmd[0]}: {exc}") from exc
    return proc.returncode, proc.stdout, proc.stderr


V3_AUTH = ("MD5", "SHA", "SHA-224", "SHA-256", "SHA-384", "SHA-512")
V3_PRIV = ("DES", "AES", "AES-192", "AES-256")


def _conf_quote(value: str) -> str:
    if any(c in value for c in "\r\n\0"):
        raise SnmpError("SNMP credentials must not contain line breaks or NUL characters")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


@dataclass
class V3Credentials:
    user: str
    auth_proto: Optional[str] = None
    auth_pass: Optional[str] = None
    priv_proto: Optional[str] = None
    priv_pass: Optional[str] = None
    context: Optional[str] = None

    @property
    def level(self) -> str:
        if self.priv_proto:
            return "authPriv"
        if self.auth_proto:
            return "authNoPriv"
        return "noAuthNoPriv"


class NetSnmpConfig:
    """A private directory holding the snmp.conf given to net-snmp (mode 0700/0600)."""

    def __init__(self, version: str, community: Optional[bytes], v3: Optional[V3Credentials]):
        lines = []
        if version == "3":
            assert v3 is not None
            lines += ["defVersion 3", f"defSecurityName {_conf_quote(v3.user)}", f"defSecurityLevel {v3.level}"]
            if v3.auth_proto:
                lines += [f"defAuthType {v3.auth_proto}", f"defAuthPassphrase {_conf_quote(v3.auth_pass or '')}"]
            if v3.priv_proto:
                lines += [f"defPrivType {v3.priv_proto}", f"defPrivPassphrase {_conf_quote(v3.priv_pass or '')}"]
            if v3.context:
                lines.append(f"defContext {_conf_quote(v3.context)}")
        else:
            assert community is not None
            lines += [
                f"defVersion {version}",
                f"defCommunity {_conf_quote(community.decode('utf-8', 'surrogateescape'))}",
            ]
        self.dir = tempfile.mkdtemp(prefix="lldp-mapper-")  # created with mode 0700
        path = os.path.join(self.dir, "snmp.conf")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        self.env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LC_ALL": "C",
            "SNMPCONFPATH": self.dir,
            "SNMP_PERSISTENT_DIR": self.dir,
            "MIBS": "",
            "MIBDIRS": self.dir,
            "HOME": self.dir,
        }

    def cleanup(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)


@dataclass
class NetSnmpWalker:
    host: str
    config: NetSnmpConfig
    version: str = "3"
    port: int = 161
    timeout: float = 2.0
    retries: int = 2
    max_repetitions: int = 25
    deadline: Optional[float] = None
    runner: Runner = default_runner
    requests: int = 0

    def _binary(self) -> str:
        name = "snmpwalk" if self.version == "1" else "snmpbulkwalk"
        exe = shutil.which(name, path=self.config.env["PATH"])
        if exe is None:
            raise SnmpError(
                f"{name} not found: install net-snmp (Debian/Ubuntu: apt install snmp, "
                "RHEL: dnf install net-snmp-utils)"
            )
        return exe

    def walk(self, root: OID) -> Varbinds:
        cmd = [self._binary(), "-On", "-Oe", "-Ox", "-Ot", "-t", f"{self.timeout:g}", "-r", str(self.retries)]
        if self.version != "1":
            cmd.append(f"-Cr{max(1, self.max_repetitions)}")
        host = self.host
        if ":" in host and not host.startswith("["):
            host = f"udp6:[{host}]"
        cmd += [f"{host}:{self.port}", ber.format_oid(root)]
        budget = (self.timeout * (self.retries + 1)) * 50 + 10
        if self.deadline is not None:
            left = self.deadline - time.monotonic()
            if left <= 0:
                raise SnmpTimeout(f"{self.host}: per-device time budget exhausted")
            budget = min(budget, left)
        self.requests += 1
        rc, out, err = self.runner(cmd, dict(self.config.env), budget)
        err_lines = [ln.strip() for ln in err.splitlines() if ln.strip()]
        if rc != 0:
            msg = err_lines[-1] if err_lines else f"exit status {rc}"
            if "Timeout" in msg:
                raise SnmpTimeout(f"{self.host}: {msg} (agent down, ACL or wrong credentials)")
            raise SnmpError(f"{self.host}: {msg}")
        try:
            vbs = parse_walk(out, f"{self.host}:{ber.format_oid(root)}")
        except ber.BerError as exc:
            raise SnmpError(str(exc)) from exc
        return [vb for vb in vbs if in_subtree(vb[0], root)]

    def close(self) -> None:
        pass
