"""Minimal BER codec for SNMPv1/v2c messages (RFC 1157, RFC 3416).

Only what a read-only walker needs is implemented: GetNext/GetBulk requests,
Response PDUs and the SMIv2 application types. Decoding is strict about
lengths so a truncated or malicious datagram raises ``BerError`` instead of
producing garbage.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple

OID = Tuple[int, ...]

# Universal and application tags.
INTEGER = 0x02
OCTET_STRING = 0x04
NULL = 0x05
OBJECT_IDENTIFIER = 0x06
SEQUENCE = 0x30
IP_ADDRESS = 0x40
COUNTER32 = 0x41
GAUGE32 = 0x42
TIMETICKS = 0x43
OPAQUE = 0x44
COUNTER64 = 0x46
NO_SUCH_OBJECT = 0x80
NO_SUCH_INSTANCE = 0x81
END_OF_MIB_VIEW = 0x82

# PDU tags.
GET_REQUEST = 0xA0
GET_NEXT_REQUEST = 0xA1
GET_RESPONSE = 0xA2
GET_BULK_REQUEST = 0xA5
REPORT = 0xA8

EXCEPTIONS = (NO_SUCH_OBJECT, NO_SUCH_INSTANCE, END_OF_MIB_VIEW)

ERROR_STATUS = {
    0: "noError",
    1: "tooBig",
    2: "noSuchName",
    3: "badValue",
    4: "readOnly",
    5: "genErr",
    6: "noAccess",
    7: "wrongType",
    8: "wrongLength",
    9: "wrongEncoding",
    10: "wrongValue",
    11: "noCreation",
    12: "inconsistentValue",
    13: "resourceUnavailable",
    14: "commitFailed",
    15: "undoFailed",
    16: "authorizationError",
    17: "notWritable",
    18: "inconsistentName",
}


class BerError(ValueError):
    """Malformed BER data."""


@dataclass(frozen=True)
class Value:
    """A decoded SNMP value.

    ``tag`` is the BER tag; ``value`` is ``int`` for integer types, ``bytes``
    for OCTET STRING / IpAddress / Opaque, a tuple for OIDs and ``None`` for
    NULL and the v2 exceptions.
    """

    tag: int
    value: object

    @property
    def is_exception(self) -> bool:
        return self.tag in EXCEPTIONS


@dataclass
class Pdu:
    tag: int
    request_id: int
    error_status: int
    error_index: int
    varbinds: List[Tuple[OID, Value]]


@dataclass
class Message:
    version: int
    community: bytes
    pdu: Pdu


# --------------------------------------------------------------------------- encoding


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(out)]) + out


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _len(len(content)) + content


def enc_int(n: int, tag: int = INTEGER) -> bytes:
    length = max(1, (n + (n < 0)).bit_length() // 8 + 1)
    return tlv(tag, n.to_bytes(length, "big", signed=True))


def enc_oid(oid: OID) -> bytes:
    if len(oid) < 2 or oid[0] > 2 or (oid[0] < 2 and oid[1] >= 40):
        raise BerError(f"invalid OID {format_oid(oid)}")
    arcs = [oid[0] * 40 + oid[1], *oid[2:]]
    out = bytearray()
    for arc in arcs:
        if arc < 0:
            raise BerError(f"invalid OID {format_oid(oid)}")
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        out.extend(reversed(chunk))
    return tlv(OBJECT_IDENTIFIER, bytes(out))


def encode_request(
    version: int,
    community: bytes,
    pdu_tag: int,
    request_id: int,
    oids: List[OID],
    non_repeaters: int = 0,
    max_repetitions: int = 0,
) -> bytes:
    """Encode a request message whose varbinds all carry NULL values."""
    varbinds = b"".join(tlv(SEQUENCE, enc_oid(o) + tlv(NULL, b"")) for o in oids)
    if pdu_tag == GET_BULK_REQUEST:
        f2, f3 = non_repeaters, max_repetitions
    else:
        f2, f3 = 0, 0
    pdu = tlv(pdu_tag, enc_int(request_id) + enc_int(f2) + enc_int(f3) + tlv(SEQUENCE, varbinds))
    return tlv(SEQUENCE, enc_int(version) + tlv(OCTET_STRING, community) + pdu)


def encode_value(v: Value) -> bytes:
    """Encode a value (used by the test agent and by walk dumps round-trips)."""
    if v.tag in (INTEGER,):
        return enc_int(int(v.value))  # type: ignore[arg-type]
    if v.tag in (COUNTER32, GAUGE32, TIMETICKS, COUNTER64):
        n = int(v.value)  # type: ignore[arg-type]
        raw = n.to_bytes(max(1, n.bit_length() // 8 + 1), "big")
        return tlv(v.tag, raw)
    if v.tag in (OCTET_STRING, IP_ADDRESS, OPAQUE):
        return tlv(v.tag, bytes(v.value))  # type: ignore[arg-type]
    if v.tag == OBJECT_IDENTIFIER:
        return enc_oid(v.value)  # type: ignore[arg-type]
    if v.tag in (NULL, *EXCEPTIONS):
        return tlv(v.tag, b"")
    raise BerError(f"cannot encode tag 0x{v.tag:02x}")


def encode_response(
    version: int,
    community: bytes,
    request_id: int,
    varbinds: List[Tuple[OID, Value]],
    error_status: int = 0,
    error_index: int = 0,
) -> bytes:
    vbs = b"".join(tlv(SEQUENCE, enc_oid(o) + encode_value(v)) for o, v in varbinds)
    pdu = tlv(GET_RESPONSE, enc_int(request_id) + enc_int(error_status) + enc_int(error_index) + tlv(SEQUENCE, vbs))
    return tlv(SEQUENCE, enc_int(version) + tlv(OCTET_STRING, community) + pdu)


# --------------------------------------------------------------------------- decoding


def read_tlv(data: bytes, pos: int, end: Optional[int] = None) -> Tuple[int, int, int]:
    """Return (tag, content_start, content_end) of the TLV at ``pos``."""
    end = len(data) if end is None else end
    if pos + 2 > end:
        raise BerError("truncated TLV header")
    tag = data[pos]
    if tag & 0x1F == 0x1F:
        raise BerError("multi-byte tags are not supported")
    first = data[pos + 1]
    pos += 2
    if first < 0x80:
        length = first
    else:
        n = first & 0x7F
        if n == 0 or n > 4:
            raise BerError("unsupported length encoding")
        if pos + n > end:
            raise BerError("truncated length")
        length = int.from_bytes(data[pos : pos + n], "big")
        pos += n
    if pos + length > end:
        raise BerError("truncated content")
    return tag, pos, pos + length


def dec_int(raw: bytes, signed: bool = True) -> int:
    if not raw:
        raise BerError("empty integer")
    if len(raw) > 9:
        raise BerError("integer too large")
    return int.from_bytes(raw, "big", signed=signed)


def dec_oid(raw: bytes) -> OID:
    if not raw:
        raise BerError("empty OID")
    arcs: List[int] = []
    n = 0
    for i, b in enumerate(raw):
        n = (n << 7) | (b & 0x7F)
        if b & 0x80:
            if i == len(raw) - 1:
                raise BerError("truncated OID")
            continue
        arcs.append(n)
        n = 0
    first = arcs[0]
    head = (0, first) if first < 40 else (1, first - 40) if first < 80 else (2, first - 80)
    return head + tuple(arcs[1:])


def decode_value(tag: int, raw: bytes) -> Value:
    if tag == INTEGER:
        return Value(tag, dec_int(raw))
    if tag in (COUNTER32, GAUGE32, TIMETICKS, COUNTER64):
        return Value(tag, dec_int(raw, signed=False))
    if tag in (OCTET_STRING, IP_ADDRESS, OPAQUE):
        return Value(tag, bytes(raw))
    if tag == OBJECT_IDENTIFIER:
        return Value(tag, dec_oid(raw))
    if tag in (NULL, *EXCEPTIONS):
        return Value(tag, None)
    # Unknown application type: keep the raw bytes.
    return Value(tag, bytes(raw))


def decode_message(data: bytes) -> Message:
    tag, start, end = read_tlv(data, 0)
    if tag != SEQUENCE:
        raise BerError("message is not a SEQUENCE")
    t, s, e = read_tlv(data, start, end)
    if t != INTEGER:
        raise BerError("missing version")
    version = dec_int(data[s:e])
    t, s, e2 = read_tlv(data, e, end)
    if t != OCTET_STRING:
        raise BerError("missing community")
    community = data[s:e2]
    pdu_tag, ps, pe = read_tlv(data, e2, end)
    if pdu_tag not in (GET_RESPONSE, REPORT, GET_REQUEST, GET_NEXT_REQUEST, GET_BULK_REQUEST):
        raise BerError(f"unexpected PDU type 0x{pdu_tag:02x}")
    fields = []
    pos = ps
    for _ in range(3):
        t, s, e = read_tlv(data, pos, pe)
        if t != INTEGER:
            raise BerError("malformed PDU header")
        fields.append(dec_int(data[s:e]))
        pos = e
    t, vs, ve = read_tlv(data, pos, pe)
    if t != SEQUENCE:
        raise BerError("malformed varbind list")
    varbinds: List[Tuple[OID, Value]] = []
    pos = vs
    while pos < ve:
        t, s, e = read_tlv(data, pos, ve)
        if t != SEQUENCE:
            raise BerError("malformed varbind")
        ot, os_, oe = read_tlv(data, s, e)
        if ot != OBJECT_IDENTIFIER:
            raise BerError("varbind without OID")
        vt, vs2, ve2 = read_tlv(data, oe, e)
        varbinds.append((dec_oid(data[os_:oe]), decode_value(vt, data[vs2:ve2])))
        pos = e
    return Message(version, bytes(community), Pdu(pdu_tag, fields[0], fields[1], fields[2], varbinds))


def format_oid(oid: OID) -> str:
    return "." + ".".join(str(x) for x in oid)


def parse_oid(text: str) -> OID:
    text = text.strip().lstrip(".")
    try:
        oid = tuple(int(x) for x in text.split("."))
    except ValueError as exc:
        raise BerError(f"not a numeric OID: {text!r}") from exc
    if len(oid) < 2 or any(x < 0 for x in oid):
        raise BerError(f"not a valid OID: {text!r}")
    return oid
