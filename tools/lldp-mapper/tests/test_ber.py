import pytest

from lldp_mapper import ber
from lldp_mapper.ber import Value


def test_oid_known_encoding():
    assert ber.enc_oid((1, 3, 6, 1, 2, 1, 1, 5, 0)).hex() == "06082b06010201010500"
    assert ber.enc_oid((1, 0, 8802, 1, 1, 2)).hex() == "060628c4620101" + "02"


@pytest.mark.parametrize(
    "oid",
    [(1, 3, 6, 1), (0, 0), (2, 999, 3), (1, 3, 6, 1, 4, 1, 2**32 - 1, 128, 16383, 16384)],
)
def test_oid_roundtrip(oid):
    raw = ber.enc_oid(oid)
    tag, s, e = ber.read_tlv(raw, 0)
    assert tag == ber.OBJECT_IDENTIFIER
    assert ber.dec_oid(raw[s:e]) == oid


@pytest.mark.parametrize("n", [0, 1, 127, 128, 255, 256, -1, -128, -129, 2**31 - 1, -(2**31)])
def test_integer_roundtrip(n):
    raw = ber.enc_int(n)
    tag, s, e = ber.read_tlv(raw, 0)
    assert ber.dec_int(raw[s:e]) == n


def test_unsigned_application_types_roundtrip():
    for tag, n in ((ber.COUNTER32, 2**32 - 1), (ber.GAUGE32, 1000), (ber.COUNTER64, 2**64 - 1), (ber.TIMETICKS, 0)):
        raw = ber.encode_value(Value(tag, n))
        t, s, e = ber.read_tlv(raw, 0)
        assert ber.decode_value(t, raw[s:e]) == Value(tag, n)


def test_message_roundtrip_and_long_lengths():
    vbs = [((1, 3, 6, 1, 2, 1, 1, i, 0), Value(ber.OCTET_STRING, b"x" * 300)) for i in range(5)]
    vbs.append(((1, 3, 6, 1, 2, 1, 1, 9), Value(ber.END_OF_MIB_VIEW, None)))
    raw = ber.encode_response(1, b"public", 4242, vbs)
    msg = ber.decode_message(raw)
    assert msg.version == 1 and msg.community == b"public"
    assert msg.pdu.request_id == 4242 and msg.pdu.tag == ber.GET_RESPONSE
    assert msg.pdu.varbinds == vbs
    assert msg.pdu.varbinds[-1][1].is_exception


def test_request_encoding_is_decodable():
    raw = ber.encode_request(1, b"c", ber.GET_BULK_REQUEST, 7, [(1, 3, 6)], 0, 25)
    msg = ber.decode_message(raw)
    assert msg.pdu.tag == ber.GET_BULK_REQUEST
    assert (msg.pdu.error_status, msg.pdu.error_index) == (0, 25)


@pytest.mark.parametrize("cut", [1, 2, 5, 10, 20])
def test_truncated_messages_raise(cut):
    raw = ber.encode_response(1, b"public", 1, [((1, 3, 6, 1), Value(ber.INTEGER, 5))])
    with pytest.raises(ber.BerError):
        ber.decode_message(raw[:-cut])


def test_garbage_raises():
    for raw in (b"", b"\x30", b"\x02\x01\x00", b"\x30\x85\x00\x00\x00\x00\x00", b"\x30\x03\x02\x01\x01"):
        with pytest.raises(ber.BerError):
            ber.decode_message(raw)


def test_parse_and_format_oid():
    assert ber.parse_oid(".1.3.6.1") == (1, 3, 6, 1)
    assert ber.format_oid((1, 3, 6)) == ".1.3.6"
    with pytest.raises(ber.BerError):
        ber.parse_oid("IF-MIB::ifName")
    with pytest.raises(ber.BerError):
        ber.enc_oid((1, 40))
