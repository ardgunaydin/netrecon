
"""Protocol-aware UDP probes for NetRecon."""

import secrets
import struct


def build_dns_query():
    """Build a DNS A-record query for example.com."""
    transaction_id = secrets.randbits(16)

    header = struct.pack(
        "!HHHHHH",
        transaction_id,
        0x0100,
        1,
        0, 0, 0
    )

    question = (
        b"\x07example"
        b"\x03com\x00"
        + struct.pack("!HH", 1, 1)
    )

    return header + question


def validate_dns_response(response, query):
    """
    Validate that a DNS response matches the sent query.

    Checks transaction ID, response flag, opcode,
    question count and original question bytes.
    """
    if len(query) < 17 or len(response) < 17:
        return False

    query_id = query[:2]
    response_id = response[:2]

    if query_id != response_id:
        return False

    query_flags = struct.unpack(
        "!H", query[2:4]
    )[0]

    response_flags = struct.unpack(
        "!H", response[2:4]
    )[0]

    # Query must not have the response flag.
    if query_flags & 0x8000:
        return False

    # DNS QR bit: response required.
    if not response_flags & 0x8000:
        return False

    # Match the DNS opcode.
    if (query_flags & 0x7800) != (response_flags & 0x7800):
        return False

    query_questions = struct.unpack(
        "!H", query[4:6]
    )[0]

    response_questions = struct.unpack(
        "!H", response[4:6]
    )[0]

    if query_questions != 1 or response_questions != 1:
        return False

    # Match the echoed question section.
    question = query[12:]

    if response[12:12 + len(question)] != question:
        return False

    return True


def build_ntp_request():
    """Build a 48-byte NTP client request."""
    request = bytearray(48)
    request[0] = 0x23
    return bytes(request)


def build_udp_probe(port):
    """Select the appropriate UDP probe."""
    if port == 53:
        return build_dns_query()

    if port == 123:
        return build_ntp_request()

    return b"\x00"


def is_valid_udp_response(port, response):
    """
    Basic UDP response validation.

    Request-aware validation is implemented separately.
    """
    if not response:
        return False

    if port == 53:
        if len(response) < 12:
            return False

        flags = struct.unpack(
            "!H", response[2:4]
        )[0]

        return bool(flags & 0x8000)

    if port == 123:
        if len(response) < 48:
            return False

        mode = response[0] & 0x07

        return mode == 4

    return True
