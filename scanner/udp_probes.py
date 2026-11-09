
"""Protocol-aware UDP probes for NetRecon."""

import secrets
import struct


# ==================================================
# DNS PROBES
# ==================================================

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
    """Check that a DNS response matches the original query."""
    if len(query) < 17 or len(response) < 17:
        return False

    if query[:2] != response[:2]:
        return False

    query_flags = struct.unpack("!H", query[2:4])[0]
    response_flags = struct.unpack("!H", response[2:4])[0]

    if query_flags & 0x8000:
        return False

    if not response_flags & 0x8000:
        return False

    if (query_flags & 0x7800) != (response_flags & 0x7800):
        return False

    query_questions = struct.unpack("!H", query[4:6])[0]
    response_questions = struct.unpack("!H", response[4:6])[0]

    if query_questions != 1 or response_questions != 1:
        return False

    question = query[12:]

    if response[12:12 + len(question)] != question:
        return False

    return True


# ==================================================
# NTP PROBES
# ==================================================

def build_ntp_request():
    """
    Build a 48-byte NTPv4 client request.

    Use a random nonzero transmit timestamp as a
    request-correlation token.
    """
    request = bytearray(48)

    # Leap = 0, Version = 4, Mode = 3 (client)
    request[0] = 0x23

    token = secrets.randbits(64) or 1

    # NTP transmit timestamp: bytes 40-47
    request[40:48] = struct.pack("!Q", token)

    return bytes(request)


def validate_ntp_response(response, request):
    """
    Validate an NTPv4 server response against the request.

    Check the server mode, version, synchronization state,
    stratum and echoed originate timestamp.
    """
    if len(request) != 48 or len(response) < 48:
        return False

    request_first = request[0]
    request_version = (request_first >> 3) & 0x07
    request_mode = request_first & 0x07

    if request_version != 4 or request_mode != 3:
        return False

    response_first = response[0]

    leap_indicator = (response_first >> 6) & 0x03
    version = (response_first >> 3) & 0x07
    mode = response_first & 0x07

    if version != request_version:
        return False

    if mode != 4:
        return False

    # LI = 3 means the server is not synchronized.
    if leap_indicator == 3:
        return False

    # Stratum 0 is Kiss-o'-Death or unspecified.
    # Stratum 16+ is not synchronized.
    stratum = response[1]

    if not 1 <= stratum <= 15:
        return False

    # Client transmit timestamp must be nonzero.
    client_transmit = request[40:48]

    if client_transmit == bytes(8):
        return False

    # Server originate timestamp must echo client transmit.
    server_originate = response[24:32]

    if server_originate != client_transmit:
        return False

    # Server transmit timestamp must be populated.
    if response[40:48] == bytes(8):
        return False

    return True


# ==================================================
# UDP PROBE SELECTION
# ==================================================

def build_udp_probe(port):
    """Select the appropriate probe for a UDP port."""
    if port == 53:
        return build_dns_query()

    if port == 123:
        return build_ntp_request()

    return b"\x00"


def is_valid_udp_response(port, response):
    """
    Legacy/basic response validation.

    Request-aware DNS and NTP checks are handled
    separately by their validation functions.
    """
    if not response:
        return False

    if port == 53:
        if len(response) < 12:
            return False

        flags = struct.unpack("!H", response[2:4])[0]
        return bool(flags & 0x8000)

    if port == 123:
        if len(response) < 48:
            return False

        return (response[0] & 0x07) == 4

    return True
