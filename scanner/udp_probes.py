
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


def _read_dns_name(packet, offset):
    """
    Parse a DNS name, including compression pointers.

    Returns (normalized_labels, next_offset), or None
    for malformed names.
    """
    labels = []
    visited = set()
    next_offset = None
    name_length = 1

    for _ in range(128):
        if offset >= len(packet):
            return None

        length = packet[offset]

        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                return None

            pointer = (
                ((length & 0x3F) << 8)
                | packet[offset + 1]
            )

            # DNS pointers must point backwards.
            if pointer >= offset or pointer in visited:
                return None

            visited.add(pointer)

            if next_offset is None:
                next_offset = offset + 2

            offset = pointer
            continue

        if length & 0xC0:
            return None

        offset += 1

        if length == 0:
            return (
                tuple(labels),
                next_offset if next_offset is not None else offset
            )

        if length > 63 or offset + length > len(packet):
            return None

        name_length += length + 1

        if name_length > 255:
            return None

        labels.append(
            packet[offset:offset + length].lower()
        )

        offset += length

    return None


def _parse_dns_question(packet):
    """Read the first DNS question safely."""
    parsed = _read_dns_name(packet, 12)

    if parsed is None:
        return None

    labels, offset = parsed

    if offset + 4 > len(packet):
        return None

    question_type, question_class = struct.unpack(
        "!HH",
        packet[offset:offset + 4]
    )

    return labels, question_type, question_class


def validate_dns_response(response, query):
    """
    Validate a DNS response against the original request.

    Names are compared case-insensitively, while DNS
    transaction ID, opcode, type and class must match.
    """
    if len(query) < 17 or len(response) < 17:
        return False

    if query[:2] != response[:2]:
        return False

    query_flags = struct.unpack("!H", query[2:4])[0]
    response_flags = struct.unpack("!H", response[2:4])[0]

    # Original query must not be a response.
    if query_flags & 0x8000:
        return False

    # Received packet must be a response.
    if not response_flags & 0x8000:
        return False

    # Match DNS opcode.
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

    original_question = _parse_dns_question(query)
    returned_question = _parse_dns_question(response)

    if original_question is None or returned_question is None:
        return False

    return original_question == returned_question


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

    Check server mode, version, synchronization state,
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

        flags = struct.unpack(
            "!H", response[2:4]
        )[0]

        return bool(flags & 0x8000)

    if port == 123:
        if len(response) < 48:
            return False

        return (response[0] & 0x07) == 4

    return True
