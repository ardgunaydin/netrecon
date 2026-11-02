
"""Protocol-aware UDP probes for NetRecon."""

import secrets
import struct


def build_dns_query():
    """Build a DNS A-record query for example.com."""
    transaction_id = secrets.randbits(16)

    header = struct.pack(
        "!HHHHHH",
        transaction_id,
        0x0100,  # Recursion desired
        1,       # One question
        0, 0, 0
    )

    question = (
        b"\x07example"
        b"\x03com\x00"
        + struct.pack("!HH", 1, 1)
    )

    return header + question


def build_ntp_request():
    """Build a 48-byte NTP client request."""
    request = bytearray(48)
    request[0] = 0x23  # NTP v4, client mode
    return bytes(request)


def build_udp_probe(port):
    """Select the appropriate UDP probe by destination port."""
    if port == 53:
        return build_dns_query()

    if port == 123:
        return build_ntp_request()

    return b"\x00"


def is_valid_udp_response(port, response):
    """Perform basic protocol response validation."""
    if not response:
        return False

    if port == 53:
        if len(response) < 12:
            return False

        flags = struct.unpack("!H", response[2:4])[0]

        # DNS QR bit must indicate a response.
        return bool(flags & 0x8000)

    if port == 123:
        if len(response) < 48:
            return False

        mode = response[0] & 0x07

        # NTP server mode.
        return mode == 4

    return True
