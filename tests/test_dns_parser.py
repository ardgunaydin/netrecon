
import struct
import unittest
from unittest.mock import patch

from scanner.udp_probes import (
    _read_dns_name,
    build_dns_query,
    validate_dns_response,
)


class TestDNSParser(unittest.TestCase):

    def setUp(self):
        with patch(
            "scanner.udp_probes.secrets.randbits",
            return_value=0x1234
        ):
            self.query = build_dns_query()

    def make_response(self, question=None):
        header = struct.pack(
            "!HHHHHH",
            0x1234, 0x8180, 1, 0, 0, 0
        )
        return header + (
            self.query[12:] if question is None else question
        )

    def test_original_question(self):
        self.assertTrue(
            validate_dns_response(
                self.make_response(),
                self.query
            )
        )

    def test_case_insensitive_name(self):
        question = (
            b"\x07EXAMPLE\x03COM\x00"
            + struct.pack("!HH", 1, 1)
        )
        self.assertTrue(
            validate_dns_response(
                self.make_response(question),
                self.query
            )
        )

    def test_different_domain(self):
        question = (
            b"\x07invalid\x03com\x00"
            + struct.pack("!HH", 1, 1)
        )
        self.assertFalse(
            validate_dns_response(
                self.make_response(question),
                self.query
            )
        )

    def test_different_record_type(self):
        question = (
            b"\x07example\x03com\x00"
            + struct.pack("!HH", 28, 1)
        )
        self.assertFalse(
            validate_dns_response(
                self.make_response(question),
                self.query
            )
        )

    def test_truncated_question(self):
        self.assertFalse(
            validate_dns_response(
                self.make_response(b"\x07exam"),
                self.query
            )
        )

    def test_pointer_loop_rejected(self):
        packet = bytes(12) + b"\xc0\x0c"
        self.assertIsNone(
            _read_dns_name(packet, 12)
        )

    def test_compressed_name_parser(self):
        packet = (
            b"\x07example\x03com\x00"
            b"\x03www\xc0\x00"
        )

        parsed = _read_dns_name(packet, 13)

        self.assertEqual(
            parsed,
            ((b"www", b"example", b"com"), 19)
        )

    def test_invalid_transaction_id(self):
        response = bytearray(self.make_response())
        response[0:2] = b"\x99\x99"

        self.assertFalse(
            validate_dns_response(
                bytes(response),
                self.query
            )
        )


if __name__ == "__main__":
    unittest.main()
