
import struct
import unittest
from unittest.mock import patch

from scanner.udp_probes import (
    build_dns_query,
    validate_dns_response
)


class TestDNSValidation(unittest.TestCase):

    def setUp(self):
        with patch(
            "scanner.udp_probes.secrets.randbits",
            return_value=0x1234
        ):
            self.query = build_dns_query()

    def make_response(self, transaction_id=0x1234):
        header = struct.pack(
            "!HHHHHH",
            transaction_id,
            0x8180,
            1,
            1, 0, 0
        )

        return header + self.query[12:]

    def test_valid_response(self):
        response = self.make_response()

        self.assertTrue(
            validate_dns_response(response, self.query)
        )

    def test_mismatched_transaction_id(self):
        response = self.make_response(
            transaction_id=0x9999
        )

        self.assertFalse(
            validate_dns_response(response, self.query)
        )

    def test_invalid_response_flag(self):
        response = bytearray(self.make_response())

        # Remove the DNS response bit.
        response[2] &= 0x7F

        self.assertFalse(
            validate_dns_response(
                bytes(response),
                self.query
            )
        )

    def test_mismatched_question(self):
        response = bytearray(self.make_response())

        # Modify the queried domain.
        response[13] = ord("x")

        self.assertFalse(
            validate_dns_response(
                bytes(response),
                self.query
            )
        )

    def test_truncated_response(self):
        self.assertFalse(
            validate_dns_response(
                b"\x12\x34",
                self.query
            )
        )

    def test_invalid_opcode(self):
        response = bytearray(self.make_response())

        # Change the DNS opcode.
        response[2] |= 0x08

        self.assertFalse(
            validate_dns_response(
                bytes(response),
                self.query
            )
        )


if __name__ == "__main__":
    unittest.main()
