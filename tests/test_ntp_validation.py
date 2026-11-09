
"""Tests for NTP request-response correlation."""

import unittest
from unittest.mock import patch

from scanner.udp_probes import (
    build_ntp_request,
    validate_ntp_response
)


class TestNTPValidation(unittest.TestCase):

    def setUp(self):
        with patch(
            "scanner.udp_probes.secrets.randbits",
            return_value=0x123456789ABCDEF0
        ):
            self.request = build_ntp_request()

    def make_response(self):
        response = bytearray(48)

        # NTPv4 server mode
        response[0] = 0x24

        # Primary reference server
        response[1] = 2

        # Echo the client transmit timestamp
        response[24:32] = self.request[40:48]

        # Server transmit timestamp
        response[40:48] = b"\x01" * 8

        return response

    def test_request_contains_token(self):
        self.assertEqual(len(self.request), 48)

        self.assertEqual(
            self.request[40:48],
            bytes.fromhex("123456789abcdef0")
        )

    def test_valid_ntp_response(self):
        response = self.make_response()

        self.assertTrue(
            validate_ntp_response(
                bytes(response),
                self.request
            )
        )

    def test_mismatched_originate_timestamp(self):
        response = self.make_response()
        response[24:32] = b"\x99" * 8

        self.assertFalse(
            validate_ntp_response(
                bytes(response),
                self.request
            )
        )

    def test_invalid_server_mode(self):
        response = self.make_response()
        response[0] = 0x23

        self.assertFalse(
            validate_ntp_response(
                bytes(response),
                self.request
            )
        )

    def test_invalid_stratum(self):
        response = self.make_response()
        response[1] = 0

        self.assertFalse(
            validate_ntp_response(
                bytes(response),
                self.request
            )
        )

    def test_unsynchronized_server(self):
        response = self.make_response()

        # Leap indicator = 3
        response[0] = 0xE4

        self.assertFalse(
            validate_ntp_response(
                bytes(response),
                self.request
            )
        )

    def test_truncated_response(self):
        self.assertFalse(
            validate_ntp_response(
                b"\x24" * 10,
                self.request
            )
        )

    def test_missing_server_transmit_timestamp(self):
        response = self.make_response()
        response[40:48] = bytes(8)

        self.assertFalse(
            validate_ntp_response(
                bytes(response),
                self.request
            )
        )


if __name__ == "__main__":
    unittest.main()
