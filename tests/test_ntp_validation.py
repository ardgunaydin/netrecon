
"""Tests for NTP timestamp generation and response validation."""

import struct
import unittest
from unittest.mock import patch

from scanner.udp_probes import (
    build_ntp_request,
    validate_ntp_response
)


class TestNTPValidation(unittest.TestCase):

    FIXED_TIME_NS = 1_700_000_000_123_456_789
    NTP_EPOCH_OFFSET = 2_208_988_800

    def setUp(self):
        with patch(
            "scanner.udp_probes.time.time_ns",
            return_value=self.FIXED_TIME_NS
        ):
            self.request = build_ntp_request()

    def make_response(self):
        response = bytearray(48)

        # NTPv4 server mode
        response[0] = 0x24

        # Valid stratum
        response[1] = 2

        # Echo client's transmit timestamp
        response[24:32] = self.request[40:48]

        # Server transmit timestamp
        response[40:48] = b"\x01" * 8

        return response

    def test_request_length(self):
        self.assertEqual(len(self.request), 48)

    def test_ntp_client_mode(self):
        self.assertEqual(self.request[0], 0x23)

    def test_ntp_seconds_conversion(self):
        seconds = struct.unpack(
            "!I",
            self.request[40:44]
        )[0]

        expected = (
            1_700_000_000 + self.NTP_EPOCH_OFFSET
        ) & 0xFFFFFFFF

        self.assertEqual(seconds, expected)

    def test_ntp_fraction_conversion(self):
        fraction = struct.unpack(
            "!I",
            self.request[44:48]
        )[0]

        expected = (
            123_456_789 * (1 << 32)
        ) // 1_000_000_000

        self.assertEqual(fraction, expected)

    def test_timestamp_changes_with_time(self):
        with patch(
            "scanner.udp_probes.time.time_ns",
            return_value=self.FIXED_TIME_NS + 1_000_000_000
        ):
            second_request = build_ntp_request()

        self.assertNotEqual(
            self.request[40:48],
            second_request[40:48]
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
