
import struct
import unittest
from unittest.mock import patch

from scanner.udp_probes import (
    build_dns_query,
    build_ntp_request,
    build_udp_probe,
    is_valid_udp_response,
)


class TestUDPProbes(unittest.TestCase):

    @patch("scanner.udp_probes.secrets.randbits", return_value=0x1234)
    def test_dns_query(self, mock_randbits):
        query = build_dns_query()

        self.assertEqual(query[:2], b"\x12\x34")
        self.assertEqual(query[2:4], b"\x01\x00")
        self.assertIn(b"\x07example\x03com\x00", query)
        self.assertEqual(query[-4:], struct.pack("!HH", 1, 1))

    def test_ntp_request(self):
        request = build_ntp_request()

        self.assertEqual(len(request), 48)
        self.assertEqual(request[0], 0x23)

    def test_probe_selection(self):
        self.assertGreater(len(build_udp_probe(53)), 12)
        self.assertEqual(len(build_udp_probe(123)), 48)
        self.assertEqual(build_udp_probe(161), b"\x00")

    def test_valid_dns_response(self):
        response = b"\x12\x34\x81\x80" + bytes(8)

        self.assertTrue(is_valid_udp_response(53, response))

    def test_invalid_dns_response(self):
        self.assertFalse(
            is_valid_udp_response(53, bytes(12))
        )
        self.assertFalse(
            is_valid_udp_response(53, b"\x81")
        )

    def test_ntp_response(self):
        response = bytearray(48)
        response[0] = 0x24  # NTP version 4, server mode

        self.assertTrue(
            is_valid_udp_response(123, bytes(response))
        )
        self.assertFalse(
            is_valid_udp_response(123, bytes(10))
        )

    def test_generic_udp_response(self):
        self.assertTrue(is_valid_udp_response(161, b"OK"))
        self.assertFalse(is_valid_udp_response(161, b""))


if __name__ == "__main__":
    unittest.main()
