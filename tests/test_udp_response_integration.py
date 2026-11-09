
"""Integration tests for request-aware UDP validation."""

import socket
import struct
import unittest
from unittest.mock import MagicMock, patch

from scanner.udp_scanner import scan_udp_port
from scanner.udp_probes import (
    build_dns_query,
    build_ntp_request,
)


class TestUDPResponseIntegration(unittest.TestCase):

    def run_mock_scan(self, port, probe, response):
        """Simulate one UDP request and response."""
        mock_socket = MagicMock()
        mock_socket.__enter__.return_value = mock_socket
        mock_socket.recv.return_value = response

        with (
            patch(
                "scanner.udp_scanner.socket.socket",
                return_value=mock_socket
            ),
            patch(
                "scanner.udp_scanner.build_udp_probe",
                return_value=probe
            )
        ):
            state = scan_udp_port(
                "127.0.0.1",
                port,
                timeout=0.5
            )

        mock_socket.connect.assert_called_once_with(
            ("127.0.0.1", port)
        )
        mock_socket.send.assert_called_once_with(probe)

        return state

    def make_dns_response(self, query):
        header = struct.pack(
            "!HHHHHH",
            struct.unpack("!H", query[:2])[0],
            0x8180,
            1, 1, 0, 0
        )

        return header + query[12:]

    def make_ntp_response(self, request):
        response = bytearray(48)

        response[0] = 0x24
        response[1] = 2

        # Echo the client's transmit timestamp.
        response[24:32] = request[40:48]

        # Server transmit timestamp.
        response[40:48] = b"\x01" * 8

        return bytes(response)

    def test_valid_dns_response_is_open(self):
        with patch(
            "scanner.udp_probes.secrets.randbits",
            return_value=0x1234
        ):
            query = build_dns_query()

        response = self.make_dns_response(query)

        state = self.run_mock_scan(
            53, query, response
        )

        self.assertEqual(state, "open")

    def test_wrong_dns_transaction_id(self):
        with patch(
            "scanner.udp_probes.secrets.randbits",
            return_value=0x1234
        ):
            query = build_dns_query()

        response = bytearray(
            self.make_dns_response(query)
        )

        response[:2] = b"\x99\x99"

        state = self.run_mock_scan(
            53, query, bytes(response)
        )

        self.assertEqual(state, "open|filtered")

    def test_valid_ntp_response_is_open(self):
        with patch(
            "scanner.udp_probes.secrets.randbits",
            return_value=0x123456789ABCDEF0
        ):
            request = build_ntp_request()

        response = self.make_ntp_response(request)

        state = self.run_mock_scan(
            123, request, response
        )

        self.assertEqual(state, "open")

    def test_wrong_ntp_originate_timestamp(self):
        with patch(
            "scanner.udp_probes.secrets.randbits",
            return_value=0x123456789ABCDEF0
        ):
            request = build_ntp_request()

        response = bytearray(
            self.make_ntp_response(request)
        )

        response[24:32] = b"\x99" * 8

        state = self.run_mock_scan(
            123, request, bytes(response)
        )

        self.assertEqual(state, "open|filtered")

    def test_generic_udp_response(self):
        state = self.run_mock_scan(
            161,
            b"\x00",
            b"TEST RESPONSE"
        )

        self.assertEqual(state, "open")

    def test_udp_timeout_is_uncertain(self):
        mock_socket = MagicMock()
        mock_socket.__enter__.return_value = mock_socket
        mock_socket.recv.side_effect = socket.timeout()

        with patch(
            "scanner.udp_scanner.socket.socket",
            return_value=mock_socket
        ):
            state = scan_udp_port(
                "127.0.0.1",
                161,
                timeout=0.5
            )

        self.assertEqual(state, "open|filtered")


if __name__ == "__main__":
    unittest.main()
