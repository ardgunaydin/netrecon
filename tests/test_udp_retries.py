
"""Tests for UDP timeout retries and CLI integration."""

import errno
import io
import socket
import unittest
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch

import netrecon

from scanner.udp_scanner import (
    scan_udp_port,
    scan_udp_ports
)


class TestUDPRetries(unittest.TestCase):

    def make_socket(self, response=None, error=None):
        sock = MagicMock()
        sock.__enter__.return_value = sock

        if error is not None:
            sock.recv.side_effect = error
        else:
            sock.recv.return_value = response

        return sock

    def test_timeout_then_success(self):
        first = self.make_socket(error=socket.timeout())
        second = self.make_socket(response=b"OK")

        with patch(
            "scanner.udp_scanner.socket.socket",
            side_effect=[first, second]
        ) as factory:
            result = scan_udp_port(
                "127.0.0.1",
                161,
                timeout=0.1,
                retries=2
            )

        self.assertEqual(result, "open")
        self.assertEqual(factory.call_count, 2)

    def test_retries_exhausted(self):
        sockets = [
            self.make_socket(error=socket.timeout())
            for _ in range(3)
        ]

        with patch(
            "scanner.udp_scanner.socket.socket",
            side_effect=sockets
        ) as factory:
            result = scan_udp_port(
                "127.0.0.1",
                161,
                timeout=0.1,
                retries=2
            )

        self.assertEqual(result, "open|filtered")
        self.assertEqual(factory.call_count, 3)

    def test_invalid_response_does_not_retry(self):
        sock = self.make_socket(response=b"")

        with patch(
            "scanner.udp_scanner.socket.socket",
            return_value=sock
        ) as factory:
            result = scan_udp_port(
                "127.0.0.1",
                161,
                retries=3
            )

        self.assertEqual(result, "open|filtered")
        self.assertEqual(factory.call_count, 1)

    def test_closed_port_does_not_retry(self):
        sock = self.make_socket(
            error=ConnectionRefusedError(errno.ECONNREFUSED, "refused")
        )

        with patch(
            "scanner.udp_scanner.socket.socket",
            return_value=sock
        ) as factory:
            result = scan_udp_port(
                "127.0.0.1",
                161,
                retries=3
            )

        self.assertEqual(result, "closed")
        self.assertEqual(factory.call_count, 1)

    def test_no_retries_by_default(self):
        sock = self.make_socket(error=socket.timeout())

        with patch(
            "scanner.udp_scanner.socket.socket",
            return_value=sock
        ) as factory:
            result = scan_udp_port(
                "127.0.0.1",
                161
            )

        self.assertEqual(result, "open|filtered")
        self.assertEqual(factory.call_count, 1)

    def test_invalid_retries(self):
        for value in (-1, 6, 1.5, True):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    scan_udp_port(
                        "127.0.0.1",
                        161,
                        retries=value
                    )

                with self.assertRaises(ValueError):
                    scan_udp_ports(
                        "127.0.0.1",
                        ports=[161],
                        retries=value
                    )

    def test_multiport_retry_forwarding(self):
        with patch(
            "scanner.udp_scanner.scan_udp_port",
            return_value="open"
        ) as mocked:
            with redirect_stdout(io.StringIO()):
                results = scan_udp_ports(
                    "127.0.0.1",
                    ports=[161],
                    threads=1,
                    retries=2
                )

        self.assertEqual(results[0]["state"], "open")
        self.assertEqual(
            mocked.call_args.kwargs["retries"],
            2
        )

    def test_cli_retry_option(self):
        args = [
            "netrecon.py",
            "-t", "127.0.0.1/32",
            "--udp",
            "-p", "161-161",
            "--skip-discovery",
            "--udp-retries", "2"
        ]

        with (
            patch("sys.argv", args),
            patch(
                "netrecon.scan_udp_ports",
                return_value=[]
            ) as mocked,
            redirect_stdout(io.StringIO())
        ):
            netrecon.main()

        self.assertEqual(
            mocked.call_args.kwargs["retries"],
            2
        )

    def test_cli_rejects_invalid_retries(self):
        args = [
            "netrecon.py",
            "-t", "127.0.0.1/32",
            "--udp",
            "-p", "161-161",
            "--skip-discovery",
            "--udp-retries", "6"
        ]

        output = io.StringIO()

        with (
            patch("sys.argv", args),
            patch("netrecon.scan_udp_ports") as mocked,
            redirect_stdout(output)
        ):
            netrecon.main()

        self.assertIn(
            "UDP retries must be between 0 and 5",
            output.getvalue()
        )
        mocked.assert_not_called()


if __name__ == "__main__":
    unittest.main()
