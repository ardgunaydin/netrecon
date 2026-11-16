
"""CLI integration tests for advanced port selection."""

import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import netrecon


class TestAdvancedPortCLI(unittest.TestCase):

    def run_tcp(self, specification):
        args = [
            "netrecon.py",
            "-t", "127.0.0.1/32",
            "-p", specification,
            "--skip-discovery"
        ]

        output = io.StringIO()

        with (
            patch("sys.argv", args),
            patch(
                "netrecon.scan_ports",
                return_value=[]
            ) as mocked,
            redirect_stdout(output)
        ):
            netrecon.main()

        return mocked, output.getvalue()

    def test_multiple_tcp_ports(self):
        mocked, _ = self.run_tcp("22,80,443")

        self.assertEqual(
            mocked.call_args.kwargs["ports"],
            [22, 80, 443]
        )

    def test_combined_tcp_ports(self):
        mocked, _ = self.run_tcp(
            "22,80,8000-8002"
        )

        self.assertEqual(
            mocked.call_args.kwargs["ports"],
            [22, 80, 8000, 8001, 8002]
        )

    def test_duplicate_removal(self):
        mocked, _ = self.run_tcp("80,80,443")

        self.assertEqual(
            mocked.call_args.kwargs["ports"],
            [80, 443]
        )

    def test_single_tcp_port(self):
        mocked, _ = self.run_tcp("443")

        self.assertEqual(
            mocked.call_args.kwargs["ports"],
            [443]
        )

    def test_legacy_range(self):
        mocked, _ = self.run_tcp("100-102")

        self.assertEqual(
            mocked.call_args.kwargs["start_port"],
            100
        )

        self.assertEqual(
            mocked.call_args.kwargs["end_port"],
            102
        )

        self.assertIsNone(
            mocked.call_args.kwargs["ports"]
        )

    def test_udp_port_selection(self):
        args = [
            "netrecon.py",
            "-t", "127.0.0.1/32",
            "--udp",
            "-p", "53,123,161",
            "--skip-discovery"
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
            mocked.call_args.kwargs["ports"],
            [53, 123, 161]
        )

    def test_invalid_port_spec(self):
        mocked, output = self.run_tcp(
            "22,99999"
        )

        mocked.assert_not_called()

        self.assertIn(
            "Invalid port specification",
            output
        )

    def test_invalid_empty_entry(self):
        mocked, output = self.run_tcp(
            "22,,80"
        )

        mocked.assert_not_called()

        self.assertIn(
            "Invalid port specification",
            output
        )


if __name__ == "__main__":
    unittest.main()
