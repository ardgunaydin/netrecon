
"""CLI tests for excluding TCP and UDP ports."""

import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import netrecon


class TestPortExclusion(unittest.TestCase):

    def run_scan(self, extra_args, udp=False):
        args = [
            "netrecon.py",
            "-t", "127.0.0.1/32",
            "--skip-discovery",
            *extra_args
        ]

        if udp:
            args.append("--udp")

        output = io.StringIO()

        with (
            patch("sys.argv", args),
            patch(
                "netrecon.scan_ports",
                return_value=[]
            ) as tcp_scan,
            patch(
                "netrecon.scan_udp_ports",
                return_value=[]
            ) as udp_scan,
            redirect_stdout(output)
        ):
            netrecon.main()

        return (
            udp_scan if udp else tcp_scan,
            output.getvalue()
        )

    def test_exclude_from_range(self):
        scan, _ = self.run_scan([
            "-p", "80-85",
            "--exclude-ports", "82,84"
        ])

        self.assertEqual(
            scan.call_args.kwargs["ports"],
            [80, 81, 83, 85]
        )

    def test_exclude_from_custom_ports(self):
        scan, _ = self.run_scan([
            "-p", "22,80,443",
            "--exclude-ports", "80"
        ])

        self.assertEqual(
            scan.call_args.kwargs["ports"],
            [22, 443]
        )

    def test_exclude_port_range(self):
        scan, _ = self.run_scan([
            "-p", "8000-8005",
            "--exclude-ports", "8002-8004"
        ])

        self.assertEqual(
            scan.call_args.kwargs["ports"],
            [8000, 8001, 8005]
        )

    def test_udp_exclusion(self):
        scan, _ = self.run_scan([
            "-p", "53,123,161",
            "--exclude-ports", "123"
        ], udp=True)

        self.assertEqual(
            scan.call_args.kwargs["ports"],
            [53, 161]
        )

    def test_exclude_nonexistent_port(self):
        scan, _ = self.run_scan([
            "-p", "80,443",
            "--exclude-ports", "22"
        ])

        self.assertEqual(
            scan.call_args.kwargs["ports"],
            [80, 443]
        )

    def test_exclude_all_ports(self):
        scan, output = self.run_scan([
            "-p", "80-82",
            "--exclude-ports", "80-82"
        ])

        scan.assert_not_called()
        self.assertIn(
            "No ports remain after exclusions",
            output
        )

    def test_invalid_exclusion(self):
        scan, output = self.run_scan([
            "-p", "80,443",
            "--exclude-ports", "99999"
        ])

        scan.assert_not_called()
        self.assertIn(
            "Invalid excluded ports",
            output
        )

    def test_exclusion_progress_count(self):
        scan, _ = self.run_scan([
            "-p", "80-85",
            "--exclude-ports", "82,84"
        ])

        progress = scan.call_args.kwargs["progress"]

        self.assertEqual(
            progress.snapshot()["total"],
            4
        )

    def test_no_exclusion_preserves_range(self):
        scan, _ = self.run_scan([
            "-p", "80-85"
        ])

        self.assertIsNone(
            scan.call_args.kwargs["ports"]
        )

        self.assertEqual(
            scan.call_args.kwargs["start_port"],
            80
        )

        self.assertEqual(
            scan.call_args.kwargs["end_port"],
            85
        )

    def test_top_ports_exclusion(self):
        with patch(
            "netrecon.get_top_ports",
            return_value=[22, 80, 443]
        ):
            scan, _ = self.run_scan([
                "--top-ports", "10",
                "--exclude-ports", "80"
            ])

        self.assertEqual(
            scan.call_args.kwargs["ports"],
            [22, 443]
        )


if __name__ == "__main__":
    unittest.main()
