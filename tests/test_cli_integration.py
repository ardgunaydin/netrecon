
# C:\Users\USER\netrecon\tests\test_cli_integration.py

import csv
import io
import json
import os
import tempfile
import unittest

from contextlib import redirect_stdout
from unittest.mock import patch

import netrecon


class TestCLIIntegration(unittest.TestCase):

    def test_udp_cli_and_exports(self):
        """Verify UDP mode, terminal output, JSON and CSV."""

        with tempfile.TemporaryDirectory() as temp_dir:
            json_path = os.path.join(temp_dir, "udp.json")
            csv_path = os.path.join(temp_dir, "udp.csv")

            args = [
                "netrecon.py",
                "-t", "127.0.0.1/32",
                "--udp",
                "-p", "123-123",
                "--skip-discovery",
                "-o", json_path,
                "--csv", csv_path
            ]

            mock_results = [
                {
                    "port": 123,
                    "protocol": "udp",
                    "state": "open|filtered"
                }
            ]

            output = io.StringIO()

            with (
                patch("sys.argv", args),
                patch(
                    "netrecon.scan_udp_ports",
                    return_value=mock_results
                ) as udp_scan,
                patch("netrecon.scan_ports") as tcp_scan,
                redirect_stdout(output)
            ):
                netrecon.main()

            udp_scan.assert_called_once()
            tcp_scan.assert_not_called()

            self.assertIn("123/udp", output.getvalue())
            self.assertIn(
                "OPEN|FILTERED",
                output.getvalue()
            )

            with open(json_path, encoding="utf-8") as file:
                data = json.load(file)

            host = data["hosts"][0]

            self.assertEqual(
                host["ports"][0]["protocol"],
                "udp"
            )
            self.assertEqual(
                host["ports"][0]["state"],
                "open|filtered"
            )
            self.assertEqual(host["open_ports"], [])

            with open(
                csv_path,
                encoding="utf-8",
                newline=""
            ) as file:
                rows = list(csv.DictReader(file))

            self.assertEqual(rows[0]["protocol"], "udp")
            self.assertEqual(
                rows[0]["state"],
                "open|filtered"
            )

    def test_tcp_is_default(self):
        """Verify TCP remains the default scanning protocol."""

        args = [
            "netrecon.py",
            "-t", "127.0.0.1/32",
            "-p", "8080-8080",
            "--skip-discovery"
        ]

        output = io.StringIO()

        with (
            patch("sys.argv", args),
            patch(
                "netrecon.scan_ports",
                return_value=[8080]
            ) as tcp_scan,
            patch("netrecon.scan_udp_ports") as udp_scan,
            patch(
                "netrecon.detect_service_version",
                return_value={
                    "service": "HTTP-ALT",
                    "banner": "Test Server"
                }
            ),
            redirect_stdout(output)
        ):
            netrecon.main()

        tcp_scan.assert_called_once()
        udp_scan.assert_not_called()

        self.assertIn("8080/tcp", output.getvalue())
        self.assertIn("OPEN", output.getvalue())

    def test_udp_top_ports_selection(self):
        """Verify UDP mode uses the UDP-specific port preset."""

        args = [
            "netrecon.py",
            "-t", "127.0.0.1/32",
            "--udp",
            "--top-ports", "10",
            "--skip-discovery"
        ]

        with (
            patch("sys.argv", args),
            patch(
                "netrecon.scan_udp_ports",
                return_value=[]
            ) as udp_scan,
            redirect_stdout(io.StringIO())
        ):
            netrecon.main()

        udp_scan.assert_called_once()

        selected_ports = udp_scan.call_args.kwargs["ports"]

        self.assertEqual(len(selected_ports), 10)
        self.assertIn(53, selected_ports)
        self.assertIn(123, selected_ports)
        self.assertIn(161, selected_ports)


if __name__ == "__main__":
    unittest.main()
