
"""End-to-end CLI integration tests for HTML reporting."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import netrecon

from utils.html_report import render_html_report


class TestHTMLCLIIntegration(unittest.TestCase):

    def test_tcp_html_export(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "scan.html"

            args = [
                "netrecon.py",
                "-t", "127.0.0.1/32",
                "-p", "22-22",
                "--skip-discovery",
                "--html", str(report)
            ]

            with (
                patch("sys.argv", args),
                patch(
                    "netrecon.scan_ports",
                    return_value=[22]
                ),
                patch(
                    "netrecon.detect_service_version",
                    return_value={
                        "service": "SSH",
                        "banner": "SSH-2.0-OpenSSH_9.6",
                        "fingerprint": {
                            "protocol": "SSH",
                            "software": "OpenSSH_9.6"
                        }
                    }
                ),
                redirect_stdout(io.StringIO())
            ):
                netrecon.main()

            self.assertTrue(report.exists())

            content = report.read_text(encoding="utf-8")
            self.assertIn("22/tcp", content)
            self.assertIn("OpenSSH_9.6", content)
            self.assertIn("NETRECON", content)

    def test_udp_html_export(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "udp.html"

            args = [
                "netrecon.py",
                "-t", "127.0.0.1/32",
                "--udp",
                "-p", "123-123",
                "--skip-discovery",
                "--html", str(report)
            ]

            with (
                patch("sys.argv", args),
                patch(
                    "netrecon.scan_udp_ports",
                    return_value=[
                        {
                            "port": 123,
                            "protocol": "udp",
                            "state": "open|filtered"
                        }
                    ]
                ),
                redirect_stdout(io.StringIO())
            ):
                netrecon.main()

            content = report.read_text(encoding="utf-8")

            self.assertIn("123/udp", content)
            self.assertIn("OPEN|FILTERED", content)

    def test_hostile_banner_is_escaped(self):
        results = {
            "127.0.0.1": {
                "hostname": "<script>alert(1)</script>",
                "ports": [
                    {
                        "port": 8080,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "HTTP",
                        "banner": '<img src=x onerror=alert(1)>',
                        "fingerprint": {
                            "software": "<script>bad</script>"
                        }
                    }
                ]
            }
        }

        content = render_html_report(
            "127.0.0.1",
            results
        )

        self.assertNotIn("<script>alert(1)</script>", content)
        self.assertNotIn("<img src=x", content)
        self.assertNotIn("<script>bad</script>", content)

        self.assertIn("&lt;script&gt;", content)
        self.assertIn("&lt;img", content)

    def test_simultaneous_exports(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)

            html_path = folder / "scan.html"
            json_path = folder / "scan.json"
            csv_path = folder / "scan.csv"

            args = [
                "netrecon.py",
                "-t", "127.0.0.1/32",
                "-p", "22-22",
                "--skip-discovery",
                "-o", str(json_path),
                "--csv", str(csv_path),
                "--html", str(html_path)
            ]

            with (
                patch("sys.argv", args),
                patch(
                    "netrecon.scan_ports",
                    return_value=[22]
                ),
                patch(
                    "netrecon.detect_service_version",
                    return_value={
                        "service": "SSH",
                        "banner": "SSH-2.0-TestServer",
                        "fingerprint": None
                    }
                ),
                redirect_stdout(io.StringIO())
            ):
                netrecon.main()

            self.assertTrue(html_path.exists())
            self.assertTrue(json_path.exists())
            self.assertTrue(csv_path.exists())

            data = json.loads(
                json_path.read_text(encoding="utf-8")
            )

            self.assertEqual(
                data["hosts"][0]["ports"][0]["port"],
                22
            )


if __name__ == "__main__":
    unittest.main()
