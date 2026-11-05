
import tempfile
import unittest
from pathlib import Path

from utils.html_report import (
    render_html_report,
    save_html_report
)


class TestHTMLReport(unittest.TestCase):

    def setUp(self):
        self.results = {
            "127.0.0.1": {
                "hostname": "localhost",
                "ports": [
                    {
                        "port": 22,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "SSH",
                        "banner": "SSH-2.0-OpenSSH_9.6",
                        "fingerprint": {
                            "protocol": "SSH",
                            "software": "OpenSSH_9.6"
                        }
                    },
                    {
                        "port": 123,
                        "protocol": "udp",
                        "state": "open|filtered",
                        "service": "NTP",
                        "banner": None
                    }
                ]
            }
        }

    def test_report_contains_host_and_ports(self):
        result = render_html_report(
            "127.0.0.1/32",
            self.results,
            1.5
        )

        self.assertIn("127.0.0.1", result)
        self.assertIn("22/tcp", result)
        self.assertIn("123/udp", result)
        self.assertIn("Open / filtered", result)
        self.assertIn("OpenSSH_9.6", result)

    def test_html_escaping(self):
        self.results["127.0.0.1"]["ports"][0]["banner"] = (
            "<script>alert('test')</script>"
        )

        result = render_html_report(
            "127.0.0.1",
            self.results
        )

        self.assertNotIn("<script>", result)
        self.assertIn("&lt;script&gt;", result)

    def test_empty_results(self):
        result = render_html_report(
            "127.0.0.1",
            {}
        )

        self.assertIn("No hosts were scanned", result)

    def test_no_ports(self):
        result = render_html_report(
            "127.0.0.1",
            {
                "127.0.0.1": {
                    "hostname": None,
                    "ports": []
                }
            }
        )

        self.assertIn("No reported ports", result)

    def test_save_html_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "reports" / "scan.html"

            save_html_report(
                path,
                "127.0.0.1",
                self.results,
                2.0
            )

            self.assertTrue(path.exists())

            content = path.read_text(encoding="utf-8")
            self.assertIn("<!DOCTYPE html>", content)
            self.assertIn("SSH", content)


if __name__ == "__main__":
    unittest.main()
