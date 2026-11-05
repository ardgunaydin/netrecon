
"""Tests for configurable TCP banner timeouts."""

import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import netrecon


class TestBannerTimeout(unittest.TestCase):

    def run_cli(self, extra_args):
        args = [
            "netrecon.py",
            "-t", "127.0.0.1/32",
            "-p", "22-22",
            "--skip-discovery",
            *extra_args
        ]

        output = io.StringIO()

        with (
            patch("sys.argv", args),
            patch(
                "netrecon.scan_ports",
                return_value=[22]
            ) as scan_mock,
            patch(
                "netrecon.detect_service_version",
                return_value={
                    "service": "SSH",
                    "banner": "SSH-2.0-OpenSSH_9.6",
                    "fingerprint": None
                }
            ) as detect_mock,
            redirect_stdout(output)
        ):
            netrecon.main()

        return output.getvalue(), scan_mock, detect_mock

    def test_custom_banner_timeout(self):
        output, scan_mock, detect_mock = self.run_cli([
            "--timeout", "0.5",
            "--banner-timeout", "4"
        ])

        self.assertIn("Banner timeout", output)

        self.assertEqual(
            scan_mock.call_args.kwargs["timeout"],
            0.5
        )

        detect_mock.assert_called_once_with(
            "127.0.0.1",
            22,
            timeout=4.0
        )

    def test_default_banner_timeout(self):
        _, _, detect_mock = self.run_cli([])

        detect_mock.assert_called_once_with(
            "127.0.0.1",
            22,
            timeout=2.0
        )

    def test_invalid_banner_timeout(self):
        for value in ("0", "-1", "61"):
            with self.subTest(value=value):
                output, scan_mock, detect_mock = self.run_cli([
                    "--banner-timeout", value
                ])

                self.assertIn(
                    "Banner timeout must be",
                    output
                )

                scan_mock.assert_not_called()
                detect_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
