
import unittest
from unittest.mock import patch

from scanner.port_scanner import scan_ports
from scanner.udp_scanner import scan_udp_ports
from utils.progress import ScanProgress


class TestProgressIntegration(unittest.TestCase):

    def test_tcp_progress(self):
        progress = ScanProgress(3)

        with patch(
            "scanner.port_scanner.scan_port",
            side_effect=lambda ip, port, timeout: (
                port if port == 80 else None
            )
        ):
            results = scan_ports(
                "127.0.0.1",
                ports=[80, 81, 82],
                threads=2,
                progress=progress
            )

        self.assertEqual(results, [80])
        self.assertEqual(progress.snapshot()["completed"], 3)
        self.assertEqual(progress.snapshot()["percent"], 100.0)

    def test_udp_progress(self):
        progress = ScanProgress(3)

        with patch(
            "scanner.udp_scanner.scan_udp_port",
            side_effect=lambda ip, port, timeout: (
                "open" if port == 53 else "closed"
            )
        ):
            results = scan_udp_ports(
                "127.0.0.1",
                ports=[53, 54, 55],
                threads=2,
                progress=progress
            )

        self.assertEqual(len(results), 3)
        self.assertEqual(progress.snapshot()["completed"], 3)
        self.assertEqual(progress.snapshot()["percent"], 100.0)

    def test_tcp_progress_callback(self):
        progress = ScanProgress(2)
        snapshots = []

        with patch(
            "scanner.port_scanner.scan_port",
            return_value=None
        ):
            scan_ports(
                "127.0.0.1",
                ports=[80, 81],
                threads=1,
                progress=progress,
                on_progress=lambda snapshot: snapshots.append(
                    snapshot
                )
            )

        self.assertEqual(len(snapshots), 2)
        self.assertEqual(snapshots[-1]["completed"], 2)

    def test_udp_progress_callback(self):
        progress = ScanProgress(2)
        snapshots = []

        with patch(
            "scanner.udp_scanner.scan_udp_port",
            return_value="open|filtered"
        ):
            scan_udp_ports(
                "127.0.0.1",
                ports=[53, 123],
                threads=1,
                progress=progress,
                on_progress=lambda snapshot: snapshots.append(
                    snapshot
                )
            )

        self.assertEqual(len(snapshots), 2)
        self.assertEqual(snapshots[-1]["completed"], 2)

    def test_progress_total_mismatch(self):
        progress = ScanProgress(1)

        with self.assertRaises(ValueError):
            scan_ports(
                "127.0.0.1",
                ports=[80, 81],
                progress=progress
            )

        with self.assertRaises(ValueError):
            scan_udp_ports(
                "127.0.0.1",
                ports=[53, 123],
                progress=progress
            )


if __name__ == "__main__":
    unittest.main()
