
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from utils.progress import ScanProgress


class TestScanProgress(unittest.TestCase):

    def test_initial_state(self):
        with patch("utils.progress.time.monotonic", return_value=10):
            tracker = ScanProgress(4)
            result = tracker.snapshot()

        self.assertEqual(result["completed"], 0)
        self.assertEqual(result["percent"], 0.0)
        self.assertIsNone(result["eta_seconds"])

    def test_rate_and_eta(self):
        with patch(
            "utils.progress.time.monotonic",
            side_effect=[10, 12]
        ):
            tracker = ScanProgress(10)
            tracker.advance(4)
            result = tracker.snapshot()

        self.assertEqual(result["percent"], 40.0)
        self.assertEqual(result["rate_per_second"], 2.0)
        self.assertEqual(result["eta_seconds"], 3.0)

    def test_completed_scan(self):
        tracker = ScanProgress(2)
        tracker.advance(2)

        result = tracker.snapshot()

        self.assertEqual(result["percent"], 100.0)
        self.assertEqual(result["eta_seconds"], 0.0)

    def test_empty_scan(self):
        result = ScanProgress(0).snapshot()
        self.assertEqual(result["percent"], 100.0)

    def test_invalid_inputs(self):
        for total in (-1, 1.5, True):
            with self.assertRaises(ValueError):
                ScanProgress(total)

        tracker = ScanProgress(1)

        for count in (0, -1, True, 1.5):
            with self.assertRaises(ValueError):
                tracker.advance(count)

        tracker.advance()

        with self.assertRaises(ValueError):
            tracker.advance()

    def test_thread_safe_updates(self):
        tracker = ScanProgress(100)

        with ThreadPoolExecutor(max_workers=8) as executor:
            list(
                executor.map(
                    lambda _: tracker.advance(),
                    range(100)
                )
            )

        self.assertEqual(
            tracker.snapshot()["completed"],
            100
        )


if __name__ == "__main__":
    unittest.main()
