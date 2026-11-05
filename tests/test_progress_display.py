
import io
import unittest
from contextlib import redirect_stdout

from utils.progress_display import ProgressReporter


class TestProgressDisplay(unittest.TestCase):

    def setUp(self):
        self.reporter = ProgressReporter(interval=0.5)

    def make_snapshot(
        self,
        completed,
        total,
        elapsed,
        percent,
        rate,
        eta
    ):
        return {
            "completed": completed,
            "total": total,
            "elapsed_seconds": elapsed,
            "percent": percent,
            "rate_per_second": rate,
            "eta_seconds": eta
        }

    def test_eta_format(self):
        self.assertEqual(
            self.reporter.format_eta(3.5),
            "3.5s"
        )
        self.assertEqual(
            self.reporter.format_eta(125),
            "2m 5s"
        )
        self.assertEqual(
            self.reporter.format_eta(None),
            "calculating"
        )

    def test_progress_output(self):
        snapshot = self.make_snapshot(
            50, 100, 2.0, 50.0, 25.0, 2.0
        )

        output = io.StringIO()

        with redirect_stdout(output):
            self.reporter(snapshot)

        self.assertIn("50.0%", output.getvalue())
        self.assertIn("50/100", output.getvalue())
        self.assertIn("25.0 ports/s", output.getvalue())

    def test_throttling(self):
        output = io.StringIO()

        with redirect_stdout(output):
            self.reporter(
                self.make_snapshot(
                    10, 100, 1.0, 10.0, 10.0, 9.0
                )
            )
            self.reporter(
                self.make_snapshot(
                    20, 100, 1.1, 20.0, 18.0, 4.4
                )
            )

        self.assertEqual(
            output.getvalue().count("[PROGRESS]"),
            1
        )

    def test_final_progress_always_printed(self):
        output = io.StringIO()

        with redirect_stdout(output):
            self.reporter(
                self.make_snapshot(
                    10, 100, 1.0, 10.0, 10.0, 9.0
                )
            )
            self.reporter(
                self.make_snapshot(
                    100, 100, 1.1, 100.0, 90.9, 0.0
                )
            )

        self.assertEqual(
            output.getvalue().count("[PROGRESS]"),
            2
        )
        self.assertIn("100.0%", output.getvalue())

    def test_invalid_interval(self):
        with self.assertRaises(ValueError):
            ProgressReporter(interval=0)


if __name__ == "__main__":
    unittest.main()
