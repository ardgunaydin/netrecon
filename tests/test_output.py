import csv
import json
import os
import tempfile
import unittest

from utils.output import (
    save_json_results,
    save_csv_results
)


class TestOutput(unittest.TestCase):

    def setUp(self):
        self.scan_results = {
            "127.0.0.1": {
                "hostname": "localhost",
                "ports": [
                    {
                        "port": 8080,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "HTTP-ALT",
                        "banner": "Test Server"
                    }
                ]
            }
        }

    def test_json_output(self):
        with tempfile.TemporaryDirectory() as temp_dir:

            filename = os.path.join(
                temp_dir,
                "scan.json"
            )

            save_json_results(
                filename=filename,
                target="127.0.0.1/32",
                start_port=1,
                end_port=1000,
                threads=50,
                scan_results=self.scan_results,
                duration=1.25
            )

            self.assertTrue(
                os.path.exists(filename)
            )

            with open(
                filename,
                "r",
                encoding="utf-8"
            ) as file:

                data = json.load(file)

            self.assertEqual(
                data["hosts"][0]["ip"],
                "127.0.0.1"
            )

            self.assertEqual(
                data["hosts"][0][
                    "open_ports"
                ][0]["port"],
                8080
            )

    def test_csv_output(self):
        with tempfile.TemporaryDirectory() as temp_dir:

            filename = os.path.join(
                temp_dir,
                "scan.csv"
            )

            save_csv_results(
                filename=filename,
                scan_results=self.scan_results
            )

            self.assertTrue(
                os.path.exists(filename)
            )

            with open(
                filename,
                "r",
                encoding="utf-8"
            ) as file:

                rows = list(
                    csv.DictReader(file)
                )

            self.assertEqual(
                rows[0]["ip"],
                "127.0.0.1"
            )

            self.assertEqual(
                rows[0]["port"],
                "8080"
            )

            self.assertEqual(
                rows[0]["service"],
                "HTTP-ALT"
            )


if __name__ == "__main__":
    unittest.main()