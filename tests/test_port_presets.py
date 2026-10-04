import unittest

from scanner.port_presets import (
    get_top_ports
)


class TestPortPresets(unittest.TestCase):

    def test_top_10_ports(self):
        ports = get_top_ports(10)

        self.assertEqual(
            len(ports),
            10
        )

        self.assertIn(
            22,
            ports
        )

        self.assertIn(
            80,
            ports
        )

        self.assertIn(
            443,
            ports
        )

    def test_top_20_ports(self):
        ports = get_top_ports(20)

        self.assertEqual(
            len(ports),
            20
        )

        self.assertEqual(
            len(set(ports)),
            20
        )

    def test_top_50_ports(self):
        ports = get_top_ports(50)

        self.assertEqual(
            len(ports),
            50
        )

        self.assertEqual(
            len(set(ports)),
            50
        )


if __name__ == "__main__":
    unittest.main()