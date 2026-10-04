import unittest
import ipaddress

from netrecon import (
    validate_network,
    parse_port_range
)


class TestNetReconValidation(unittest.TestCase):

    def test_valid_network(self):
        network = validate_network(
            "192.168.1.0/24"
        )

        self.assertIsInstance(
            network,
            ipaddress.IPv4Network
        )

        self.assertEqual(
            str(network),
            "192.168.1.0/24"
        )

    def test_single_ip(self):
        network = validate_network(
            "127.0.0.1/32"
        )

        self.assertEqual(
            str(network),
            "127.0.0.1/32"
        )

    def test_invalid_network(self):
        network = validate_network(
            "999.999.999.999"
        )

        self.assertIsNone(
            network
        )

    def test_valid_port_range(self):
        result = parse_port_range(
            "1-1000"
        )

        self.assertEqual(
            result,
            (1, 1000)
        )

    def test_invalid_port_range(self):
        result = parse_port_range(
            "1000-1"
        )

        self.assertIsNone(
            result
        )

    def test_port_above_limit(self):
        result = parse_port_range(
            "1-70000"
        )

        self.assertIsNone(
            result
        )

    def test_port_zero(self):
        result = parse_port_range(
            "0-100"
        )

        self.assertIsNone(
            result
        )


if __name__ == "__main__":
    unittest.main()