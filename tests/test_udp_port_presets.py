
# tests/test_udp_port_presets.py

import unittest

from scanner.port_presets import get_top_udp_ports


class TestUDPPortPresets(unittest.TestCase):

    def test_top_10_udp_ports(self):
        ports = get_top_udp_ports(10)

        self.assertEqual(len(ports), 10)
        self.assertIn(53, ports)
        self.assertIn(123, ports)
        self.assertIn(161, ports)

    def test_top_20_udp_ports(self):
        ports = get_top_udp_ports(20)

        self.assertEqual(len(ports), 20)
        self.assertEqual(len(set(ports)), 20)

    def test_top_50_udp_ports(self):
        ports = get_top_udp_ports(50)

        self.assertEqual(len(ports), 50)
        self.assertEqual(len(set(ports)), 50)

    def test_invalid_udp_preset(self):
        with self.assertRaises(ValueError):
            get_top_udp_ports(15)


if __name__ == "__main__":
    unittest.main()
