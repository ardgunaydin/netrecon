
import unittest

from scanner.port_parser import parse_port_spec


class TestPortParser(unittest.TestCase):

    def test_single_port(self):
        self.assertEqual(parse_port_spec("80"), [80])

    def test_multiple_ports(self):
        self.assertEqual(
            parse_port_spec("22,80,443"),
            [22, 80, 443]
        )

    def test_port_range(self):
        self.assertEqual(
            parse_port_spec("8000-8003"),
            [8000, 8001, 8002, 8003]
        )

    def test_combined_specification(self):
        self.assertEqual(
            parse_port_spec("22,80,8000-8002"),
            [22, 80, 8000, 8001, 8002]
        )

    def test_duplicate_removal(self):
        self.assertEqual(
            parse_port_spec("80,80,443,80"),
            [80, 443]
        )

    def test_sorting(self):
        self.assertEqual(
            parse_port_spec("443,22,80"),
            [22, 80, 443]
        )

    def test_whitespace(self):
        self.assertEqual(
            parse_port_spec(" 22, 80 , 443 "),
            [22, 80, 443]
        )

    def test_boundary_ports(self):
        self.assertEqual(
            parse_port_spec("1,65535"),
            [1, 65535]
        )

    def test_invalid_ports(self):
        for value in (
            "", "0", "65536", "-1", "abc",
            "80,", "80,,443", "100-50",
            "1-65536", "1-2-3", "22.5"
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_port_spec(value)

    def test_full_range(self):
        ports = parse_port_spec("1-65535")

        self.assertEqual(len(ports), 65535)
        self.assertEqual(ports[0], 1)
        self.assertEqual(ports[-1], 65535)


if __name__ == "__main__":
    unittest.main()
