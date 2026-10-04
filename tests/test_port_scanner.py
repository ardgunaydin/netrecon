import socket
import unittest

from scanner.port_scanner import (
    scan_port,
    scan_ports
)


class TestPortScanner(unittest.TestCase):

    def test_detect_open_port(self):
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as server:

            server.bind(
                ("127.0.0.1", 0)
            )

            server.listen(1)

            port = server.getsockname()[1]

            result = scan_port(
                "127.0.0.1",
                port,
                timeout=1
            )

            self.assertEqual(
                result,
                port
            )

    def test_scan_ports_detects_open_port(self):
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as server:

            server.bind(
                ("127.0.0.1", 0)
            )

            server.listen(1)

            port = server.getsockname()[1]

            results = scan_ports(
                "127.0.0.1",
                start_port=port,
                end_port=port,
                threads=1,
                timeout=1
            )

            self.assertIn(
                port,
                results
            )

    def test_closed_port_returns_none(self):
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as temp_socket:

            temp_socket.bind(
                ("127.0.0.1", 0)
            )

            port = temp_socket.getsockname()[1]

        result = scan_port(
            "127.0.0.1",
            port,
            timeout=0.2
        )

        self.assertIsNone(
            result
        )


if __name__ == "__main__":
    unittest.main()