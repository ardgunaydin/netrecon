# tests/test_udp_scanner.py

import socket
import threading
import unittest
from unittest.mock import patch

from scanner.udp_scanner import (
    scan_udp_port,
    scan_udp_ports
)


class TestUDPScanner(unittest.TestCase):

    def test_open_udp_port(self):
        # Create a local UDP service that sends a reply.
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        ) as server:

            server.bind(("127.0.0.1", 0))
            server.settimeout(2)

            port = server.getsockname()[1]

            def respond():
                try:
                    data, address = server.recvfrom(1024)
                    server.sendto(b"OK", address)
                except OSError:
                    pass

            worker = threading.Thread(
                target=respond,
                daemon=True
            )
            worker.start()

            result = scan_udp_port(
                "127.0.0.1",
                port,
                timeout=1
            )

            worker.join(timeout=2)

            self.assertEqual(result, "open")

    def test_no_response(self):
        # A listening UDP socket does not send a reply.
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        ) as server:

            server.bind(("127.0.0.1", 0))
            port = server.getsockname()[1]

            result = scan_udp_port(
                "127.0.0.1",
                port,
                timeout=0.2
            )

            self.assertEqual(
                result,
                "open|filtered"
            )

    def test_invalid_port(self):
        with self.assertRaises(ValueError):
            scan_udp_port("127.0.0.1", 70000)

    def test_invalid_threads(self):
        with self.assertRaises(ValueError):
            scan_udp_ports(
                "127.0.0.1",
                ports=[53],
                threads=0
            )

    def test_multiple_ports(self):
        # Mock the port scanner for predictable results.
        def fake_scan(ip, port, timeout):
            if port == 123:
                return "open"

            return "closed"

        with patch(
            "scanner.udp_scanner.scan_udp_port",
            side_effect=fake_scan
        ):
            results = scan_udp_ports(
                "127.0.0.1",
                ports=[161, 123, 53],
                threads=3
            )

        self.assertEqual(
            [item["port"] for item in results],
            [53, 123, 161]
        )

        self.assertEqual(
            results[1]["state"],
            "open"
        )


if __name__ == "__main__":
    unittest.main()