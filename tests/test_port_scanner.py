import socket
import unittest

from scanner.port_scanner import scan_port


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


if __name__ == "__main__":
    unittest.main()