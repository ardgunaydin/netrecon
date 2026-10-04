import unittest

from scanner.service_detector import detect_service


class TestServiceDetector(unittest.TestCase):

    def test_http(self):
        self.assertEqual(
            detect_service(80),
            "HTTP"
        )

    def test_https(self):
        self.assertEqual(
            detect_service(443),
            "HTTPS"
        )

    def test_ssh(self):
        self.assertEqual(
            detect_service(22),
            "SSH"
        )

    def test_smb(self):
        self.assertEqual(
            detect_service(445),
            "SMB"
        )

    def test_rdp(self):
        self.assertEqual(
            detect_service(3389),
            "RDP"
        )

    def test_mysql(self):
        self.assertEqual(
            detect_service(3306),
            "MYSQL"
        )


if __name__ == "__main__":
    unittest.main()