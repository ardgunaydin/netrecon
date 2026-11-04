
import unittest

from scanner.fingerprint_parser import (
    parse_ssh_banner,
    parse_http_banner,
    parse_mail_banner,
    parse_ftp_banner,
    parse_service_fingerprint,
)


class TestFingerprintParser(unittest.TestCase):

    def test_ssh_banner(self):
        result = parse_ssh_banner("SSH-2.0-OpenSSH_9.6")
        self.assertEqual(result["protocol"], "SSH")
        self.assertEqual(result["protocol_version"], "2.0")
        self.assertEqual(result["software"], "OpenSSH_9.6")

    def test_invalid_ssh_banner(self):
        self.assertIsNone(parse_ssh_banner("Invalid banner"))

    def test_http_banner(self):
        result = parse_http_banner("nginx/1.24.0")
        self.assertEqual(result["software"], "nginx")
        self.assertEqual(result["version"], "1.24.0")

    def test_apache_banner(self):
        result = parse_http_banner("Apache/2.4.58")
        self.assertEqual(result["software"], "Apache")
        self.assertEqual(result["version"], "2.4.58")

    def test_smtp_banner(self):
        result = parse_mail_banner(
            "220 mail.example.com ESMTP Postfix"
        )
        self.assertEqual(result["protocol"], "SMTP")
        self.assertIn("Postfix", result["details"])

    def test_ftp_banner(self):
        result = parse_ftp_banner(
            "220 ProFTPD 1.3.8 Server"
        )
        self.assertEqual(result["protocol"], "FTP")
        self.assertIn("ProFTPD", result["details"])

    def test_unknown_service(self):
        result = parse_service_fingerprint(
            "UNKNOWN", "Test Banner"
        )
        self.assertIsNone(result)

    def test_empty_banner(self):
        self.assertIsNone(
            parse_service_fingerprint("SSH", None)
        )


if __name__ == "__main__":
    unittest.main()
