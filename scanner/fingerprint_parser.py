
"""Service fingerprint parsing utilities for NetRecon."""

import re


def parse_ssh_banner(banner):
    """Extract the SSH protocol and server implementation."""
    if not banner:
        return None

    match = re.search(
        r"SSH-(\d+\.\d+)-([^\s\r\n]+)",
        banner,
        re.IGNORECASE
    )

    if not match:
        return None

    return {
        "protocol": "SSH",
        "protocol_version": match.group(1),
        "software": match.group(2),
    }


def parse_http_banner(banner):
    """Parse common HTTP Server header values."""
    if not banner:
        return None

    match = re.search(
        r"^(?:Server:\s*)?([A-Za-z][\w.-]*)(?:/([^\s()]+))?",
        banner.strip(),
        re.IGNORECASE
    )

    if not match:
        return None

    return {
        "protocol": "HTTP",
        "software": match.group(1),
        "version": match.group(2),
    }


def parse_mail_banner(banner):
    """Identify basic SMTP server greetings."""
    if not banner:
        return None

    match = re.match(
        r"^220[\s-]+(.+)",
        banner.strip(),
        re.IGNORECASE
    )

    if not match:
        return None

    return {
        "protocol": "SMTP",
        "details": match.group(1).strip(),
    }


def parse_ftp_banner(banner):
    """Identify basic FTP server greetings."""
    if not banner:
        return None

    match = re.match(
        r"^220[\s-]+(.+)",
        banner.strip(),
        re.IGNORECASE
    )

    if not match:
        return None

    return {
        "protocol": "FTP",
        "details": match.group(1).strip(),
    }


def parse_service_fingerprint(service, banner):
    """Dispatch banner parsing according to service type."""
    if not banner:
        return None

    service = service.upper()

    if service == "SSH":
        return parse_ssh_banner(banner)

    if service in ("HTTP", "HTTPS", "HTTP-ALT", "HTTPS-ALT"):
        return parse_http_banner(banner)

    if service == "SMTP":
        return parse_mail_banner(banner)

    if service == "FTP":
        return parse_ftp_banner(banner)

    return None
