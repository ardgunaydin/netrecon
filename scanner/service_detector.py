import socket
import ssl


COMMON_SERVICES = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MSRPC",
    139: "NETBIOS",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRESQL",
    5900: "VNC",
    6379: "REDIS",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
}


def detect_service(port):
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]

    try:
        return socket.getservbyport(port, "tcp").upper()

    except OSError:
        return "UNKNOWN"


def grab_http_banner(ip, port, timeout=2):
    try:
        with socket.create_connection(
            (ip, port),
            timeout=timeout
        ) as sock:

            request = (
                f"HEAD / HTTP/1.1\r\n"
                f"Host: {ip}\r\n"
                f"Connection: close\r\n\r\n"
            )

            sock.sendall(
                request.encode()
            )

            response = sock.recv(
                4096
            ).decode(
                errors="ignore"
            )

            for line in response.splitlines():
                if line.lower().startswith("server:"):
                    return line.split(
                        ":",
                        1
                    )[1].strip()

            first_line = response.splitlines()

            if first_line:
                return first_line[0].strip()

    except (
        socket.timeout,
        ConnectionRefusedError,
        OSError
    ):
        pass

    return None


def grab_https_banner(ip, port, timeout=2):
    try:
        context = ssl.create_default_context()

        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection(
            (ip, port),
            timeout=timeout
        ) as raw_socket:

            with context.wrap_socket(
                raw_socket,
                server_hostname=ip
            ) as secure_socket:

                request = (
                    f"HEAD / HTTP/1.1\r\n"
                    f"Host: {ip}\r\n"
                    f"Connection: close\r\n\r\n"
                )

                secure_socket.sendall(
                    request.encode()
                )

                response = secure_socket.recv(
                    4096
                ).decode(
                    errors="ignore"
                )

                for line in response.splitlines():
                    if line.lower().startswith("server:"):
                        return line.split(
                            ":",
                            1
                        )[1].strip()

                first_line = response.splitlines()

                if first_line:
                    return first_line[0].strip()

    except (
        socket.timeout,
        ssl.SSLError,
        ConnectionRefusedError,
        OSError
    ):
        pass

    return None


def grab_generic_banner(ip, port, timeout=2):
    try:
        with socket.create_connection(
            (ip, port),
            timeout=timeout
        ) as sock:

            sock.settimeout(timeout)

            try:
                banner = sock.recv(
                    1024
                )

                if banner:
                    return banner.decode(
                        errors="ignore"
                    ).strip()

            except socket.timeout:
                pass

    except (
        socket.timeout,
        ConnectionRefusedError,
        OSError
    ):
        pass

    return None


def detect_service_version(ip, port):
    service = detect_service(port)

    banner = None

    if port in (80, 8080):
        banner = grab_http_banner(
            ip,
            port
        )

    elif port in (443, 8443):
        banner = grab_https_banner(
            ip,
            port
        )

    else:
        banner = grab_generic_banner(
            ip,
            port
        )

    return {
        "service": service,
        "banner": banner
    }