# scanner/udp_scanner.py

import errno
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


def scan_udp_port(ip, port, timeout=0.5):
    """
    Scan a single UDP port.

    Possible states:
    - open: A UDP response was received.
    - closed: Connection refused (ICMP port unreachable).
    - open|filtered: No response received.
    - error: Other network/socket errors.
    """

    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")

    if timeout <= 0:
        raise ValueError("Timeout must be greater than 0.")

    try:
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        ) as sock:

            sock.settimeout(timeout)

            sock.connect((str(ip), port))

            # Generic UDP probe
            sock.send(b"\x00")

            # Wait for a UDP response
            sock.recv(4096)

            return "open"

    except socket.timeout:
        return "open|filtered"

    except OSError as error:
        error_code = getattr(error, "winerror", None)

        if error_code is None:
            error_code = error.errno

        if error_code in (
            errno.ECONNREFUSED,
            10054  # Windows: WSAECONNRESET
        ):
            return "closed"

        return "error"


def scan_udp_ports(
    ip,
    start_port=None,
    end_port=None,
    ports=None,
    threads=50,
    timeout=0.5
):
    """
    Scan multiple UDP ports concurrently.
    """

    if threads < 1:
        raise ValueError("Threads must be greater than 0.")

    if ports is not None:
        target_ports = sorted(set(ports))

    else:
        if start_port is None or end_port is None:
            raise ValueError(
                "A port range or port list is required."
            )

        if not 1 <= start_port <= end_port <= 65535:
            raise ValueError("Invalid UDP port range.")

        target_ports = list(
            range(start_port, end_port + 1)
        )

    results = []

    print(
        f"\n[*] Starting UDP scan on {ip} "
        f"({len(target_ports)} ports)..."
    )

    with ThreadPoolExecutor(
        max_workers=threads
    ) as executor:

        futures = {
            executor.submit(
                scan_udp_port,
                ip,
                port,
                timeout
            ): port
            for port in target_ports
        }

        for future in as_completed(futures):
            port = futures[future]

            state = future.result()

            results.append({
                "port": port,
                "protocol": "udp",
                "state": state
            })

            if state == "open":
                print(
                    f"[+] {ip}:{port}/udp OPEN"
                )

            elif state == "open|filtered":
                print(
                    f"[?] {ip}:{port}/udp OPEN|FILTERED"
                )

    return sorted(
        results,
        key=lambda result: result["port"]
    )