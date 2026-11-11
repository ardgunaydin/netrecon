
"""UDP scanning with retries, validation and progress tracking."""

import errno
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.udp_probes import (
    build_udp_probe,
    is_valid_udp_response,
    validate_dns_response,
    validate_ntp_response,
)

from utils.progress import ScanProgress


def _validate_retries(retries):
    if (
        not isinstance(retries, int)
        or isinstance(retries, bool)
        or not 0 <= retries <= 5
    ):
        raise ValueError(
            "UDP retries must be an integer between 0 and 5."
        )


def scan_udp_port(ip, port, timeout=0.5, retries=0):
    """
    Scan a UDP port with optional timeout retries.

    retries=0 means one attempt.
    retries=2 means up to three attempts.

    Only socket timeouts trigger another attempt.
    """

    if not isinstance(port, int) or isinstance(port, bool):
        raise ValueError("Port must be an integer.")

    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")

    if timeout <= 0:
        raise ValueError("Timeout must be greater than 0.")

    _validate_retries(retries)

    for attempt in range(retries + 1):
        try:
            with socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM
            ) as sock:

                sock.settimeout(timeout)
                sock.connect((str(ip), port))

                # A fresh protocol-aware probe for each attempt.
                probe = build_udp_probe(port)
                sock.send(probe)

                response = sock.recv(4096)

                if port == 53:
                    valid = validate_dns_response(
                        response,
                        probe
                    )

                elif port == 123:
                    valid = validate_ntp_response(
                        response,
                        probe
                    )

                else:
                    valid = is_valid_udp_response(
                        port,
                        response
                    )

                if valid:
                    return "open"

                # Invalid responses do not trigger retries.
                return "open|filtered"

        except socket.timeout:
            # The loop creates a fresh socket on retry.
            if attempt == retries:
                return "open|filtered"

        except OSError as error:
            error_code = getattr(
                error, "winerror", None
            )

            if error_code is None:
                error_code = error.errno

            if error_code in (
                errno.ECONNREFUSED,
                10054  # Windows WSAECONNRESET
            ):
                return "closed"

            return "error"

    return "open|filtered"


def scan_udp_ports(
    ip,
    start_port=None,
    end_port=None,
    ports=None,
    threads=50,
    timeout=0.5,
    progress=None,
    on_progress=None,
    retries=0
):
    """
    Concurrent UDP scanning with retries and progress tracking.

    Progress counts completed ports, not individual attempts.
    """

    if threads < 1:
        raise ValueError(
            "Threads must be greater than 0."
        )

    if timeout <= 0:
        raise ValueError(
            "Timeout must be greater than 0."
        )

    _validate_retries(retries)

    if ports is not None:
        target_ports = sorted(set(ports))

    else:
        if start_port is None or end_port is None:
            raise ValueError(
                "A port range or port list is required."
            )

        if not 1 <= start_port <= end_port <= 65535:
            raise ValueError(
                "Invalid UDP port range."
            )

        target_ports = list(
            range(start_port, end_port + 1)
        )

    if any(
        not isinstance(port, int)
        or isinstance(port, bool)
        or not 1 <= port <= 65535
        for port in target_ports
    ):
        raise ValueError(
            "Ports must be integers between 1 and 65535."
        )

    total_ports = len(target_ports)

    if progress is None:
        progress = ScanProgress(total_ports)

    elif progress.snapshot()["total"] != total_ports:
        raise ValueError(
            "Progress total does not match target ports."
        )

    if progress.snapshot()["completed"] != 0:
        raise ValueError(
            "Progress tracker must start at zero."
        )

    results = []

    print(
        f"\n[*] Starting UDP scan on {ip} "
        f"({total_ports} ports, {retries} retries)..."
    )

    with ThreadPoolExecutor(
        max_workers=threads
    ) as executor:

        # Preserve the original 3-argument call when retries
        # are disabled, keeping existing integrations compatible.
        if retries == 0:
            futures = {
                executor.submit(
                    scan_udp_port,
                    ip,
                    port,
                    timeout
                ): port
                for port in target_ports
            }

        else:
            futures = {
                executor.submit(
                    scan_udp_port,
                    ip,
                    port,
                    timeout,
                    retries=retries
                ): port
                for port in target_ports
            }

        for future in as_completed(futures):
            port = futures[future]

            try:
                state = future.result()

            except Exception as error:
                print(
                    f"[!] Error scanning "
                    f"{ip}:{port}/udp: {error}"
                )
                state = "error"

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

            elif state == "error":
                print(
                    f"[!] {ip}:{port}/udp ERROR"
                )

            progress.advance()

            if on_progress is not None:
                on_progress(progress.snapshot())

    return sorted(
        results,
        key=lambda result: result["port"]
    )
