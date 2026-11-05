
"""TCP port scanning with optional progress tracking."""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.progress import ScanProgress


def scan_port(ip, port, timeout=0.5):
    """Attempt a TCP connection to a single port."""
    try:
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as sock:

            sock.settimeout(timeout)

            result = sock.connect_ex(
                (str(ip), port)
            )

            if result == 0:
                return port

    except (socket.timeout, OSError):
        pass

    return None


def scan_ports(
    ip,
    start_port=None,
    end_port=None,
    ports=None,
    threads=100,
    timeout=0.5,
    progress=None,
    on_progress=None
):
    """Scan TCP ports concurrently and track progress."""

    if threads < 1:
        raise ValueError(
            "Threads must be greater than 0."
        )

    if timeout <= 0:
        raise ValueError(
            "Timeout must be greater than 0."
        )

    if ports is not None:
        target_ports = sorted(set(ports))

        print(
            f"\n[*] Scanning {ip} "
            f"on {len(target_ports)} selected ports..."
        )

    else:
        if start_port is None or end_port is None:
            raise ValueError(
                "A port range or port list is required."
            )

        if not 1 <= start_port <= end_port <= 65535:
            raise ValueError(
                "Invalid TCP port range."
            )

        target_ports = list(
            range(start_port, end_port + 1)
        )

        print(
            f"\n[*] Scanning {ip} "
            f"ports {start_port}-{end_port}..."
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

    open_ports = []

    with ThreadPoolExecutor(
        max_workers=threads
    ) as executor:

        futures = {
            executor.submit(
                scan_port,
                ip,
                port,
                timeout
            ): port
            for port in target_ports
        }

        for future in as_completed(futures):
            port = futures[future]

            try:
                result = future.result()

                if result is not None:
                    open_ports.append(result)

                    print(
                        f"[+] {ip}:{result}/tcp OPEN"
                    )

            except Exception as error:
                print(
                    f"[!] Error scanning "
                    f"{ip}:{port}: {error}"
                )

            finally:
                progress.advance()

                if on_progress is not None:
                    on_progress(progress.snapshot())

    return sorted(open_ports)
