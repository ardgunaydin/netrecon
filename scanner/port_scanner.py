import socket
from concurrent.futures import (
    ThreadPoolExecutor,
    as_completed
)


def scan_port(
    ip,
    port,
    timeout=0.5
):
    try:
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as sock:

            sock.settimeout(
                timeout
            )

            result = sock.connect_ex(
                (
                    str(ip),
                    port
                )
            )

            if result == 0:
                return port

    except (
        socket.timeout,
        socket.error,
        OSError
    ):
        pass

    return None


def scan_ports(
    ip,
    start_port=None,
    end_port=None,
    ports=None,
    threads=100,
    timeout=0.5
):
    open_ports = []

    if ports is not None:
        target_ports = sorted(
            set(ports)
        )

        print(
            f"\n[*] Scanning {ip} "
            f"on {len(target_ports)} selected ports..."
        )

    else:
        if (
            start_port is None
            or end_port is None
        ):
            raise ValueError(
                "start_port and end_port "
                "are required when ports is not provided."
            )

        target_ports = list(
            range(
                start_port,
                end_port + 1
            )
        )

        print(
            f"\n[*] Scanning {ip} "
            f"ports {start_port}-{end_port}..."
        )

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

        for future in as_completed(
            futures
        ):
            port = futures[
                future
            ]

            try:
                result = future.result()

                if result is not None:
                    open_ports.append(
                        result
                    )

                    print(
                        f"[+] "
                        f"{ip}:{result} "
                        f"OPEN"
                    )

            except Exception as error:
                print(
                    f"[!] Error scanning "
                    f"{ip}:{port}: "
                    f"{error}"
                )

    return sorted(
        open_ports
    )