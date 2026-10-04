import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


def scan_port(ip, port, timeout=0.5):
    """
    Scan a single TCP port.

    Returns:
        port number if open
        None if closed/unreachable
    """

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)

            result = sock.connect_ex((str(ip), port))

            if result == 0:
                return port

    except (socket.timeout, socket.error):
        pass

    return None


def scan_ports(ip, start_port=1, end_port=1024, threads=100):
    """
    Scan a TCP port range on a single host.
    """

    open_ports = []

    print(f"\n[*] Scanning {ip} ports {start_port}-{end_port}...")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, ip, port): port
            for port in range(start_port, end_port + 1)
        }

        for future in as_completed(futures):
            try:
                result = future.result()

                if result is not None:
                    open_ports.append(result)
                    print(f"[+] {ip}:{result} OPEN")

            except Exception as error:
                port = futures[future]
                print(f"[!] Error scanning {ip}:{port}: {error}")

    return sorted(open_ports)