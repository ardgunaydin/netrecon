import argparse
import ipaddress
import socket
import time

from scanner.host_scanner import discover_hosts
from scanner.port_scanner import scan_ports
from scanner.service_detector import detect_service_version

from utils.logger import setup_logger
from utils.output import (
    save_json_results,
    save_csv_results
)


VERSION = "0.7.0"


def validate_network(network):
    try:
        return ipaddress.ip_network(
            network,
            strict=False
        )

    except ValueError:
        print(f"[!] Invalid network: {network}")
        return None


def parse_port_range(port_range):
    try:
        start_port, end_port = map(
            int,
            port_range.split("-")
        )

        if not (1 <= start_port <= 65535):
            raise ValueError

        if not (1 <= end_port <= 65535):
            raise ValueError

        if start_port > end_port:
            raise ValueError

        return start_port, end_port

    except ValueError:
        print(
            "[!] Invalid port range. "
            "Example: -p 1-1024"
        )
        return None


def resolve_hostname(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname

    except (
        socket.herror,
        socket.gaierror,
        OSError
    ):
        return None


def main():
    logger = setup_logger()

    parser = argparse.ArgumentParser(
        prog="NetRecon",
        description=(
            "NetRecon - Lightweight Network Scanner "
            "for host discovery, TCP port scanning, "
            "service detection and banner grabbing."
        ),
        epilog=(
            "Example: "
            "python netrecon.py "
            "-t 127.0.0.1/32 "
            "-p 1-1000 "
            "--resolve-hostnames"
        )
    )

    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help=(
            "Target IP or network "
            "(example: 192.168.1.0/24)"
        )
    )

    parser.add_argument(
        "-p",
        "--ports",
        default="1-1024",
        help=(
            "TCP port range "
            "(default: 1-1024)"
        )
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=50,
        help=(
            "Number of worker threads "
            "(default: 50)"
        )
    )

    parser.add_argument(
        "-o",
        "--output",
        help=(
            "Save scan results "
            "to a JSON file"
        )
    )

    parser.add_argument(
        "--csv",
        help=(
            "Save scan results "
            "to a CSV file"
        )
    )

    parser.add_argument(
        "--skip-discovery",
        action="store_true",
        help=(
            "Skip ping-based host discovery "
            "and scan target hosts directly"
        )
    )

    parser.add_argument(
        "--resolve-hostnames",
        action="store_true",
        help=(
            "Attempt reverse DNS "
            "hostname resolution"
        )
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"NetRecon {VERSION}"
    )

    args = parser.parse_args()

    # ==================================================
    # INPUT VALIDATION
    # ==================================================

    network = validate_network(
        args.target
    )

    if network is None:
        return

    port_range = parse_port_range(
        args.ports
    )

    if port_range is None:
        return

    if args.threads < 1:
        print(
            "[!] Threads must be greater than 0."
        )
        return

    start_port, end_port = port_range

    # ==================================================
    # START INFORMATION
    # ==================================================

    print()
    print("=" * 78)
    print("                              NETRECON")
    print("=" * 78)

    print(
        f"[+] Version           : "
        f"{VERSION}"
    )

    print(
        f"[+] Target            : "
        f"{network}"
    )

    print(
        f"[+] Ports             : "
        f"{start_port}-{end_port}"
    )

    print(
        f"[+] Threads           : "
        f"{args.threads}"
    )

    print(
        f"[+] Host discovery    : "
        f"{'OFF' if args.skip_discovery else 'ON'}"
    )

    print(
        f"[+] Hostname resolving: "
        f"{'ON' if args.resolve_hostnames else 'OFF'}"
    )

    print()

    logger.info(
        f"Scan started - "
        f"Version={VERSION}, "
        f"Target={network}, "
        f"Ports={start_port}-{end_port}, "
        f"Threads={args.threads}, "
        f"SkipDiscovery={args.skip_discovery}, "
        f"ResolveHostnames={args.resolve_hostnames}"
    )

    start_time = time.time()

    # ==================================================
    # HOST DISCOVERY
    # ==================================================

    if args.skip_discovery:
        print(
            "[*] Host discovery skipped."
        )

        live_hosts = [
            str(host)
            for host in network.hosts()
        ]

        if not live_hosts:
            live_hosts = [
                str(network.network_address)
            ]

    else:
        live_hosts = discover_hosts(
            network,
            threads=args.threads
        )

    scan_results = {}

    # ==================================================
    # PORT SCANNING
    # ==================================================

    for host in live_hosts:
        logger.info(
            f"Scanning host: {host}"
        )

        hostname = None

        if args.resolve_hostnames:
            hostname = resolve_hostname(
                host
            )

        open_ports = scan_ports(
            host,
            start_port=start_port,
            end_port=end_port,
            threads=args.threads
        )

        formatted_ports = []

        # ==============================================
        # SERVICE + BANNER DETECTION
        # ==============================================

        for port in open_ports:
            service_info = detect_service_version(
                host,
                port
            )

            port_info = {
                "port": port,
                "protocol": "tcp",
                "state": "open",
                "service": service_info["service"],
                "banner": service_info["banner"]
            }

            formatted_ports.append(
                port_info
            )

            logger.info(
                f"{host}:{port} "
                f"{service_info['service']} "
                f"OPEN "
                f"Banner={service_info['banner']}"
            )

        scan_results[host] = {
            "hostname": hostname,
            "ports": formatted_ports
        }

    duration = (
        time.time()
        - start_time
    )

    # ==================================================
    # RESULTS
    # ==================================================

    print()
    print("=" * 78)
    print("SCAN RESULTS")
    print("=" * 78)

    if not live_hosts:
        print(
            "[-] No live hosts found."
        )

        logger.info(
            "No live hosts found."
        )

    else:
        for host, host_info in scan_results.items():
            hostname = host_info[
                "hostname"
            ]

            ports = host_info[
                "ports"
            ]

            print()

            if hostname:
                print(
                    f"Host: {host} "
                    f"({hostname})"
                )

            else:
                print(
                    f"Host: {host}"
                )

            print("-" * 78)

            if ports:
                print(
                    f"{'PORT':<12}"
                    f"{'STATE':<12}"
                    f"{'SERVICE':<18}"
                    f"BANNER"
                )

                print(
                    f"{'-' * 8:<12}"
                    f"{'-' * 8:<12}"
                    f"{'-' * 14:<18}"
                    f"{'-' * 30}"
                )

                for port_info in ports:
                    banner = (
                        port_info["banner"]
                        or "-"
                    )

                    print(
                        f"{str(port_info['port']) + '/tcp':<12}"
                        f"{'OPEN':<12}"
                        f"{port_info['service']:<18}"
                        f"{banner}"
                    )

            else:
                print(
                    "No open ports found."
                )

    # ==================================================
    # SUMMARY
    # ==================================================

    total_open_ports = sum(
        len(
            host_info["ports"]
        )
        for host_info
        in scan_results.values()
    )

    print()
    print("=" * 78)
    print("SCAN SUMMARY")
    print("=" * 78)

    print(
        f"Hosts scanned     : "
        f"{len(live_hosts)}"
    )

    print(
        f"Open ports        : "
        f"{total_open_ports}"
    )

    print(
        f"Scan duration     : "
        f"{duration:.2f} seconds"
    )

    print("=" * 78)

    # ==================================================
    # JSON OUTPUT
    # ==================================================

    if args.output:
        try:
            save_json_results(
                filename=args.output,
                target=network,
                start_port=start_port,
                end_port=end_port,
                threads=args.threads,
                scan_results=scan_results,
                duration=duration
            )

        except OSError as error:
            print(
                f"[!] Could not save "
                f"JSON output: {error}"
            )

            logger.error(
                f"Could not save "
                f"JSON output: {error}"
            )

    # ==================================================
    # CSV OUTPUT
    # ==================================================

    if args.csv:
        try:
            save_csv_results(
                filename=args.csv,
                scan_results=scan_results
            )

        except OSError as error:
            print(
                f"[!] Could not save "
                f"CSV output: {error}"
            )

            logger.error(
                f"Could not save "
                f"CSV output: {error}"
            )

    # ==================================================
    # LOG FINISH
    # ==================================================

    logger.info(
        f"Scan finished - "
        f"{len(live_hosts)} host(s), "
        f"{total_open_ports} open port(s), "
        f"duration={duration:.2f}s"
    )


if __name__ == "__main__":
    main()