import ipaddress
import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed


def ping_host(ip):
    operating_system = platform.system().lower()

    if operating_system == "windows":
        command = ["ping", "-n", "1", "-w", "1000", str(ip)]
    else:
        command = ["ping", "-c", "1", "-W", "1", str(ip)]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        return result.returncode == 0

    except Exception:
        return False


def discover_hosts(network, threads=50):
    subnet = ipaddress.ip_network(network, strict=False)

    hosts = list(subnet.hosts())
    live_hosts = []

    print(f"[*] Starting host discovery with {threads} threads...\n")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_ip = {
            executor.submit(ping_host, host): host
            for host in hosts
        }

        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]

            try:
                if future.result():
                    live_hosts.append(str(ip))
                    print(f"[+] {ip} ONLINE")

            except Exception as error:
                print(f"[!] Error scanning {ip}: {error}")

    return sorted(
        live_hosts,
        key=ipaddress.ip_address
    )