import csv
import json
import os
from datetime import datetime


def save_json_results(
    filename,
    target,
    start_port,
    end_port,
    threads,
    scan_results,
    duration
):
    directory = os.path.dirname(filename)

    if directory:
        os.makedirs(
            directory,
            exist_ok=True
        )

    data = {
        "scan_info": {
            "target": str(target),
            "port_range": f"{start_port}-{end_port}",
            "threads": threads,
            "duration_seconds": round(duration, 2),
            "timestamp": (
                datetime.now()
                .astimezone()
                .isoformat()
            )
        },
        "hosts": []
    }

    for host, host_info in scan_results.items():
        host_data = {
            "ip": host,
            "hostname": host_info["hostname"],
            "open_ports": host_info["ports"]
        }

        data["hosts"].append(host_data)

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            data,
            file,
            indent=4
        )

    print()
    print(
        f"[+] JSON results saved to: {filename}"
    )


def save_csv_results(
    filename,
    scan_results
):
    directory = os.path.dirname(filename)

    if directory:
        os.makedirs(
            directory,
            exist_ok=True
        )

    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            "ip",
            "hostname",
            "port",
            "protocol",
            "state",
            "service",
            "banner"
        ])

        for host, host_info in scan_results.items():
            hostname = (
                host_info["hostname"]
                or ""
            )

            ports = host_info["ports"]

            if not ports:
                writer.writerow([
                    host,
                    hostname,
                    "",
                    "",
                    "",
                    "",
                    ""
                ])

                continue

            for port_info in ports:
                writer.writerow([
                    host,
                    hostname,
                    port_info["port"],
                    port_info["protocol"],
                    port_info["state"],
                    port_info["service"],
                    port_info["banner"] or ""
                ])

    print()
    print(
        f"[+] CSV results saved to: {filename}"
    )