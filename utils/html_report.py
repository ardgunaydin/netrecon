
"""Standalone, safely escaped HTML reports for NetRecon."""

import html
import json
from datetime import datetime
from pathlib import Path


def escape(value):
    """Escape untrusted text before inserting it into HTML."""
    if value is None:
        return "-"
    return html.escape(str(value), quote=True)


def render_html_report(target, scan_results, duration=0):
    """Create a self-contained HTML report from scan results."""
    scan_results = scan_results or {}
    hosts_scanned = len(scan_results)

    all_ports = [
        port
        for host in scan_results.values()
        for port in host.get("ports", [])
    ]

    open_ports = sum(
        port.get("state") == "open"
        for port in all_ports
    )
    uncertain_ports = sum(
        port.get("state") == "open|filtered"
        for port in all_ports
    )

    generated_at = datetime.now().astimezone().strftime(
        "%Y-%m-%d %H:%M:%S %Z"
    )

    sections = []

    for ip, host_info in scan_results.items():
        hostname = host_info.get("hostname") or "-"
        ports = host_info.get("ports", [])

        rows = []

        for port in sorted(
            ports,
            key=lambda item: (
                item.get("protocol", ""),
                item.get("port", 0)
            )
        ):
            state = str(port.get("state", "unknown")).lower()

            state_class = {
                "open": "open",
                "open|filtered": "uncertain"
            }.get(state, "other")

            fingerprint = port.get("fingerprint")
            fingerprint_text = (
                json.dumps(fingerprint, ensure_ascii=False)
                if fingerprint is not None
                else "-"
            )

            port_label = (
                f"{port.get('port', '-')}/"
                f"{port.get('protocol', '-')}"
            )

            rows.append(f"""
                <tr>
                    <td>{escape(port_label)}</td>
                    <td>
                        <span class="state {state_class}">
                            {escape(state.upper())}
                        </span>
                    </td>
                    <td>{escape(port.get("service", "UNKNOWN"))}</td>
                    <td class="wrap">{escape(port.get("banner"))}</td>
                    <td class="wrap">{escape(fingerprint_text)}</td>
                </tr>
            """)

        table_rows = "\n".join(rows) if rows else (
            '<tr><td colspan="5">No reported ports</td></tr>'
        )

        sections.append(f"""
            <section class="host">
                <h2>{escape(ip)}</h2>
                <p class="muted">Hostname: {escape(hostname)}</p>
                <div class="table-scroll">
                    <table>
                        <thead>
                            <tr>
                                <th>Port</th>
                                <th>State</th>
                                <th>Service</th>
                                <th>Banner</th>
                                <th>Fingerprint</th>
                            </tr>
                        </thead>
                        <tbody>{table_rows}</tbody>
                    </table>
                </div>
            </section>
        """)

    host_sections = "\n".join(sections) or (
        '<section class="host">No hosts were scanned.</section>'
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>NetRecon Scan Report</title>
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            margin: 0;
            background: #0b1220;
            color: #e5edf8;
            font-family: system-ui, Arial, sans-serif;
            line-height: 1.5;
        }}
        main {{
            max-width: 1200px;
            margin: auto;
            padding: 36px 20px;
        }}
        h1 {{ margin-bottom: 4px; color: #60a5fa; }}
        h2 {{ margin: 0; font-size: 19px; }}
        .muted {{ color: #94a3b8; }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 16px;
            margin: 28px 0;
        }}
        .card, .host {{
            background: #131e31;
            border: 1px solid #283851;
            border-radius: 12px;
            padding: 20px;
        }}
        .card strong {{
            display: block;
            font-size: 28px;
            color: #f8fafc;
        }}
        .host {{ margin-bottom: 20px; }}
        .table-scroll {{ overflow-x: auto; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 16px;
        }}
        th, td {{
            padding: 12px;
            border-bottom: 1px solid #283851;
            text-align: left;
            vertical-align: top;
        }}
        th {{ color: #93c5fd; }}
        .wrap {{
            white-space: pre-wrap;
            overflow-wrap: anywhere;
            max-width: 320px;
        }}
        .state {{
            font-size: 12px;
            font-weight: 700;
            border-radius: 5px;
            padding: 5px 8px;
        }}
        .open {{ background: #14532d; color: #bbf7d0; }}
        .uncertain {{ background: #78350f; color: #fde68a; }}
        .other {{ background: #334155; color: #e2e8f0; }}
        footer {{ margin-top: 30px; }}
    </style>
</head>
<body>
    <main>
        <header>
            <h1>NETRECON</h1>
            <p class="muted">Network Reconnaissance Report</p>
            <p>
                <strong>Target:</strong> {escape(target)}
                <br>
                <strong>Generated:</strong> {escape(generated_at)}
                <br>
                <strong>Duration:</strong> {duration:.2f} seconds
            </p>
        </header>

        <div class="stats">
            <div class="card">
                <strong>{hosts_scanned}</strong>Hosts scanned
            </div>
            <div class="card">
                <strong>{open_ports}</strong>Open ports
            </div>
            <div class="card">
                <strong>{uncertain_ports}</strong>Open / filtered
            </div>
            <div class="card">
                <strong>{len(all_ports)}</strong>Reported ports
            </div>
        </div>

        {host_sections}

        <footer class="muted">
            NetRecon | Authorized security testing only.
            Service fingerprints are unverified remote data.
        </footer>
    </main>
</body>
</html>
"""


def save_html_report(filename, target, scan_results, duration=0):
    """Write a standalone UTF-8 HTML report to disk."""
    output_path = Path(filename)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    content = render_html_report(
        target=target,
        scan_results=scan_results,
        duration=duration
    )

    output_path.write_text(content, encoding="utf-8")
    print(f"[+] HTML report saved to: {output_path}")
