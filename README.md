NetRecon is a lightweight, Python-based network reconnaissance tool for educational use, home labs, CTF environments, and authorized network security assessments.

It combines ping-based host discovery, multithreaded TCP and UDP port scanning, common-service identification, TCP banner grabbing, optional reverse DNS resolution, and JSON/CSV reporting in a simple command-line interface.
Authorization required: Only scan systems and networks you own or have explicit permission to assess.

Release status: This README describes the v1.1.0 development work. The published stable release is v1.0.0, while the development branch reports v1.1.0. The new release has not yet been published.

Features
- IPv4 address and CIDR network targets
- Ping-based, multithreaded host discovery
- Multithreaded TCP connect scanning (default)
- Multithreaded UDP scanning (--udp, new in v1.1.0)
- Custom port ranges (-p START-END)
- Separate curated TCP and UDP presets (--top-ports 10, 20, or 50)
- Configurable worker threads and per-port timeouts
- Common-service identification by port number
- Basic TCP service detection and banner grabbing, including HTTP/HTTPS
- Optional reverse DNS hostname resolution
- Optional host-discovery bypass (--skip-discovery)
- Structured JSON and CSV exports
- File-based scan logging
- Automated unit and CLI integration tests
- GitHub Actions CI configured for multiple Python versions
- Modular, standard-library-only Python architecture
Current limitations: UDP uses a generic one-byte probe, not protocol-specific payloads or comprehensive UDP fingerprinting. TCP banner grabbing is not available in UDP mode. Only one of TCP or UDP is scanned per invocation; IPv6 scanning is not implemented.
Installation
Requires Python 3.10 or newer and Git (for cloning).
git clone https://github.com/ardgunaydin/netrecon.git
cd netrecon
python --version
No third-party runtime packages are required. NetRecon uses Python's standard library.
The GitHub default branch may still reflect v1.0.0 until the v1.1.0 development branch is merged.

Quick Start
# Default TCP scan: ports 1-1024
python netrecon.py -t 127.0.0.1/32 --skip-discovery

# Selected TCP ports from the curated preset
python netrecon.py -t 127.0.0.1/32 --top-ports 20 --skip-discovery

# UDP scan: a single local port
python netrecon.py -t 127.0.0.1/32 --udp -p 123-123 --skip-discovery

# UDP scan: curated top 10 ports
python netrecon.py -t 127.0.0.1/32 --udp --top-ports 10 --skip-discovery
127.0.0.1/32 targets your own computer. Use other targets only when authorized. If --skip-discovery is omitted, NetRecon first attempts ping-based host discovery.
TCP Port Scanning
TCP is the default mode and uses connection attempts to identify ports that accept a TCP connection.
# Scan TCP ports 1-1000
python netrecon.py -t 127.0.0.1/32 -p 1-1000 --skip-discovery

# Scan 10 selected TCP ports
python netrecon.py -t 127.0.0.1/32 --top-ports 10 --skip-discovery
For detected open TCP ports, NetRecon attempts to identify common services and retrieve banners. HTTP/HTTPS probes are supported on selected known web-service ports; other TCP services may expose a generic banner.

Port-based service names are best-effort labels, not proof of a specific application or version.
UDP Port Scanning (v1.1.0)
Enable UDP mode with --udp:
# Scan a UDP port range
python netrecon.py -t 127.0.0.1/32 --udp -p 100-150 --skip-discovery

# Scan curated UDP ports
python netrecon.py -t 127.0.0.1/32 --udp --top-ports 10 --skip-discovery
NetRecon sends a one-byte UDP datagram and waits for a response or a socket error. Because UDP is connectionless, the result can be ambiguous.
State	Meaning
open	A UDP response was received.
closed	The operating system reported a connection-refused / port-unreachable condition.
open|filtered	No response was received before the timeout; the port might be open or filtered.
error	Another socket/network error occurred.


The CLI and exported results exclude closed entries but can include open, open|filtered, and error. The Open ports summary counts only confirmed open results; Open|Filtered ports is reported separately.

Important: open|filtered does not confirm that a UDP service is running. Many real UDP services ignore generic probes and require valid application-layer requests.
Example UDP result
The following is an example of a localhost test, not a claim about another network:
[+] Protocol          : UDP
[+] Target            : 127.0.0.1/32
[+] Ports             : 123-123

PORT        STATE           SERVICE           BANNER
--------    --------------  --------------    ------------------------------
123/udp     OPEN|FILTERED   NTP               -

Hosts scanned     : 1
Open ports        : 0
Open|Filtered ports: 1
Service names such as DNS (53), NTP (123), or SNMP (161) are based on well-known UDP port assignments, not active protocol fingerprinting.
Port Presets
Use --top-ports 10, --top-ports 20, or --top-ports 50. NetRecon selects different lists for TCP and UDP.
# TCP preset
python netrecon.py -t 127.0.0.1/32 --top-ports 20 --skip-discovery

# UDP preset
python netrecon.py -t 127.0.0.1/32 --udp --top-ports 20 --skip-discovery
These are curated collections of commonly used service ports, not statistical frequency rankings and not equivalent to Nmap's port-frequency database.

-p and --top-ports are mutually exclusive.
Scanning Options
Timeout and Threads
Defaults: 50 worker threads and 0.5-second per-port timeout.
python netrecon.py -t 127.0.0.1/32 -p 1-100 --threads 25 --timeout 1 --skip-discovery
Shorter timeouts can miss slow responses; larger thread counts create more simultaneous traffic. Use reasonable settings on authorized networks.
Host Discovery
By default, NetRecon checks which hosts respond to a ping before scanning. To scan the specified target(s) without this check:
python netrecon.py -t 127.0.0.1/32 -p 1-100 --skip-discovery
A host that does not respond to ping is not necessarily offline. Note that skipping discovery for a large CIDR range can generate many scans.
Reverse DNS
python netrecon.py -t 127.0.0.1/32 --top-ports 10 --resolve-hostnames
If reverse resolution fails, NetRecon continues with the IP address.
JSON and CSV Reports
Both protocols support the same export flags:
# Save a UDP scan in both formats
python netrecon.py -t 127.0.0.1/32 --udp -p 123-123 --skip-discovery -o output/udp_scan.json --csv output/udp_scan.csv

# Save a TCP scan in both formats
python netrecon.py -t 127.0.0.1/32 -p 1-100 --skip-discovery -o output/tcp_scan.json --csv output/tcp_scan.csv
JSON structure
Illustrative output for a UDP port that did not respond:
{
  "scan_info": {
    "target": "127.0.0.1/32",
    "scan_mode": "range",
    "threads": 50,
    "duration_seconds": 0.51,
    "timestamp": "2026-10-25T18:21:42+01:00",
    "timeout_seconds": 0.5,
    "port_range": "123-123"
  },
  "hosts": [
    {
      "ip": "127.0.0.1",
      "hostname": null,
      "ports": [
        {
          "port": 123,
          "protocol": "udp",
          "state": "open|filtered",
          "service": "NTP",
          "banner": null
        }
      ],
      "open_ports": []
    }
  ]
}
- ports includes reported port entries, including open|filtered results.
- open_ports includes only confirmed open entries, retained for compatibility with earlier output consumers.
- scan_info.scan_mode describes range versus preset selection, not the transport protocol. Each port entry carries its own protocol field.
- Timestamps and scan durations depend on the run.
CSV columns
ip,hostname,port,protocol,state,service,banner
For example:
ip,hostname,port,protocol,state,service,banner
127.0.0.1,,123,udp,open|filtered,NTP,
Privacy: JSON/CSV reports can contain internal hostnames, addresses, and service information. Do not commit generated reports or logs to public repositories. Add /output/ to .gitignore when using the example paths above.
Logging
NetRecon logs scan activity to results/netrecon.log, including scan parameters, discovered hosts, observed ports, service labels, and scan duration. Generated logs should remain outside Git tracking.
Command-Line Reference
Option	Description
-t, --target	Target IP address or CIDR network (required).
-p, --ports	Custom port range (e.g., 1-1000).
--top-ports {10,20,50}	Use a curated TCP or UDP port preset.
--udp	Use UDP instead of the default TCP scan.
--threads	Number of worker threads (default: 50).
--timeout	Per-port timeout in seconds (default: 0.5).
--skip-discovery	Bypass ping-based host discovery.
--resolve-hostnames	Attempt reverse DNS lookup.
-o, --output	Save JSON results.
--csv	Save CSV results.
--version	Show the current program version.
-h, --help	Show CLI usage.


python netrecon.py --help
python netrecon.py --version
Project Structure
netrecon/
├── .github/
│   └── workflows/
│       └── tests.yml
├── scanner/
│   ├── __init__.py
│   ├── host_scanner.py
│   ├── port_presets.py
│   ├── port_scanner.py
│   ├── service_detector.py
│   └── udp_scanner.py          # New in v1.1.0
├── utils/
│   ├── __init__.py
│   ├── logger.py
│   └── output.py
├── tests/
│   ├── __init__.py
│   ├── test_cli_integration.py # New in v1.1.0
│   ├── test_netrecon.py
│   ├── test_output.py
│   ├── test_port_presets.py
│   ├── test_port_scanner.py
│   ├── test_service_detector.py
│   ├── test_udp_port_presets.py # New in v1.1.0
│   └── test_udp_scanner.py      # New in v1.1.0
├── results/
│   └── .gitkeep
├── .gitignore
├── LICENSE
├── README.md
├── requirements.txt
└── netrecon.py
output/ is a generated reports directory and should be Git-ignored, not committed.
Architecture
                       Target IP / CIDR
                              |
                   Ping-based discovery
                     (or skip discovery)
                              |
                        Protocol mode
                         /        \
                        /          \
                 TCP connect      UDP probe
                  scanning         scanning
                     |                |
              Service + banner    Port-based service
              identification      label + UDP state
                        \          /
                         \        /
                       Scan results
                       /    |     \
                  Terminal JSON    CSV
                              |
                         Scan logging
Scanner, host discovery, service detection, reports, and tests are separated into independent modules.
Testing
NetRecon uses the standard-library unittest framework.
python -m unittest discover -s tests -v
Latest local development run (25 October 2026): 34 tests passed, 0 failures. This does not yet confirm a green GitHub Actions run for the development branch.

Coverage includes:
- IPv4/CIDR and port-range validation
- TCP open/closed port behavior and selected-port scanning
- TCP common-port presets
- TCP service name detection
- UDP response and no-response states
- UDP input validation and multiport scanning
- UDP common-port presets (10/20/50)
- Default TCP vs. selected UDP CLI mode
- UDP CLI JSON/CSV exports
- JSON and CSV serialization
Some tests mock the scanner to verify CLI integration deterministically; others use localhost sockets. Successful tests do not guarantee correct identification of every real-world UDP service.
Continuous Integration
The GitHub Actions workflow at [`.github/workflows/tests.yml`](.github/workflows/tests.yml) is configured to run tests on pushes and pull requests using:
- Python 3.10
- Python 3.11
- Python 3.12
- Python 3.13
Check GitHub Actions for the status of a particular commit or pull request.
Development Status and Roadmap
Published stable release: v1.0.0

Next release in development: v1.1.0 — adds UDP scanning, separate UDP port presets, updated reporting, and CLI integration tests. The local test suite currently passes; release tagging and remote CI validation remain to be completed.

Potential future improvements:
- Protocol-specific UDP probes for more reliable results
- More advanced service/version fingerprinting
- Configurable banner-grabbing timeout
- Richer scan metrics and progress indicators
- Optional colored terminal output and HTML reports
- Python packaging / installable CLI
- IPv6 support
- Additional negative-path and integration tests
Security and Ethical Use
NetRecon is intended for personal devices, local development environments, virtual machines, home labs, CTFs, and other environments where testing is authorized.

Do not scan networks or hosts without permission. Scanning can trigger IDS/IPS alerts, breach policy, or disrupt fragile services. Users are responsible for compliance with relevant laws and policies.
License
Licensed under the MIT License. See LICENSE.
Author
Arda Günaydın — Computer Science student focused on networking, cybersecurity, and network security engineering.

GitHub: @ardgunaydin

Repository: github.com/ardgunaydin/netrecon