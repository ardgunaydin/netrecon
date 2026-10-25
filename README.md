NetRecon is a lightweight, Python-based network reconnaissance tool for educational use, home labs, CTFs, and authorized network security testing.

It provides IPv4 host discovery, multithreaded TCP and UDP scanning, port-based service identification, TCP banner grabbing, reverse DNS lookup, logging, and structured JSON/CSV reports from a command-line interface.
Use NetRecon only on systems and networks you own or are explicitly authorized to test.

Project status
- Code version: 1.1.0 on main (UDP scanning changes merged).
- Latest published GitHub release: v1.0.0 as of 25 October 2026. A separate v1.1.0 release has not yet been published.
- Verification: 34 automated tests passed locally; GitHub Actions passed on Python 3.10, 3.11, 3.12 and 3.13 after merging.
Features
- IPv4 addresses and CIDR network targets
- Ping-based, multithreaded host discovery
- Multithreaded TCP connect scanning (default mode)
- Multithreaded UDP scanning (--udp)
- Custom port ranges (-p START-END)
- Separate curated TCP and UDP presets (--top-ports 10, 20, 50)
- Configurable worker count and per-port timeout
- Common-service identification by port number
- TCP banner grabbing, including basic HTTP/HTTPS responses
- Optional reverse DNS resolution
- Option to bypass ping discovery (--skip-discovery)
- Terminal reporting, file logging, JSON/CSV exports
- Unit and CLI integration tests with GitHub Actions CI
- No third-party runtime dependencies
Installation
Requires Python 3.10+.
git clone https://github.com/ardgunaydin/netrecon.git
cd netrecon
python --version
NetRecon uses Python's standard library, so no additional packages are required for normal use.
Quick start
# Basic TCP scan (default range: 1-1024)
python netrecon.py -t 127.0.0.1/32 --skip-discovery

# Selected common TCP ports
python netrecon.py -t 127.0.0.1/32 --top-ports 20 --skip-discovery

# A custom UDP port range
python netrecon.py -t 127.0.0.1/32 --udp -p 123-123 --skip-discovery

# Top 10 curated UDP ports
python netrecon.py -t 127.0.0.1/32 --udp --top-ports 10 --skip-discovery
127.0.0.1/32 targets your own computer. Without --skip-discovery, the tool first attempts ICMP-based host discovery.
TCP and UDP scanning
TCP (default)
TCP scanning uses connection attempts to identify open ports. When possible, NetRecon then makes a separate connection to retrieve a service banner. Basic HTTP and HTTPS header handling is supported.
python netrecon.py -t 127.0.0.1/32 -p 1-1000 --skip-discovery
UDP (--udp)
UDP scanning sends a generic one-byte probe to each selected UDP port and interprets the response or socket error:
State	Meaning
open	A UDP response was received.
closed	A connection-refused / port-unreachable indication was received.
open|filtered	No response arrived before timeout; the port may be open or filtered.
error	Another network/socket error occurred.


Important: open|filtered does not prove a service is open. Many UDP services ignore generic probes, and network/firewall behavior affects results. Protocol-specific UDP payloads and UDP banner grabbing are not implemented in this version.
python netrecon.py -t 127.0.0.1/32 --udp -p 53-161 --skip-discovery
--top-ports uses separate, curated port lists depending on the active TCP or UDP mode. The lists are not statistical rankings or Nmap's frequency database.
Command-line options
Option	Description
-t, --target	IPv4 address or CIDR network (required)
-p, --ports	Port range, such as 1-1024
--top-ports {10,20,50}	Use curated port presets for the selected protocol
--udp	Scan UDP instead of TCP
--threads	Number of worker threads (default: 50)
--timeout	Per-port timeout in seconds (default: 0.5)
--skip-discovery	Scan targets directly, without ping-based discovery
--resolve-hostnames	Attempt reverse DNS lookup
-o, --output	Export results as JSON
--csv	Export results as CSV
--version	Show the program version
-h, --help	Show help


The -p and --top-ports options cannot be used together. One protocol (TCP or UDP) is scanned per invocation.
Example output
The following is an example based on a localhost UDP test; actual results depend on the machine and network.
==============================================================================
                              NETRECON
==============================================================================
[+] Version           : 1.1.0
[+] Protocol          : UDP
[+] Target            : 127.0.0.1/32
[+] Ports             : 123-123
[+] Threads           : 50
[+] Timeout           : 0.5 seconds
[+] Host discovery    : OFF
[+] Hostname resolving: OFF

[*] Host discovery skipped.
[*] Starting UDP scan on 127.0.0.1 (1 ports)...
[?] 127.0.0.1:123/udp OPEN|FILTERED

SCAN RESULTS
Host: 127.0.0.1
PORT        STATE           SERVICE           BANNER
--------    --------------  --------------    ------------------------------
123/udp     OPEN|FILTERED   NTP               -

SCAN SUMMARY
Hosts scanned     : 1
Open ports        : 0
Open|Filtered ports: 1
Scan mode         : 123-123
Service names such as NTP, DNS or SNMP are derived from conventional port mappings and do not prove that the named software or protocol is running.
JSON and CSV reports
Create both formats in one scan:
python netrecon.py -t 127.0.0.1/32 --udp -p 123-123 --skip-discovery -o output/udp_scan.json --csv output/udp_scan.csv
Example JSON host record:
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
In JSON, ports contains the reported port states; open_ports contains only ports confirmed open. JSON reports also include scan metadata such as the target, scan mode, timeout and elapsed time.

CSV exports include the columns ip, hostname, port, protocol, state, service and banner.
Generated output files under output/ are excluded from Git using .gitignore. Review any report before sharing it publicly.

Project structure
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
│   └── udp_scanner.py
├── utils/
│   ├── __init__.py
│   ├── logger.py
│   └── output.py
├── tests/
│   ├── __init__.py
│   ├── test_cli_integration.py
│   ├── test_netrecon.py
│   ├── test_output.py
│   ├── test_port_presets.py
│   ├── test_port_scanner.py
│   ├── test_service_detector.py
│   ├── test_udp_port_presets.py
│   └── test_udp_scanner.py
├── results/
│   └── .gitkeep
├── .gitignore
├── LICENSE
├── README.md
├── requirements.txt
└── netrecon.py
Testing and CI
Run all tests:
python -m unittest discover -s tests -v
Last verified local run: 34 tests passed. Coverage includes input validation, TCP scanning, port presets, UDP socket behavior, TCP/UDP CLI selection, and JSON/CSV serialization.

GitHub Actions runs on pushes and pull requests for Python 3.10, 3.11, 3.12 and 3.13:

View the successful post-merge CI run.
Roadmap
Potential improvements:
- Protocol-aware UDP probes and more reliable service identification
- Improved service/version fingerprinting
- Configurable banner timeouts
- Scan progress and richer statistics
- Optional colored terminal output and HTML reports
- An installable Python package / CLI
- IPv6 support
- Additional edge-case and end-to-end tests
Security and ethical use
Use NetRecon only against systems and networks you own or have permission to test. Scanning can trigger IDS/IPS alerts, violate organizational rules, or affect fragile services. You are responsible for complying with applicable laws and policies.
License
MIT License — see LICENSE.
Author
Arda Günaydın — Computer Science student interested in networking and network security engineering.

GitHub: @ardgunaydin · NetRecon repository
