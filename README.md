NetRecon
NetRecon is a lightweight, Python-based network reconnaissance tool built for education, home labs, CTFs, and authorized network security assessments.

It supports IPv4 host discovery, multithreaded TCP and UDP port scanning, basic service identification, TCP banner grabbing, reverse DNS lookups, and JSON/CSV reporting—all through a command-line interface.
Responsible use: Scan only systems and networks you own or are explicitly authorized to test.

Project Status
- Application version: 1.1.0 (the new UDP probe feature is being developed on feature/udp-protocol-probes).
- Latest previously confirmed GitHub release: v1.0.0 (25 October 2026). A v1.1.0 release has not been confirmed.
- Baseline verification: 34 tests previously passed on main, with GitHub Actions passing for Python 3.10–3.13. The new probe integration and tests must be verified before merging.
Features
- IPv4 addresses and CIDR network targets
- Multithreaded, ping-based host discovery
- Multithreaded TCP connect scanning (default)
- Multithreaded UDP scanning with basic response classification
- Protocol-aware UDP probes for DNS (53) and NTP (123) on the development branch
- Generic one-byte UDP probes for other ports
- Configurable port ranges and curated TCP/UDP port presets (top 10, 20, or 50)
- Configurable worker count and per-port timeout
- Port-based service naming
- TCP banner grabbing, including basic HTTP/HTTPS handling
- Optional reverse DNS lookup
- Optional bypass of host discovery (--skip-discovery)
- Terminal output, logging, and JSON/CSV exports
- Automated unit and CLI integration tests, with GitHub Actions CI
- No third-party runtime dependencies
Installation
Requirements: Python 3.10 or later.
git clone https://github.com/ardgunaydin/netrecon.git
cd netrecon
python --version
For the latest protocol-aware UDP work, switch to the feature branch after it has been pushed to GitHub:
git fetch origin
git switch feature/udp-protocol-probes
NetRecon uses the Python standard library; no additional packages are required for ordinary operation.
Quick Start
# Default TCP scan, ports 1–1024, on the local machine
python netrecon.py -t 127.0.0.1/32 --skip-discovery

# Curated common TCP ports
python netrecon.py -t 127.0.0.1/32 --top-ports 20 --skip-discovery

# DNS over UDP
python netrecon.py -t 127.0.0.1/32 --udp -p 53-53 --skip-discovery

# NTP over UDP
python netrecon.py -t 127.0.0.1/32 --udp -p 123-123 --skip-discovery

# Curated common UDP ports
python netrecon.py -t 127.0.0.1/32 --udp --top-ports 10 --skip-discovery
127.0.0.1/32 refers to your own machine. Without --skip-discovery, NetRecon first attempts ICMP-based host discovery. A local test is meaningful only when a corresponding service is running.
Scanning Modes
TCP (Default)
TCP scanning attempts connections to selected destination ports. For open ports, NetRecon attempts a separate connection to retrieve a banner. Basic HTTP and HTTPS response handling is supported.
python netrecon.py -t 127.0.0.1/32 -p 1-1000 --skip-discovery
UDP (--udp)
UDP is connectionless. NetRecon sends a probe and uses returned datagrams, socket errors, or timeouts to classify each port. A missing response is inherently ambiguous.
Protocol-Aware UDP Probes
The development branch introduces the following probes:
UDP destination port	Service	Probe	Basic response check
53	DNS	DNS A-record query for example.com	DNS response flag and minimum header length
123	NTP	48-byte NTP client request	Minimum packet length and server mode
Other ports	Generic	Single zero byte	Nonempty response


The DNS query uses a random transaction ID. Current response validation is basic: it does not yet verify the echoed DNS transaction ID, the queried name, or the responding endpoint against the original request. Likewise, NTP responses are not yet cryptographically authenticated or matched to a unique request. A response that passes these checks is not proof of service identity or safety.
UDP Port States
State	Meaning
open	A received datagram passed basic response validation.
closed	The operating system reported connection refusal or port unreachability.
open|filtered	The probe timed out or the received response failed basic validation; the port may be open or filtered.
error	Another socket or network error occurred.


Important: open|filtered does not establish that a service is open. Many UDP applications do not respond to unsolicited or unrecognized requests, and firewall behavior may affect results. Protocol-aware probing improves the usefulness of responses, but false positives and false negatives remain possible.
python netrecon.py -t 127.0.0.1/32 --udp -p 53-161 --skip-discovery
--top-ports selects a separate, curated TCP or UDP list. These are practical presets, not statistical rankings derived from Nmap's port-frequency dataset. TCP and UDP are scanned in separate invocations.
Command-Line Options
Option	Description
-t, --target	Required IPv4 address or CIDR network
-p, --ports	Inclusive port range, such as 1-1024
--top-ports {10,20,50}	Curated common ports for the selected protocol
--udp	Use UDP scanning instead of the default TCP scan
--threads	Worker threads (default: 50)
--timeout	Per-port socket timeout in seconds (default: 0.5)
--skip-discovery	Scan targets without ICMP-based host discovery
--resolve-hostnames	Attempt reverse DNS resolution
-o, --output	Export JSON results to the specified path
--csv	Export CSV results to the specified path
--version	Show the application version
-h, --help	Show CLI help


The -p and --top-ports options cannot be used together.
Example Output
Illustrative local UDP scan (results depend on the machine and network):
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
--------    --------------  ----------------  ------------------------------
123/udp     OPEN|FILTERED   NTP               -

SCAN SUMMARY
Hosts scanned     : 1
Open ports        : 0
Open|Filtered ports: 1
Scan mode         : 123-123
Service labels such as DNS, NTP, or SNMP are initially inferred from common port mappings. They do not prove the software or protocol running on that port.
JSON and CSV Reports
Export both formats in one run:
python netrecon.py -t 127.0.0.1/32 --udp -p 123-123 --skip-discovery -o output/udp_scan.json --csv output/udp_scan.csv
Example JSON host record (illustrative):
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
The ports field contains reported port states. The open_ports field includes only ports confirmed open according to the scanner's classification. JSON exports also include scan metadata such as the target, selected port mode, timeout, and elapsed duration.

CSV exports include ip, hostname, port, protocol, state, service, and banner columns. Generated reports under output/ are ignored by Git. Review reports before distributing them.
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
│   ├── udp_probes.py          # New: DNS/NTP probe builders and checks
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
│   ├── test_udp_probes.py     # New: protocol probe unit tests
│   └── test_udp_scanner.py
├── results/
│   └── .gitkeep
├── .gitignore
├── LICENSE
├── README.md
├── requirements.txt
└── netrecon.py
Tests and Continuous Integration
Run all tests:
python -m unittest discover -s tests -v
The existing test suite covers input validation, TCP port scanning, port presets, UDP socket behavior, CLI mode selection, and JSON/CSV serialization. The development branch adds protocol probe construction and response-validation tests.

Verification note: The earlier main baseline passed 34 tests. Do not assume the updated test count or successful execution of the new tests until the full suite is run locally and in CI.

GitHub Actions runs the test suite on Python 3.10, 3.11, 3.12, and 3.13 for pushes and pull requests.
Roadmap
- [x] TCP connect scanning and host discovery
- [x] UDP port scanning
- [x] Separate TCP and UDP port presets
- [x] DNS and NTP protocol-aware probe implementation (feature branch)
- [ ] Stronger DNS transaction ID and NTP request-response matching
- [ ] Additional UDP protocols and richer service fingerprints
- [ ] Improved service/version detection
- [ ] Configurable banner read timeouts
- [ ] Scan progress indicators and richer statistics
- [ ] Optional terminal colors and HTML reporting
- [ ] Installable Python package and CLI command
- [ ] IPv6 support
- [ ] Broader integration and edge-case tests
Security and Ethical Use
NetRecon is intended for learning and authorized security testing only. Scanning may trigger IDS/IPS alerts, violate network policies, or affect fragile services. Use only against targets that you own or have explicit permission to assess, and follow applicable laws and organizational rules.
License
MIT License. See LICENSE.
Author
Arda Günaydın — Computer Science student with interests in networking and cybersecurity.

GitHub: @ardgunaydin · NetRecon Repository