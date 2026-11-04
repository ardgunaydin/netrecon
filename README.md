NetRecon
NetRecon is a lightweight, Python-based network reconnaissance tool for education, home labs, CTFs, and authorized security testing.

It supports IPv4 host discovery, multithreaded TCP and UDP scanning, service identification, TCP banner grabbing, basic service fingerprint analysis, reverse DNS lookup, logging, and structured JSON/CSV reports.
Responsible use: Scan only systems and networks you own or have explicit permission to test.

Project status
- Application version: 1.1.0. Advanced service detection is being developed on feature/advanced-service-detection for a future v1.2.0; the application version has not yet been bumped.
- Latest previously confirmed GitHub release: v1.0.0 (25 October 2026). A newer release has not been verified here.
- Local tests: 49 tests reported passing on the advanced-service-detection branch. GitHub Actions results for this branch should be confirmed after pushing.
Features
- IPv4 addresses and CIDR network targets
- Multithreaded ICMP-based host discovery
- TCP connect scanning (default mode)
- UDP scanning with protocol-aware DNS (53) and NTP (123) probes
- Generic UDP probes for other ports
- Custom port ranges (-p START-END) and curated TCP/UDP presets (--top-ports 10, 20, 50)
- Configurable worker count and scan timeout
- Port-based service identification
- TCP banner grabbing, including basic HTTP and HTTPS handling
- Basic service fingerprint parsing for SSH, HTTP/HTTPS, SMTP, and FTP banners (development branch)
- Terminal reporting and JSON/CSV exports, including an optional fingerprint field
- Optional reverse DNS lookups and optional bypass of host discovery
- Python standard library only: no third-party runtime dependencies
- Automated tests and GitHub Actions CI
Requirements and installation
Requires Python 3.10+.
git clone https://github.com/ardgunaydin/netrecon.git
cd netrecon
python --version
The advanced service detection changes are on a feature branch until merged:
git fetch origin
git switch feature/advanced-service-detection
The feature branch can only be checked out from GitHub after it has been pushed. If working on your local feature branch already, no switch is needed.
Quick start
# TCP scan of localhost, default port range 1-1024
python netrecon.py -t 127.0.0.1/32 --skip-discovery

# Curated common TCP ports
python netrecon.py -t 127.0.0.1/32 --top-ports 20 --skip-discovery

# DNS UDP probe
python netrecon.py -t 127.0.0.1/32 --udp -p 53-53 --skip-discovery

# NTP UDP probe
python netrecon.py -t 127.0.0.1/32 --udp -p 123-123 --skip-discovery

# Curated UDP ports
python netrecon.py -t 127.0.0.1/32 --udp --top-ports 10 --skip-discovery
127.0.0.1/32 refers to your own computer. A service must be listening to return a banner. Without --skip-discovery, NetRecon first attempts host discovery.
Scanning modes
TCP (default)
NetRecon attempts TCP connections to the selected ports. When a port is open, it tries to obtain a banner using a separate connection. HTTP/HTTPS handling sends a basic HEAD request; other services use passive banner retrieval. Open ports do not always return a banner.
python netrecon.py -t 127.0.0.1/32 -p 1-1000 --skip-discovery
UDP (--udp)
UDP is connectionless. NetRecon sends a request and uses returned data, socket errors, and timeouts to classify results:
State	Meaning
open	A response passed the scanner's basic checks.
closed	The OS reported a connection refusal or port-unreachable condition.
open|filtered	No response arrived or a response failed basic checks; actual state is uncertain.
error	Another network or socket error occurred.


Destination	Probe	Basic response validation
UDP/53 (DNS)	DNS A-record query for example.com	Minimum DNS header length and response flag
UDP/123 (NTP)	48-byte NTP client request	Minimum length and server mode
Other UDP ports	One-byte generic probe	Non-empty response


Limitations: A timeout is not proof that a port is open or filtered. DNS and NTP response validation is basic; it does not currently verify DNS transaction IDs or securely match NTP responses to requests. The port-specific service label is not proof of the actual service running there.
Advanced service fingerprinting (development branch)
NetRecon v1.2.0 development adds a parser that turns recognized TCP banners into structured hints. It is integrated into scanner/service_detector.py and the terminal and JSON/CSV output paths.
Service label	Example banner	Parsed information
SSH	SSH-2.0-OpenSSH_9.6	SSH protocol version 2.0, software OpenSSH_9.6
HTTP/HTTPS	nginx/1.24.0	Software nginx, version 1.24.0
SMTP	220 mail.example.com ESMTP Postfix	SMTP greeting details
FTP	220 ProFTPD 1.3.8 Server	FTP greeting details


The HTTP/HTTPS parser works with server banner values returned by the current HTTP banner collector (typically the value of the Server header). It does not do deep application fingerprinting. SMTP and FTP use port-based service labels to interpret similar 220 greetings. Fingerprints are unverified, potentially misleading strings supplied by remote services; a detected software name or version is not independently validated.

Example fingerprint object:
{
  "protocol": "SSH",
  "protocol_version": "2.0",
  "software": "OpenSSH_9.6"
}
Fingerprint output
The terminal keeps its existing BANNER column and appends detected information when available.

Example (illustrative, not a live scan):
PORT        STATE           SERVICE           BANNER
22/tcp      OPEN            SSH               SSH-2.0-OpenSSH_9.6 | Detected: OpenSSH_9.6
JSON export includes an optional fingerprint property for scanned TCP ports. It may be null when the banner is missing or unrecognized. UDP port records do not require this property.
{
  "port": 22,
  "protocol": "tcp",
  "state": "open",
  "service": "SSH",
  "banner": "SSH-2.0-OpenSSH_9.6",
  "fingerprint": {
    "protocol": "SSH",
    "protocol_version": "2.0",
    "software": "OpenSSH_9.6"
  }
}
CSV export adds a fingerprint column after banner. When a fingerprint exists, its structured data is serialized as a JSON string in that cell; otherwise, the cell is empty.
Command-line options
Option	Description
-t, --target	Required IPv4 address or CIDR network
-p, --ports	Inclusive port range, such as 1-1024
--top-ports {10,20,50}	Curated common ports for the selected TCP/UDP mode
--udp	Scan UDP instead of TCP
--threads	Number of scan worker threads (default 50)
--timeout	Per-port scan timeout in seconds (default 0.5)
--skip-discovery	Scan targets without ping-based discovery
--resolve-hostnames	Attempt reverse DNS lookup
-o, --output	Write JSON report
--csv	Write CSV report
--version	Display application version
-h, --help	Show CLI help


-p and --top-ports cannot be used together. TCP and UDP are scanned in separate invocations. Banner grabbing currently has its own default timeout in the service detector; the CLI --timeout controls the port scan rather than every banner read.
Export reports
python netrecon.py -t 127.0.0.1/32 --top-ports 10 --skip-discovery -o output/scan.json --csv output/scan.csv
JSON reports include scan metadata (target, mode, threads, duration, timestamp, and relevant port/time settings) plus per-host ports and open_ports records. CSV reports include ip, hostname, port, protocol, state, service, banner, and fingerprint. Review scan output before sharing it.
Project structure
netrecon/
├── .github/workflows/tests.yml
├── scanner/
│   ├── __init__.py
│   ├── fingerprint_parser.py      # SSH, HTTP, SMTP, FTP banner parsing (new)
│   ├── host_scanner.py
│   ├── port_presets.py
│   ├── port_scanner.py
│   ├── service_detector.py        # Service detection + parser integration
│   ├── udp_probes.py
│   └── udp_scanner.py
├── utils/
│   ├── __init__.py
│   ├── logger.py
│   └── output.py                  # JSON/CSV fingerprint export
├── tests/
│   ├── __init__.py
│   ├── test_cli_integration.py
│   ├── test_fingerprint_parser.py # New banner parser tests
│   ├── test_netrecon.py
│   ├── test_output.py
│   ├── test_port_presets.py
│   ├── test_port_scanner.py
│   ├── test_service_detector.py
│   ├── test_udp_port_presets.py
│   ├── test_udp_probes.py
│   └── test_udp_scanner.py
├── results/.gitkeep
├── .gitignore
├── LICENSE
├── README.md
├── requirements.txt
└── netrecon.py
Tests and CI
Run the full test suite:
python -m unittest discover -s tests -v
The advanced service detection branch was reported to pass 49 tests locally after fixing a Python indentation issue in netrecon.py. The new tests cover SSH/HTTP/SMTP/FTP parsing and empty or unsupported banners. Existing tests cover input validation, scanning, presets, CLI selection, and JSON/CSV serialization.

GitHub Actions is configured to run tests on Python 3.10, 3.11, 3.12, and 3.13. Confirm its status on the feature branch and subsequent pull request before merging.
Roadmap
- [x] TCP connect scanning and host discovery
- [x] UDP scanning and TCP/UDP port presets
- [x] Protocol-aware DNS and NTP UDP probes
- [x] Basic TCP service fingerprint parsing (feature branch)
- [x] Fingerprint data in terminal and JSON/CSV reports (feature branch)
- [ ] Stronger DNS/NTP request-response matching
- [ ] More robust banner normalization and version extraction
- [ ] HTTP response/header handling improvements and additional service fingerprints
- [ ] Configurable banner read timeouts
- [ ] Scan progress and statistics
- [ ] Optional terminal colors and HTML reports
- [ ] Installable Python package and CLI entrypoint
- [ ] IPv6 support
- [ ] Broader integration and edge-case tests
Security and ethical use
NetRecon is designed for learning and authorized assessments. Network scans may trigger monitoring and security controls or interfere with fragile services. Follow applicable laws, rules, and explicit target authorization.
License
MIT License. See LICENSE.
Author
Arda Günaydın — Computer Science student interested in networking and cybersecurity.

GitHub: @ardgunaydin · NetRecon repository