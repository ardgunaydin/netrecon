# NetRecon

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![Tests](https://github.com/ardgunaydin/netrecon/actions/workflows/tests.yml/badge.svg)](https://github.com/ardgunaydin/netrecon/actions/workflows/tests.yml)
[![Version](https://img.shields.io/badge/version-1.0.0-green)](https://github.com/ardgunaydin/netrecon)
[![License](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)

**NetRecon** is a lightweight Python-based network reconnaissance tool designed for educational purposes, security labs, CTF environments, and authorized network testing.

It provides host discovery, multithreaded TCP port scanning, service identification, banner grabbing, hostname resolution, configurable timeouts, common-port presets, logging, and structured JSON/CSV output through a simple command-line interface.

> NetRecon is intended only for systems and networks you own or have explicit permission to test.

---

## Features

- IPv4 and CIDR target support
- Ping-based host discovery
- Multithreaded host discovery
- Multithreaded TCP port scanning
- Custom TCP port ranges
- Common-port scan presets
  - Top 10
  - Top 20
  - Top 50
- Configurable TCP connection timeout
- Common service identification
- Basic banner grabbing
- HTTP banner detection
- HTTPS banner detection
- Reverse DNS hostname resolution
- Skip host-discovery mode
- JSON result export
- CSV result export
- File-based scan logging
- Configurable thread count
- CLI help and version information
- Automated unit tests
- Multi-version GitHub Actions CI
- Modular project architecture

---

## Example

Run a common-port reconnaissance scan:

```bash
python netrecon.py -t 127.0.0.1/32 --top-ports 20 --timeout 0.2 --resolve-hostnames
```

Example output:

```text
==============================================================================
                              NETRECON
==============================================================================
[+] Version           : 1.0.0
[+] Target            : 127.0.0.1/32
[+] Ports             : Top 20 common ports
[+] Threads           : 50
[+] Timeout           : 0.2 seconds
[+] Host discovery    : ON
[+] Hostname resolving: ON

[*] Starting host discovery with 50 threads...

[+] 127.0.0.1 ONLINE

[*] Scanning 127.0.0.1 on 20 selected ports...
[+] 127.0.0.1:135 OPEN
[+] 127.0.0.1:445 OPEN
[+] 127.0.0.1:8080 OPEN

==============================================================================
SCAN RESULTS
==============================================================================

Host: 127.0.0.1 (YOUR-HOSTNAME)
------------------------------------------------------------------------------
PORT        STATE       SERVICE           BANNER
--------    --------    --------------    ------------------------------
135/tcp     OPEN        MSRPC             -
445/tcp     OPEN        SMB               -
8080/tcp    OPEN        HTTP-ALT          SimpleHTTP/0.6 Python/3.x

==============================================================================
SCAN SUMMARY
==============================================================================
Hosts scanned     : 1
Open ports        : 3
Scan mode         : Top 20 common ports
Scan duration     : 4.35 seconds
==============================================================================
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/ardgunaydin/netrecon.git
cd netrecon
```

Check your Python version:

```bash
python --version
```

Recommended:

```text
Python 3.10+
```

NetRecon currently relies only on Python standard-library modules, so no third-party runtime dependencies are required.

---

## Usage

### Basic Scan

```bash
python netrecon.py -t 127.0.0.1/32
```

If no port configuration is provided, NetRecon scans:

```text
1-1024
```

---

### Custom Port Range

```bash
python netrecon.py -t 127.0.0.1/32 -p 1-1000
```

Another example:

```bash
python netrecon.py -t 127.0.0.1/32 -p 8000-9000
```

---

## Common Port Presets

NetRecon includes curated common TCP port presets for faster reconnaissance.

### Top 10 Ports

```bash
python netrecon.py -t 127.0.0.1/32 --top-ports 10
```

### Top 20 Ports

```bash
python netrecon.py -t 127.0.0.1/32 --top-ports 20
```

### Top 50 Ports

```bash
python netrecon.py -t 127.0.0.1/32 --top-ports 50
```

The preset list is a curated collection of common TCP services and is not intended to reproduce Nmap's frequency database.

The `-p` and `--top-ports` options are mutually exclusive.

For example, this is valid:

```bash
python netrecon.py -t 127.0.0.1/32 -p 1-1000
```

And this is also valid:

```bash
python netrecon.py -t 127.0.0.1/32 --top-ports 20
```

---

## Configure Connection Timeout

The TCP connection timeout can be changed with:

```bash
python netrecon.py -t 127.0.0.1/32 --top-ports 20 --timeout 0.2
```

Default:

```text
0.5 seconds
```

Lower timeout values may make scans faster, while higher values may be useful on slower networks.

---

## Configure Thread Count

NetRecon uses multithreading to improve scan performance.

Default:

```text
50 threads
```

Custom value:

```bash
python netrecon.py -t 127.0.0.1/32 -p 1-1000 --threads 100
```

---

## Hostname Resolution

Enable reverse DNS resolution with:

```bash
python netrecon.py -t 127.0.0.1/32 --top-ports 20 --resolve-hostnames
```

Example:

```text
Host: 127.0.0.1 (MY-LAPTOP)
```

If no hostname can be resolved, NetRecon continues using the IP address.

---

## Skip Host Discovery

By default, NetRecon performs ping-based host discovery before TCP scanning.

To skip this step:

```bash
python netrecon.py -t 127.0.0.1/32 --skip-discovery
```

This can be useful when a target does not respond to ICMP echo requests but may still expose TCP services.

---

## Service Detection

NetRecon maps common TCP ports to known services.

Examples:

```text
21     FTP
22     SSH
25     SMTP
53     DNS
80     HTTP
135    MSRPC
139    NETBIOS
443    HTTPS
445    SMB
1433   MSSQL
3306   MYSQL
3389   RDP
5432   POSTGRESQL
5900   VNC
6379   REDIS
8080   HTTP-ALT
8443   HTTPS-ALT
```

Service names based purely on port numbers are best-effort identifications and should not be treated as definitive proof of the software running on that port.

---

## Banner Grabbing

For supported services, NetRecon attempts to retrieve additional information from the service.

For example:

```text
PORT        STATE       SERVICE           BANNER
--------    --------    --------------    ------------------------------
8080/tcp    OPEN        HTTP-ALT          SimpleHTTP/0.6 Python/3.12.3
```

A simple local test server can be started with:

```bash
python -m http.server 8080
```

Then scanned using:

```bash
python netrecon.py -t 127.0.0.1/32 --top-ports 20
```

---

## JSON Export

Save scan results as JSON:

```bash
python netrecon.py \
    -t 127.0.0.1/32 \
    --top-ports 20 \
    -o results/scan.json
```

Example:

```json
{
    "scan_info": {
        "target": "127.0.0.1/32",
        "scan_mode": "top_ports",
        "threads": 50,
        "duration_seconds": 4.33,
        "timeout_seconds": 0.2,
        "selected_ports": [
            22,
            80,
            443,
            445
        ]
    },
    "hosts": [
        {
            "ip": "127.0.0.1",
            "hostname": null,
            "open_ports": [
                {
                    "port": 8080,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "HTTP-ALT",
                    "banner": "SimpleHTTP/0.6 Python/3.12.3"
                }
            ]
        }
    ]
}
```

The actual `selected_ports` array contains the complete preset selected for the scan.

---

## CSV Export

Save results as CSV:

```bash
python netrecon.py \
    -t 127.0.0.1/32 \
    --top-ports 20 \
    --csv results/scan.csv
```

CSV columns:

```text
ip
hostname
port
protocol
state
service
banner
```

---

## JSON + CSV Export

Both formats can be generated during the same scan:

```bash
python netrecon.py \
    -t 127.0.0.1/32 \
    --top-ports 20 \
    --timeout 0.2 \
    --resolve-hostnames \
    -o results/scan.json \
    --csv results/scan.csv
```

---

## Logging

NetRecon stores scan activity in:

```text
results/netrecon.log
```

Logs include information such as:

```text
Scan start
Target
Port configuration
Thread count
Timeout
Discovered hosts
Open ports
Detected services
Banner information
Scan completion
Scan duration
```

Generated scan results and logs are excluded from Git tracking through `.gitignore`.

---

## Command-Line Options

| Option | Description |
|---|---|
| `-t`, `--target` | Target IPv4 address or CIDR network |
| `-p`, `--ports` | Custom TCP port range |
| `--top-ports {10,20,50}` | Scan a preset of common TCP ports |
| `--threads` | Number of worker threads |
| `--timeout` | TCP connection timeout in seconds |
| `--skip-discovery` | Skip ping-based host discovery |
| `--resolve-hostnames` | Attempt reverse DNS resolution |
| `-o`, `--output` | Save results as JSON |
| `--csv` | Save results as CSV |
| `--version` | Display NetRecon version |
| `-h`, `--help` | Display CLI help |

Show help:

```bash
python netrecon.py --help
```

Show version:

```bash
python netrecon.py --version
```

---

## Project Structure

```text
netrecon/
│
├── .github/
│   └── workflows/
│       └── tests.yml
│
├── scanner/
│   ├── __init__.py
│   ├── host_scanner.py
│   ├── port_presets.py
│   ├── port_scanner.py
│   └── service_detector.py
│
├── utils/
│   ├── __init__.py
│   ├── logger.py
│   └── output.py
│
├── tests/
│   ├── __init__.py
│   ├── test_netrecon.py
│   ├── test_output.py
│   ├── test_port_presets.py
│   ├── test_port_scanner.py
│   └── test_service_detector.py
│
├── results/
│   └── .gitkeep
│
├── .gitignore
├── LICENSE
├── README.md
├── requirements.txt
└── netrecon.py
```

---

## Architecture

NetRecon uses a modular reconnaissance pipeline:

```text
                  ┌─────────────────┐
                  │     Target      │
                  └────────┬────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │ Host Discovery  │
                  └────────┬────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │ TCP Port Scan   │
                  └────────┬────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │Service Detection│
                  └────────┬────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │ Banner Grabbing │
                  └────────┬────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │Hostname Resolve │
                  └────────┬────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │ Scan Results    │
                  └───────┬─┬─┬─────┘
                          │ │ │
                ┌─────────┘ │ └─────────┐
                ▼           ▼           ▼
             Terminal      JSON        CSV
                              │
                              ▼
                             Log
```

The project separates scanning, service detection, output handling, logging, and testing into independent modules.

---

## Testing

NetRecon uses Python's built-in `unittest` framework.

Run the complete test suite:

```bash
python -m unittest discover -s tests -v
```

Current test suite:

```text
22 automated tests
```

The tests currently cover:

- Valid CIDR parsing
- Invalid network handling
- Single-IP targets
- Valid port ranges
- Invalid port ranges
- Port boundary validation
- TCP open-port detection
- TCP closed-port detection
- Port-range scanning
- Custom port-list scanning
- Top 10 port preset
- Top 20 port preset
- Top 50 port preset
- Duplicate preset validation
- HTTP service identification
- HTTPS service identification
- SSH service identification
- SMB service identification
- RDP service identification
- MySQL service identification
- JSON output
- CSV output

Example result:

```text
----------------------------------------------------------------------
Ran 22 tests

OK
```

---

## Continuous Integration

NetRecon uses **GitHub Actions** to automatically run the test suite when code is pushed or a pull request is opened.

The CI workflow currently tests NetRecon against:

```text
Python 3.10
Python 3.11
Python 3.12
Python 3.13
```

Workflow:

```text
.github/workflows/tests.yml
```

This helps verify compatibility across multiple supported Python versions.

---

## Development Status

Current stable release:

```text
NetRecon v1.0.0
```

Feature status:

| Feature | Status |
|---|:---:|
| IPv4 / CIDR parsing | ✅ |
| Host discovery | ✅ |
| Multithreaded discovery | ✅ |
| TCP port scanning | ✅ |
| Multithreaded port scanning | ✅ |
| Custom port ranges | ✅ |
| Common-port presets | ✅ |
| Configurable timeout | ✅ |
| Service detection | ✅ |
| Banner grabbing | ✅ |
| HTTP/HTTPS detection | ✅ |
| Reverse DNS | ✅ |
| Skip discovery | ✅ |
| JSON export | ✅ |
| CSV export | ✅ |
| Logging | ✅ |
| Unit tests | ✅ |
| GitHub Actions CI | ✅ |

---

## Roadmap

Potential future improvements include:

- Improved protocol fingerprinting
- More advanced service/version detection
- Additional scan profiles
- UDP scanning support
- Configurable banner timeout
- Improved scan statistics
- Optional colored terminal output
- Python package / CLI installation
- Additional test coverage
- IPv6 support

---

## Security and Ethical Use

NetRecon is intended for:

- Personal systems
- Local development environments
- Home labs
- Virtual machines
- CTF environments
- Cybersecurity training platforms
- Networks where explicit authorization has been granted

Do **not** use NetRecon to scan devices, systems, or networks without authorization.

Network reconnaissance can trigger IDS/IPS systems, violate organizational policies, disrupt services, or violate applicable laws when performed without permission.

Always ensure that you have authorization before scanning a target.

---

## Disclaimer

This project was created for educational purposes and authorized cybersecurity testing.

The author assumes no responsibility for misuse, damage, policy violations, or unlawful activity resulting from the use of this software.

Users are responsible for ensuring that their use of NetRecon complies with all applicable laws, regulations, and network policies.

---

## License

This project is licensed under the **MIT License**.

See the [LICENSE](LICENSE) file for details.

---

## Author

**Arda Günaydın**

Computer Science student focused on networking, cybersecurity, and network security engineering.

GitHub: [@ardgunaydin](https://github.com/ardgunaydin)

---

## Repository

https://github.com/ardgunaydin/netrecon