# NetRecon

NetRecon is a lightweight Python-based network reconnaissance tool designed for educational, lab, and authorized security testing environments.

It provides host discovery, multithreaded TCP port scanning, service identification, banner grabbing, hostname resolution, logging, and structured JSON/CSV output through a simple command-line interface.

## Features

- IPv4 and CIDR target support
- Ping-based host discovery
- Multithreaded host discovery
- Multithreaded TCP port scanning
- Custom port ranges
- Common service identification
- Basic banner grabbing
- HTTP and HTTPS banner detection
- Reverse DNS hostname resolution
- Skip host discovery mode
- JSON export
- CSV export
- Scan logging
- Configurable thread count
- CLI help and version information
- Automated unit tests

## Example

```bash
python netrecon.py -t 127.0.0.1/32 -p 1-1000 --resolve-hostnames
```

Example output:

```text
==============================================================================
                              NETRECON
==============================================================================
[+] Version           : 0.7.0
[+] Target            : 127.0.0.1/32
[+] Ports             : 1-1000
[+] Threads           : 50
[+] Host discovery    : ON
[+] Hostname resolving: ON

[*] Starting host discovery with 50 threads...

[+] 127.0.0.1 ONLINE

[*] Scanning 127.0.0.1 ports 1-1000...
[+] 127.0.0.1:135 OPEN
[+] 127.0.0.1:445 OPEN

==============================================================================
SCAN RESULTS
==============================================================================

Host: 127.0.0.1 (YOUR-HOSTNAME)
------------------------------------------------------------------------------
PORT        STATE       SERVICE           BANNER
--------    --------    --------------    ------------------------------
135/tcp     OPEN        MSRPC             -
445/tcp     OPEN        SMB               -

==============================================================================
SCAN SUMMARY
==============================================================================
Hosts scanned     : 1
Open ports        : 2
Scan duration     : 14.38 seconds
==============================================================================
```

## Installation

Clone the repository:

```bash
git clone https://github.com/ardgunaydin/netrecon.git
cd netrecon
```

NetRecon currently uses only Python standard-library modules, so no external dependencies are required.

Recommended Python version:

```text
Python 3.10+
```

Check your Python installation:

```bash
python --version