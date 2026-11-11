
# NetRecon

NetRecon is a lightweight, Python-based network reconnaissance tool designed for education, home labs, CTFs, and authorized security assessments.

It provides multithreaded TCP/UDP scanning, IPv4 host discovery, protocol-aware UDP probes, service fingerprinting, live progress tracking, and structured reporting.

## Project Status

- **Application Version:** 1.3.0
- **Current Development:** UDP Reliability Improvements
- **Development Branch:** `feature/udp-reliability`
- **Language:** Python 3.10+
- **Dependencies:** Python Standard Library

The current development cycle focuses on improving UDP protocol validation, standards-compatible NTP requests, and configurable retry behavior.

## Features

### Network Discovery
- IPv4 address and CIDR network support
- Multithreaded host discovery
- Optional reverse DNS resolution
- Optional host discovery bypass

### TCP Port Scanning
- Multithreaded TCP connect scanning
- Configurable port ranges
- Common TCP port presets
- Configurable connection timeouts
- Automatic identification of open TCP ports

### UDP Port Scanning
- Multithreaded UDP scanning
- Protocol-aware DNS and NTP probes
- Generic UDP probes for other ports
- UDP-specific port presets
- Configurable UDP timeouts
- Configurable UDP timeout retries
- Request-aware response validation

### Advanced DNS Validation
- DNS transaction ID verification
- DNS response flag validation
- DNS opcode matching
- DNS question parsing
- Case-insensitive domain comparison
- DNS compression pointer parsing
- DNS record type and class verification
- Malformed DNS packet rejection

### Advanced NTP Validation
- NTPv4 client request generation
- Standards-compatible NTP transmit timestamps
- Unix-to-NTP epoch conversion
- 32-bit seconds and fractional seconds encoding
- Request-response timestamp correlation
- Server mode and version validation
- Stratum verification
- Unsynchronized server detection
- Invalid response rejection

### UDP Retry Mechanism
- Configurable retry count from 0 to 5
- Retries only after UDP socket timeouts
- Fresh socket creation for each retry
- Fresh protocol-aware probe generation
- No unnecessary retries after valid responses
- No retries after connection refusal
- Progress tracking based on completed ports

### Service Detection
- Port-based service identification
- TCP banner grabbing
- HTTP and HTTPS banner detection
- SSH fingerprint parsing
- SMTP fingerprint parsing
- FTP fingerprint parsing
- Basic service version identification

### Real-Time Progress Tracking
- Thread-safe progress engine
- Completed port counter
- Progress percentage
- Scanning rate
- Estimated remaining time
- Periodic CLI progress updates

### Configurable Timeouts
- TCP connection timeout
- UDP response timeout
- Independent TCP banner timeout
- UDP timeout retry controls

### Reporting
- Terminal scan results
- JSON export
- CSV export
- Standalone HTML reports
- Responsive dark-themed HTML reports
- Host and port statistics
- Service banners and fingerprints
- HTML escaping of untrusted data

### Testing and Reliability
- Automated unit tests
- CLI integration tests
- DNS and NTP protocol validation tests
- UDP retry tests
- GitHub Actions CI
- Python standard library only

---

## Installation

NetRecon requires Python 3.10 or later.

Clone the repository:

```bash
git clone https://github.com/ardgunaydin/netrecon.git
cd netrecon
```

Check the installed Python version:

```bash
python --version
```

No additional runtime packages are required.

## Usage

### Basic TCP Scan

```bash
python netrecon.py -t 127.0.0.1/32 --skip-discovery
```

### Custom TCP Port Range

```bash
python netrecon.py -t 127.0.0.1/32 -p 1-1000 --skip-discovery
```

### Top TCP Ports

```bash
python netrecon.py -t 127.0.0.1/32 --top-ports 20 --skip-discovery
```

### Basic UDP Scan

```bash
python netrecon.py -t 127.0.0.1/32 --udp --top-ports 10 --skip-discovery
```

### UDP Scan with Retries

```bash
python netrecon.py -t 127.0.0.1/32 --udp -p 53-123 --skip-discovery --timeout 0.5 --udp-retries 2
```

The `--udp-retries` option specifies additional attempts after a UDP socket timeout.

| Value | Maximum Attempts |
|-------|------------------|
| 0 | 1 (default) |
| 1 | 2 |
| 2 | 3 |
| 3 | 4 |
| 4 | 5 |
| 5 | 6 |

Retries are not performed after valid responses, invalid protocol responses, or connection refusal.

### Advanced TCP Timeout Configuration

```bash
python netrecon.py -t 127.0.0.1/32 -p 1-1024 --skip-discovery --timeout 0.5 --banner-timeout 3
```

### Configure Worker Threads

```bash
python netrecon.py -t 127.0.0.1/32 -p 1-1024 --threads 100 --skip-discovery
```

### Resolve Hostnames

```bash
python netrecon.py -t 127.0.0.1/32 -p 1-1024 --resolve-hostnames
```

### Export JSON Results

```bash
python netrecon.py -t 127.0.0.1/32 -p 1-1024 --skip-discovery -o output/scan.json
```

### Export CSV Results

```bash
python netrecon.py -t 127.0.0.1/32 -p 1-1024 --skip-discovery --csv output/scan.csv
```

### Generate HTML Report

```bash
python netrecon.py -t 127.0.0.1/32 -p 1-1024 --skip-discovery --html output/scan.html
```

### Export Multiple Report Formats

```bash
python netrecon.py -t 127.0.0.1/32 -p 1-1024 --skip-discovery -o output/scan.json --csv output/scan.csv --html output/scan.html
```

### Check Application Version

```bash
python netrecon.py --version
```

---

## UDP Protocol Validation

### DNS Validation

NetRecon sends protocol-aware DNS queries and validates incoming responses against the original request.

Validation includes:

1. Matching DNS transaction identifiers
2. Confirming the DNS response flag
3. Matching DNS opcodes
4. Parsing DNS question names
5. Comparing question types and classes
6. Supporting case-insensitive domain names
7. Detecting malformed compression pointers

A matching response provides stronger evidence that the expected DNS service answered.

### NTP Validation

NetRecon generates NTPv4 client requests using the standard 64-bit NTP timestamp representation.

The timestamp contains:

- 32-bit seconds field
- 32-bit fractional seconds field

NTP timestamps use an epoch beginning on January 1, 1900.

NetRecon converts Unix timestamps to the NTP representation and verifies that the server echoes the original transmit timestamp in its originate timestamp field.

Additional validation checks include:

- NTP version
- Server mode
- Stratum value
- Leap indicator
- Server transmit timestamp

These checks improve response correlation but do not provide cryptographic authentication.

### UDP Port States

| State | Meaning |
|-------|---------|
| open | A response passed the configured protocol validation |
| closed | Connection refused or port unreachable |
| open\|filtered | Timeout or response that failed validation |
| error | Other socket or network errors |

UDP results are inherently less definitive than TCP connection results.

An `open|filtered` result does not conclusively establish that a port is open.

---

## Real-Time Scan Progress

NetRecon includes a thread-safe progress tracking engine.

Displayed information includes:

- Number of completed ports
- Total target ports
- Completion percentage
- Estimated scan rate
- Estimated remaining time

Progress tracking is available for TCP and UDP scans.

When UDP retries are enabled, progress is counted per completed port rather than per individual attempt.

## HTML Security Reports

NetRecon can generate standalone HTML reports containing:

- Scan target and generation timestamp
- Scan duration
- Number of scanned hosts
- Open and open|filtered port statistics
- Port numbers and protocols
- Service identification
- TCP banner information
- Available service fingerprints

Reports use a responsive dark-themed design.

HTML escaping is applied to untrusted scan data to reduce the risk of HTML injection.

HTML reports are generated without external runtime dependencies.

## Testing

NetRecon includes automated unit and integration tests.

Run the complete test suite:

```bash
python -m unittest discover -s tests -v
```

Run DNS parser tests:

```bash
python -m unittest tests.test_dns_parser -v
```

Run NTP validation tests:

```bash
python -m unittest tests.test_ntp_validation -v
```

Run UDP retry tests:

```bash
python -m unittest tests.test_udp_retries -v
```

Run UDP integration tests:

```bash
python -m unittest tests.test_udp_response_integration -v
```

GitHub Actions is configured to run tests across Python 3.10, 3.11, 3.12, and 3.13.

## Limitations

- IPv4 scanning only
- TCP and UDP require separate scan invocations
- UDP timeout results can be ambiguous
- Some services may not respond to generic UDP probes
- UDP retrying may increase total scan duration
- Service banners may be missing or inaccurate
- Fingerprints are based on unverified remote responses
- DNS/NTP response correlation is not cryptographic authentication
- HTML reports do not perform vulnerability assessment
- Service detection is best-effort

## Roadmap

### Completed

- [x] Multithreaded TCP scanning
- [x] Multithreaded UDP scanning
- [x] Protocol-aware DNS probes
- [x] Protocol-aware NTP probes
- [x] TCP service fingerprinting
- [x] Thread-safe scan progress tracking
- [x] Real-time CLI statistics
- [x] Configurable TCP banner timeouts
- [x] JSON and CSV exports
- [x] Standalone HTML reports
- [x] Improved DNS question parsing
- [x] DNS request-response correlation
- [x] Standards-compatible NTP timestamps
- [x] NTP request-response correlation
- [x] Configurable UDP timeout retries

### Planned

- [ ] IPv6 scanning
- [ ] Additional service fingerprinting
- [ ] Improved UDP error and response classification
- [ ] Enhanced scan performance
- [ ] Installable Python CLI package
- [ ] Additional integration and reliability tests
- [ ] Expanded reporting and result filtering

## Security and Ethical Use

NetRecon is intended exclusively for educational purposes, home laboratories, CTF environments, and authorized security assessments.

Only scan systems and networks that you own or have explicit permission to test.

Network scanning may trigger security monitoring tools or affect sensitive services.

## License

MIT License.

## Author

Arda Günaydın

Computer Science student interested in networking and cybersecurity.

GitHub: https://github.com/ardgunaydin

## Repository

https://github.com/ardgunaydin/netrecon
