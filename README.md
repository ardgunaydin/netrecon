
# NetRecon

NetRecon is a Python-based network reconnaissance tool designed for
education, home labs, CTFs, and authorized security assessments.

It provides multithreaded TCP/UDP scanning, IPv4 host discovery,
service fingerprinting, live progress tracking, and structured reports.

## Version

**Application version:** 1.3.0 (development)

The v1.3.0 GitHub release will be published after testing and merging.

## Features

- IPv4 host discovery and CIDR target support
- Multithreaded TCP connect scanning
- UDP scanning with DNS and NTP protocol-aware probes
- Custom port ranges and curated port presets
- SSH, HTTP/HTTPS, SMTP, and FTP banner fingerprint parsing
- Thread-safe scan progress tracking
- Live progress percentage, scanning rate, and ETA
- Configurable connection and banner timeouts
- Reverse DNS lookup
- JSON, CSV, and standalone HTML reporting
- Responsive dark-themed HTML reports
- HTML escaping for untrusted scan data
- Unit and CLI integration tests
- GitHub Actions CI
- No third-party runtime dependencies

## Installation

Requires Python 3.10 or later.

```bash
git clone https://github.com/ardgunaydin/netrecon.git
cd netrecon
```

## Usage

Basic TCP scan:

```bash
python netrecon.py -t 127.0.0.1/32 --skip-discovery
```

UDP scanning:

```bash
python netrecon.py -t 127.0.0.1/32 --udp --top-ports 10 --skip-discovery
```

Configure scanning and banner timeouts:

```bash
python netrecon.py -t 127.0.0.1/32 -p 1-1024 --skip-discovery --timeout 0.5 --banner-timeout 3
```

Generate an HTML report:

```bash
python netrecon.py -t 127.0.0.1/32 -p 1-1024 --skip-discovery --html output/scan.html
```

Export JSON, CSV and HTML together:

```bash
python netrecon.py -t 127.0.0.1/32 -p 1-1024 --skip-discovery -o output/scan.json --csv output/scan.csv --html output/scan.html
```

## HTML Security Reports

NetRecon generates standalone HTML reports containing:

- Target and scan metadata
- Hosts scanned
- Open and open|filtered port statistics
- Port numbers, protocols and states
- Service names and banners
- Available fingerprint data

The reports use a responsive dark-themed layout and require no external
JavaScript or CSS dependencies.

Untrusted scan fields are HTML-escaped before rendering.

Reports may contain sensitive network information. Review them before sharing.

## Progress Tracking

TCP and UDP scans support progress reporting with:

- Completed and total port counts
- Completion percentage
- Approximate scanning rate
- Estimated remaining time

The progress engine uses thread-safe counters and monotonic timing.
ETA values are estimates rather than guaranteed completion times.

## Testing

Run the complete test suite:

```bash
python -m unittest discover -s tests -v
```

GitHub Actions is configured to test Python 3.10, 3.11, 3.12, and 3.13.

## Limitations

- IPv4 scanning only
- TCP and UDP require separate scan invocations
- UDP open|filtered results are inherently uncertain
- Fingerprints are based on unverified service responses
- HTML reporting does not perform vulnerability assessment
- Service detection and banner grabbing are best-effort operations

## Roadmap

- [x] TCP and UDP scanning
- [x] Protocol-aware DNS/NTP UDP probes
- [x] TCP service fingerprinting
- [x] Thread-safe scan progress
- [x] Live scanning statistics
- [x] Configurable banner timeouts
- [x] Standalone HTML reports
- [ ] IPv6 support
- [ ] Additional service fingerprints
- [ ] Improved UDP response correlation
- [ ] Installable CLI package
- [ ] Additional performance and reliability tests

## Security and Ethical Use

Use NetRecon only against networks and systems you own or have explicit
authorization to test. Network scanning can trigger IDS/IPS alerts or
affect sensitive services.

## License

MIT License.

## Author

Arda Günaydın

Computer Science student interested in networking and cybersecurity.

GitHub: https://github.com/ardgunaydin
