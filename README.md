# Modular Recon Tool

A modular reconnaissance and enumeration tool for domains and IPs. It supports WHOIS lookup, DNS record enumeration, comprehensive subdomain discovery (passive sources + brute force), Nmap-based port scanning with optional banner grabbing, and web technology detection (headers/HTML/cookies + Wappalyzer). Results can be printed to console and optionally appended to a report file.

## Features
- WHOIS: Registrar, dates, name servers
- DNS: A, MX, TXT, NS records
- Subdomains: Passive (crt.sh, HackerTarget, AlienVault OTX, ThreatCrowd) + brute force with threads
- HTTP checks: Optional HTTP/HTTPS status and page titles for discovered subdomains
- Port scan: Nmap TCP scan with configurable ports and optional banner grabbing
- Tech detection: Detect server/CMS/frameworks/languages/CDN, OS hints and versions; optional Wappalyzer
- Logging: Verbose output levels and optional file logging to `recon.log`

## Requirements
- Python 3.8+
- System Nmap installed (required by `python-nmap`)
  - Windows: Install Nmap from https://nmap.org/download.html and ensure `nmap.exe` is in your PATH
- Network access to the target(s)

Python libraries (install via `requirements.txt`):
- python-whois, python-nmap, dnspython, requests, beautifulsoup4, python-Wappalyzer, builtwith, colorama, lxml

Install dependencies:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

> Note: `datetime` and `logging` are from Python’s standard library and do not require installation.

## Quick Start
Run the tool:

```bash
python main.py <target>
```

Increase verbosity:

```bash
python main.py <target> -v         # info
python main.py <target> -vv        # debug
```

Write outputs to a report file (appends to `recon.log` by default):

```bash
python main.py <target> --report
python main.py <target> --report --output my_report.log
```

## Usage
The CLI exposes modular actions that you can combine:

- WHOIS lookup
  - `python main.py example.com --whois`
- DNS enumeration (A, MX, TXT, NS)
  - `python main.py example.com --dns`
- Subdomain enumeration
  - Passive only: `python main.py example.com --subdomains --passive-only`
  - Bruteforce only: `python main.py example.com --subdomains --bruteforce-only`
  - Passive + default wordlist: `python main.py example.com --subdomains`
  - Passive + custom wordlist: `python main.py example.com --subdomains --wordlist custom.txt`
  - Check HTTP/HTTPS status: `python main.py example.com --subdomains --check-http`
- Port scan (Nmap)
  - Default range (1–1000): `python main.py 192.168.1.1 --ports`
  - Specific ports: `python main.py 192.168.1.1 --ports 22,80,443`
  - Range and list mixed: `python main.py 192.168.1.1 --ports 22,80,100-200`
  - Banner grabbing: `python main.py 192.168.1.1 --ports 80,443 --banner`
- Technology detection
  - `python main.py example.com --tech`

You can chain modules in one run, e.g.:

```bash
python main.py example.com --whois --dns --subdomains --ports 1-1000 --report
```

## Options Summary
- `target`: Domain or IP (required)
- `--whois`: Perform WHOIS lookup
- `--dns`: DNS enumeration (A, MX, TXT, NS)
- `--subdomains`: Run subdomain enumeration
- `--wordlist FILE`: Custom wordlist for brute force
- `--passive-only`: Only passive sources (no brute force)
- `--bruteforce-only`: Only brute force (no passive)
- `--check-http`: Fetch HTTP/HTTPS status and title for found subdomains
- `--threads N`: Thread count for brute force (default: 10)
- `--ports [PORTS]`: Enable port scan; omit value to use `1-1000`
- `--banner`: Attempt to grab service banners on open ports
- `--tech`: Run technology detection module
- `--report`: Append results to a log file
- `--output FILE`: Report output file (default: `recon.log`)
- `-v`, `-vv`: Increase verbosity

## Output
- Console: Human-readable summaries per module
- Report file: When `--report` is used, results are appended to `--output` (default `recon.log`).
  - WHOIS, DNS, subdomain enumeration, and port scan include timestamps and structured entries.
  - Technology detection can also generate a separate tech report via `TechDetector.generate_report()`.

## Technology Detection Details
The `TechDetector` module analyzes:
- Headers: `Server`, `X-Powered-By`, CDN hints (Cloudflare/Akamai)
- HTML: CMS (WordPress/Joomla/Drupal), frameworks (React/Vue/Angular/Bootstrap/jQuery)
- Cookies: Language/framework hints (PHP, ASP.NET, Laravel)
- OS and versions: Extracts OS hints (Linux distros, Windows Server/IIS) and versions (nginx/Apache/IIS/PHP/WordPress/jQuery/etc.)
- Optional Wappalyzer: Adds broader technology detections

Example:

```bash
python main.py example.com --tech --report --output tech.log
```

## Notes & Troubleshooting
- Nmap not found: Ensure Nmap is installed and `nmap.exe` is in PATH on Windows.
- WHOIS module: Install `python-whois` (`pip install python-whois`). If a different `whois` package is installed, you may see "Incorrect whois module installed".
- HTTP checks: SSL verification is disabled for flexibility; use responsibly.
- API rate limits: Passive sources (e.g., HackerTarget) may throttle. Try again later if errors occur.
- Timeouts: DNS and HTTP requests use modest timeouts; increase `--threads` or retry if network conditions are slow.

## Legal & Ethical Use
Only scan and enumerate targets you own or have explicit permission to test. Misuse may violate laws or terms of service.

## Project Structure
- `main.py`: CLI entry point and modules for WHOIS, DNS, subdomain enumeration, port scanning, reporting
- `tech_detect.py`: Technology detection module and report generator
- `requirements.txt`: Python dependencies

## Example Commands
```bash
# WHOIS + DNS
python main.py example.com --whois --dns

# Subdomains (passive + default) and HTTP checks, with report
python main.py example.com --subdomains --check-http --report --output recon.log

# Full recon with port scan
python main.py example.com --whois --dns --subdomains --ports 1-1000 --report

# Technology detection
python main.py example.com --tech --report --output tech.log
```

---
For questions or improvements, feel free to adapt the modules in `main.py` and `tech_detect.py`.
