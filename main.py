#!/usr/bin/env python3

import argparse
import logging
import datetime
import socket
import nmap
import sys
import json
import dns.resolver
import requests
import concurrent.futures
from typing import Set, List, Dict, Optional
from tech_detect import TechDetector

try:
    import whois
except ImportError:
    whois = None


# -------------------------
# Logging Setup
# -------------------------
def setup_logging(verbosity: int):
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )


# -------------------------
# WHOIS Lookup
# -------------------------
def whois_lookup(domain: str, log_file: str | None = None):
    """
    Perform a WHOIS lookup.
    Optionally write WHOIS output to a log file.
    """
    logging.info(f"Starting WHOIS lookup for {domain}")

    try:
        import whois as pywhois
        if not hasattr(pywhois, "whois"):
            raise ImportError("Incorrect whois module installed")

        w = pywhois.whois(domain)

        whois_data = {
            "domain": w.domain_name,
            "registrar": w.registrar,
            "creation_date": w.creation_date,
            "expiration_date": w.expiration_date,
            "name_servers": w.name_servers,
        }

        logging.debug(f"WHOIS parsed data: {whois_data}")

        # Print to stdout
        print("\n=== WHOIS INFORMATION ===")
        for k, v in whois_data.items():
            print(f"{k.capitalize():15}: {v}")
        print("=========================\n")

        # Optional file logging
        if log_file:
            logging.info(f"Writing WHOIS data to {log_file}")
            with open(log_file, "a") as f:
                f.write(f"\n[{datetime.datetime.utcnow().isoformat()} UTC]\n")
                for k, v in whois_data.items():
                    f.write(f"{k}: {v}\n")
                f.write("-" * 40 + "\n")

        return whois_data

    except ImportError:
        logging.error("python-whois not installed. Run: pip install python-whois")
        return {"error": "missing python-whois"}

    except Exception as e:
        logging.error(f"WHOIS lookup failed: {e}", exc_info=True)
        return {"error": str(e)}


def dns_enumeration(domain: str, log_file: str | None = None):
    """
    Perform DNS enumeration (A, MX, TXT, NS).
    Optionally write results to a log file.
    """
    logging.info(f"Starting DNS enumeration for {domain}")

    resolver = dns.resolver.Resolver()
    record_types = ["A", "MX", "TXT", "NS"]

    results = {
        "domain": domain,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "records": {}
    }

    for rtype in record_types:
        logging.debug(f"Querying {rtype} records for {domain}")
        results["records"][rtype] = []

        try:
            answers = resolver.resolve(domain, rtype)
            for rdata in answers:
                value = str(rdata)
                results["records"][rtype].append(value)
                logging.debug(f"{rtype} record found: {value}")

        except dns.resolver.NoAnswer:
            logging.info(f"No {rtype} records found")
        except dns.resolver.NXDOMAIN:
            logging.error("Domain does not exist")
            return {"error": "NXDOMAIN"}
        except dns.exception.Timeout:
            logging.warning(f"DNS query timeout for {rtype}")
        except Exception as e:
            logging.error(f"Failed to resolve {rtype}: {e}", exc_info=True)

    # Console output
    print("\n=== DNS ENUMERATION ===")
    for rtype, values in results["records"].items():
        print(f"{rtype} Records:")
        if values:
            for v in values:
                print(f"  - {v}")
        else:
            print("  - None")
    print("======================\n")

    # Optional file logging
    if log_file:
        logging.info(f"Writing DNS results to {log_file}")
        with open(log_file, "a") as f:
            f.write(f"\n[{results['timestamp']} UTC]\n")
            f.write(f"Domain: {domain}\n")
            for rtype, values in results["records"].items():
                f.write(f"{rtype} Records:\n")
                if values:
                    for v in values:
                        f.write(f"  - {v}\n")
                else:
                    f.write("  - None\n")
            f.write("-" * 40 + "\n")

    logging.info("DNS enumeration completed")
    return results


# -------------------------
# Subdomain Enumeration
# -------------------------

# Default wordlist for subdomain brute-forcing
DEFAULT_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "dns1", "dns2", "mx", "mx1", "mx2", "blog", "dev", "www2", "admin",
    "portal", "api", "app", "test", "staging", "prod", "production", "beta",
    "alpha", "demo", "sandbox", "uat", "qa", "stage", "cdn", "static", "assets",
    "img", "images", "media", "video", "download", "downloads", "upload", "uploads",
    "backup", "backups", "db", "database", "mysql", "postgres", "redis", "mongo",
    "elasticsearch", "elastic", "kibana", "grafana", "prometheus", "jenkins",
    "gitlab", "github", "bitbucket", "jira", "confluence", "wiki", "docs",
    "documentation", "help", "support", "status", "monitor", "monitoring",
    "log", "logs", "logging", "analytics", "metrics", "stats", "dashboard",
    "panel", "cpanel", "whm", "plesk", "webmin", "phpmyadmin", "pma",
    "remote", "vpn", "gateway", "proxy", "lb", "loadbalancer", "cache",
    "varnish", "nginx", "apache", "iis", "tomcat", "node", "python", "ruby",
    "php", "java", "go", "rust", "shop", "store", "cart", "checkout", "payment",
    "pay", "billing", "invoice", "order", "orders", "account", "accounts",
    "user", "users", "customer", "customers", "client", "clients", "member",
    "members", "login", "signin", "signup", "register", "auth", "oauth",
    "sso", "saml", "ldap", "ad", "active", "directory", "exchange", "outlook",
    "office", "o365", "microsoft", "google", "aws", "azure", "cloud", "s3",
    "bucket", "storage", "file", "files", "share", "sharing", "sync", "backup",
    "archive", "old", "new", "v1", "v2", "v3", "api1", "api2", "api3",
    "internal", "external", "public", "private", "secure", "ssl", "tls",
    "cert", "certificate", "pki", "ca", "root", "intermediate", "code",
    "git", "svn", "cvs", "repo", "repository", "build", "ci", "cd", "deploy",
    "release", "releases", "version", "update", "updates", "patch", "hotfix",
    "fix", "bug", "bugs", "issue", "issues", "ticket", "tickets", "task",
    "tasks", "project", "projects", "team", "teams", "group", "groups",
    "org", "organization", "company", "corp", "corporate", "enterprise",
    "business", "biz", "info", "about", "contact", "careers", "jobs", "hr",
    "legal", "terms", "privacy", "policy", "security", "compliance", "audit",
    "report", "reports", "reporting", "data", "bigdata", "hadoop", "spark",
    "kafka", "rabbitmq", "activemq", "queue", "message", "messaging", "event",
    "events", "notification", "notifications", "alert", "alerts", "email",
    "newsletter", "marketing", "crm", "salesforce", "hubspot", "mailchimp",
    "sendgrid", "ses", "sns", "sqs", "lambda", "serverless", "container",
    "docker", "kubernetes", "k8s", "swarm", "mesos", "marathon", "consul",
    "vault", "terraform", "ansible", "puppet", "chef", "salt", "nagios",
    "zabbix", "icinga", "splunk", "sumo", "datadog", "newrelic", "dynatrace",
    "apm", "rum", "synthetic", "mobile", "ios", "android", "app1", "app2",
    "m", "mobile-api", "rest", "graphql", "soap", "wsdl", "xml", "json",
    "rpc", "grpc", "websocket", "ws", "wss", "socket", "realtime", "live",
    "stream", "streaming", "broadcast", "radio", "tv", "iptv", "vod",
    "content", "cms", "wordpress", "wp", "drupal", "joomla", "magento",
    "shopify", "woocommerce", "prestashop", "opencart", "forum", "community",
    "social", "facebook", "twitter", "instagram", "linkedin", "youtube",
    "vimeo", "pinterest", "reddit", "discord", "slack", "zoom", "meet",
    "webex", "teams", "skype", "hangouts", "chat", "im", "voip", "sip",
    "pbx", "asterisk", "freepbx", "3cx", "call", "phone", "tel", "fax",
    "print", "printer", "scan", "scanner", "copy", "copier", "iot", "sensor",
    "device", "devices", "embedded", "firmware", "hardware", "software"
]


def resolve_subdomain(subdomain: str, domain: str, resolver: dns.resolver.Resolver) -> Optional[Dict]:
    """
    Attempt to resolve a subdomain and return its details.
    """
    full_domain = f"{subdomain}.{domain}"
    
    try:
        answers = resolver.resolve(full_domain, 'A')
        ips = [str(rdata) for rdata in answers]
        
        logging.debug(f"Resolved {full_domain} -> {ips}")
        
        return {
            "subdomain": subdomain,
            "full_domain": full_domain,
            "ips": ips,
            "source": "bruteforce"
        }
    
    except dns.resolver.NXDOMAIN:
        logging.debug(f"NXDOMAIN: {full_domain}")
        return None
    except dns.resolver.NoAnswer:
        logging.debug(f"No answer: {full_domain}")
        return None
    except dns.resolver.NoNameservers:
        logging.debug(f"No nameservers: {full_domain}")
        return None
    except dns.exception.Timeout:
        logging.debug(f"Timeout: {full_domain}")
        return None
    except Exception as e:
        logging.debug(f"Error resolving {full_domain}: {e}")
        return None


def bruteforce_subdomains(
    domain: str,
    wordlist: List[str],
    threads: int = 10,
    resolver: dns.resolver.Resolver = None
) -> List[Dict]:
    """
    Brute-force subdomains using a wordlist with multi-threading.
    """
    logging.info(f"Starting subdomain brute-force for {domain} with {len(wordlist)} words")
    
    if resolver is None:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
    
    found_subdomains = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_subdomain = {
            executor.submit(resolve_subdomain, sub, domain, resolver): sub
            for sub in wordlist
        }
        
        for future in concurrent.futures.as_completed(future_to_subdomain):
            result = future.result()
            if result:
                found_subdomains.append(result)
                logging.info(f"Found: {result['full_domain']} -> {result['ips']}")
    
    return found_subdomains


def fetch_crtsh_subdomains(domain: str) -> List[Dict]:
    """
    Fetch subdomains from crt.sh (Certificate Transparency logs).
    """
    logging.info(f"Querying crt.sh for {domain}")
    
    subdomains = []
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        
        seen = set()
        for entry in data:
            name = entry.get("name_value", "")
            # Handle wildcard and multi-line entries
            for line in name.split("\n"):
                line = line.strip().lower()
                if line.startswith("*."):
                    line = line[2:]
                if line.endswith(domain) and line not in seen:
                    seen.add(line)
                    subdomains.append({
                        "subdomain": line.replace(f".{domain}", ""),
                        "full_domain": line,
                        "source": "crt.sh"
                    })
        
        logging.info(f"Found {len(subdomains)} subdomains from crt.sh")
        
    except requests.exceptions.RequestException as e:
        logging.error(f"crt.sh query failed: {e}")
    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse crt.sh response: {e}")
    except Exception as e:
        logging.error(f"Unexpected error querying crt.sh: {e}")
    
    return subdomains


def fetch_hackertarget_subdomains(domain: str) -> List[Dict]:
    """
    Fetch subdomains from HackerTarget API.
    """
    logging.info(f"Querying HackerTarget for {domain}")
    
    subdomains = []
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        if "error" in response.text.lower() or "API count exceeded" in response.text:
            logging.warning(f"HackerTarget API error: {response.text}")
            return subdomains
        
        for line in response.text.strip().split("\n"):
            if "," in line:
                subdomain_full, ip = line.split(",", 1)
                subdomain_full = subdomain_full.strip().lower()
                if subdomain_full.endswith(domain):
                    subdomains.append({
                        "subdomain": subdomain_full.replace(f".{domain}", ""),
                        "full_domain": subdomain_full,
                        "ips": [ip.strip()],
                        "source": "hackertarget"
                    })
        
        logging.info(f"Found {len(subdomains)} subdomains from HackerTarget")
        
    except requests.exceptions.RequestException as e:
        logging.error(f"HackerTarget query failed: {e}")
    except Exception as e:
        logging.error(f"Unexpected error querying HackerTarget: {e}")
    
    return subdomains


def fetch_alienvault_subdomains(domain: str) -> List[Dict]:
    """
    Fetch subdomains from AlienVault OTX.
    """
    logging.info(f"Querying AlienVault OTX for {domain}")
    
    subdomains = []
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        
        seen = set()
        for entry in data.get("passive_dns", []):
            hostname = entry.get("hostname", "").lower()
            if hostname.endswith(domain) and hostname not in seen:
                seen.add(hostname)
                subdomains.append({
                    "subdomain": hostname.replace(f".{domain}", ""),
                    "full_domain": hostname,
                    "ips": [entry.get("address", "")],
                    "source": "alienvault"
                })
        
        logging.info(f"Found {len(subdomains)} subdomains from AlienVault")
        
    except requests.exceptions.RequestException as e:
        logging.error(f"AlienVault query failed: {e}")
    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse AlienVault response: {e}")
    except Exception as e:
        logging.error(f"Unexpected error querying AlienVault: {e}")
    
    return subdomains


def fetch_threatcrowd_subdomains(domain: str) -> List[Dict]:
    """
    Fetch subdomains from ThreatCrowd.
    """
    logging.info(f"Querying ThreatCrowd for {domain}")
    
    subdomains = []
    url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        
        if data.get("response_code") == "1":
            for sub in data.get("subdomains", []):
                sub = sub.lower()
                if sub.endswith(domain):
                    subdomains.append({
                        "subdomain": sub.replace(f".{domain}", ""),
                        "full_domain": sub,
                        "source": "threatcrowd"
                    })
        
        logging.info(f"Found {len(subdomains)} subdomains from ThreatCrowd")
        
    except requests.exceptions.RequestException as e:
        logging.error(f"ThreatCrowd query failed: {e}")
    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse ThreatCrowd response: {e}")
    except Exception as e:
        logging.error(f"Unexpected error querying ThreatCrowd: {e}")
    
    return subdomains


def load_wordlist(filepath: str) -> List[str]:
    """
    Load a wordlist from a file.
    """
    try:
        with open(filepath, 'r') as f:
            words = [line.strip().lower() for line in f if line.strip()]
        logging.info(f"Loaded {len(words)} words from {filepath}")
        return words
    except FileNotFoundError:
        logging.error(f"Wordlist file not found: {filepath}")
        return []
    except Exception as e:
        logging.error(f"Failed to load wordlist: {e}")
        return []


def check_subdomain_http(subdomain_info: Dict, timeout: int = 5) -> Dict:
    """
    Check if a subdomain responds to HTTP/HTTPS requests.
    """
    full_domain = subdomain_info.get("full_domain", "")
    
    subdomain_info["http_status"] = None
    subdomain_info["https_status"] = None
    subdomain_info["http_title"] = None
    
    # Check HTTP
    try:
        response = requests.get(
            f"http://{full_domain}",
            timeout=timeout,
            allow_redirects=True,
            verify=False
        )
        subdomain_info["http_status"] = response.status_code
        
        # Extract title
        if "<title>" in response.text.lower():
            start = response.text.lower().find("<title>") + 7
            end = response.text.lower().find("</title>")
            if end > start:
                subdomain_info["http_title"] = response.text[start:end].strip()[:100]
        
    except requests.exceptions.RequestException:
        pass
    
    # Check HTTPS
    try:
        response = requests.get(
            f"https://{full_domain}",
            timeout=timeout,
            allow_redirects=True,
            verify=False
        )
        subdomain_info["https_status"] = response.status_code
        
        # Extract title if not already set
        if not subdomain_info.get("http_title") and "<title>" in response.text.lower():
            start = response.text.lower().find("<title>") + 7
            end = response.text.lower().find("</title>")
            if end > start:
                subdomain_info["http_title"] = response.text[start:end].strip()[:100]
        
    except requests.exceptions.RequestException:
        pass
    
    return subdomain_info


def subdomain_enum(
    domain: str,
    wordlist_path: str | None = None,
    use_passive: bool = True,
    use_bruteforce: bool = True,
    threads: int = 10,
    check_http: bool = False,
    log_file: str | None = None
) -> Dict:
    """
    Perform comprehensive subdomain enumeration.
    
    Args:
        domain: Target domain
        wordlist_path: Path to custom wordlist (optional)
        use_passive: Use passive sources (crt.sh, HackerTarget, etc.)
        use_bruteforce: Perform DNS brute-forcing
        threads: Number of threads for brute-forcing
        check_http: Check HTTP/HTTPS status of found subdomains
        log_file: Optional file to log results
    
    Returns:
        Dictionary with enumeration results
    """
    logging.info(f"Starting subdomain enumeration for {domain}")
    
    timestamp = datetime.datetime.utcnow().isoformat()
    
    results = {
        "domain": domain,
        "timestamp": timestamp,
        "subdomains": [],
        "sources_used": [],
        "total_found": 0
    }
    
    all_subdomains: Dict[str, Dict] = {}
    
    # Passive enumeration
    if use_passive:
        logging.info("Starting passive subdomain enumeration...")
        
        # crt.sh
        results["sources_used"].append("crt.sh")
        for sub in fetch_crtsh_subdomains(domain):
            full = sub["full_domain"]
            if full not in all_subdomains:
                all_subdomains[full] = sub
            else:
                # Add source to existing entry
                existing_sources = all_subdomains[full].get("sources", [all_subdomains[full].get("source", "")])
                if sub["source"] not in existing_sources:
                    existing_sources.append(sub["source"])
                    all_subdomains[full]["sources"] = existing_sources
        
        # HackerTarget
        results["sources_used"].append("hackertarget")
        for sub in fetch_hackertarget_subdomains(domain):
            full = sub["full_domain"]
            if full not in all_subdomains:
                all_subdomains[full] = sub
            else:
                if "ips" in sub and sub["ips"]:
                    existing_ips = all_subdomains[full].get("ips", [])
                    for ip in sub["ips"]:
                        if ip not in existing_ips:
                            existing_ips.append(ip)
                    all_subdomains[full]["ips"] = existing_ips
        
        # AlienVault
        results["sources_used"].append("alienvault")
        for sub in fetch_alienvault_subdomains(domain):
            full = sub["full_domain"]
            if full not in all_subdomains:
                all_subdomains[full] = sub
        
        # ThreatCrowd
        results["sources_used"].append("threatcrowd")
        for sub in fetch_threatcrowd_subdomains(domain):
            full = sub["full_domain"]
            if full not in all_subdomains:
                all_subdomains[full] = sub
    
    # Brute-force enumeration
    if use_bruteforce:
        logging.info("Starting brute-force subdomain enumeration...")
        results["sources_used"].append("bruteforce")
        
        # Load wordlist
        if wordlist_path:
            wordlist = load_wordlist(wordlist_path)
        else:
            wordlist = DEFAULT_SUBDOMAINS
            logging.info(f"Using default wordlist with {len(wordlist)} entries")
        
        if wordlist:
            for sub in bruteforce_subdomains(domain, wordlist, threads=threads):
                full = sub["full_domain"]
                if full not in all_subdomains:
                    all_subdomains[full] = sub
                else:
                    # Update with resolved IPs
                    if "ips" in sub and sub["ips"]:
                        all_subdomains[full]["ips"] = sub["ips"]
    
    # Check HTTP status if requested
    if check_http and all_subdomains:
        logging.info("Checking HTTP/HTTPS status of found subdomains...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(check_subdomain_http, sub): full
                for full, sub in all_subdomains.items()
            }
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                full = result["full_domain"]
                all_subdomains[full] = result
    
    # Resolve IPs for subdomains that don't have them
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2
    
    for full, sub in all_subdomains.items():
        if "ips" not in sub or not sub["ips"]:
            try:
                answers = resolver.resolve(full, 'A')
                sub["ips"] = [str(rdata) for rdata in answers]
            except Exception:
                sub["ips"] = []
    
    # Convert to list and sort
    results["subdomains"] = sorted(all_subdomains.values(), key=lambda x: x["full_domain"])
    results["total_found"] = len(results["subdomains"])
    
    # Print results
    _print_subdomain_results(results)
    
    # Write to log file if specified
    if log_file:
        _write_subdomain_log(results, log_file)
    
    logging.info(f"Subdomain enumeration completed. Found {results['total_found']} subdomains.")
    
    return results


def _print_subdomain_results(results: Dict):
    """Print subdomain enumeration results to console."""
    print("\n" + "=" * 60)
    print("           SUBDOMAIN ENUMERATION RESULTS")
    print("=" * 60)
    print(f"Target Domain : {results['domain']}")
    print(f"Timestamp     : {results['timestamp']} UTC")
    print(f"Sources Used  : {', '.join(results['sources_used'])}")
    print(f"Total Found   : {results['total_found']}")
    print("-" * 60)
    
    if results["subdomains"]:
        print(f"\n{'Subdomain':<40} {'IP(s)':<20} {'HTTP':<6} {'HTTPS':<6}")
        print("-" * 75)
        
        for sub in results["subdomains"]:
            full_domain = sub.get("full_domain", "")[:39]
            ips = ", ".join(sub.get("ips", []))[:19] if sub.get("ips") else "N/A"
            http = str(sub.get("http_status", "-"))
            https = str(sub.get("https_status", "-"))
            
            print(f"{full_domain:<40} {ips:<20} {http:<6} {https:<6}")
            
            # Print title if available
            if sub.get("http_title"):
                print(f"  └─ Title: {sub['http_title'][:60]}")
    else:
        print("\nNo subdomains found.")
    
    print("=" * 60 + "\n")


def _write_subdomain_log(results: Dict, log_file: str):
    """Write subdomain enumeration results to log file."""
    logging.info(f"Writing subdomain results to {log_file}")
    
    with open(log_file, "a") as f:
        f.write(f"\n{'=' * 60}\n")
        f.write(f"SUBDOMAIN ENUMERATION RESULTS\n")
        f.write(f"{'=' * 60}\n")
        f.write(f"Target Domain : {results['domain']}\n")
        f.write(f"Timestamp     : {results['timestamp']} UTC\n")
        f.write(f"Sources Used  : {', '.join(results['sources_used'])}\n")
        f.write(f"Total Found   : {results['total_found']}\n")
        f.write(f"{'-' * 60}\n\n")
        
        if results["subdomains"]:
            for sub in results["subdomains"]:
                f.write(f"Subdomain: {sub.get('full_domain', '')}\n")
                f.write(f"  IPs: {', '.join(sub.get('ips', [])) or 'N/A'}\n")
                f.write(f"  Source: {sub.get('source', 'N/A')}\n")
                
                if sub.get("http_status"):
                    f.write(f"  HTTP Status: {sub['http_status']}\n")
                if sub.get("https_status"):
                    f.write(f"  HTTPS Status: {sub['https_status']}\n")
                if sub.get("http_title"):
                    f.write(f"  Title: {sub['http_title']}\n")
                
                f.write("\n")
        else:
            f.write("No subdomains found.\n")
        
        f.write(f"{'=' * 60}\n")


def validate_port_range(port_string: str) -> str:
    """
    Validate and normalize port range input.
    """
    if not port_string:
        raise ValueError("Port string cannot be empty")
    
    port_string = port_string.replace(" ", "")
    parts = port_string.split(",")
    
    for part in parts:
        if "-" in part:
            range_parts = part.split("-")
            if len(range_parts) != 2:
                raise ValueError(f"Invalid port range format: {part}")
            
            try:
                start = int(range_parts[0])
                end = int(range_parts[1])
            except ValueError:
                raise ValueError(f"Invalid port numbers in range: {part}")
            
            if start < 1 or end > 65535:
                raise ValueError(f"Port numbers must be between 1-65535: {part}")
            if start > end:
                raise ValueError(f"Start port must be <= end port: {part}")
        else:
            try:
                port = int(part)
            except ValueError:
                raise ValueError(f"Invalid port number: {part}")
            
            if port < 1 or port > 65535:
                raise ValueError(f"Port number must be between 1-65535: {part}")
    
    return port_string


def port_scan(
    target_input: str,
    ports: str = "1-1000",
    scan_args: str = "-sT -Pn",
    grab_banners: bool = False,
    log_file: str | None = None
):
    """
    Performs a port scan using Nmap.
    """
    logging.info(f"Starting port scan on {target_input}")
    logging.debug(
        f"Scan config → ports={ports}, args='{scan_args}', grab_banners={grab_banners}"
    )

    try:
        validated_ports = validate_port_range(ports)
        logging.debug(f"Validated port range: {validated_ports}")
    except ValueError as e:
        logging.error(f"Invalid port specification: {e}")
        return {"error": str(e), "timestamp": datetime.datetime.utcnow().isoformat()}

    nm = nmap.PortScanner()
    timestamp = datetime.datetime.utcnow().isoformat()

    try:
        nm.scan(hosts=target_input, ports=validated_ports, arguments=scan_args)
        hosts_list = nm.all_hosts()

        logging.debug(f"Nmap returned hosts: {hosts_list}")

        if not hosts_list:
            logging.warning("No hosts responded to scan")
            result = {
                "target": target_input,
                "timestamp": timestamp,
                "ports_scanned": validated_ports,
                "status": "down/no-response"
            }
            _write_portscan_log(result, log_file)
            return result

        actual_ip = hosts_list[0]
        logging.info(f"Target is up: {actual_ip}")

        scan_results = {
            "target_input": target_input,
            "resolved_ip": actual_ip,
            "timestamp": timestamp,
            "ports_scanned": validated_ports,
            "status": "up",
            "protocols": {}
        }

        for proto in nm[actual_ip].all_protocols():
            logging.debug(f"Processing protocol: {proto}")
            scan_results["protocols"][proto] = []

            for port in sorted(nm[actual_ip][proto].keys()):
                pdata = nm[actual_ip][proto][port]
                state = pdata.get("state")
                service = pdata.get("name")

                logging.info(
                    f"{actual_ip}:{port}/{proto} → state={state}, service={service}"
                )

                port_info = {
                    "port": port,
                    "state": state,
                    "service": service
                }

                if grab_banners and state == "open":
                    logging.debug(f"Attempting banner grab on {actual_ip}:{port}")
                    banner = grab_banner(actual_ip, port)
                    if banner:
                        port_info["banner"] = banner

                scan_results["protocols"][proto].append(port_info)

        logging.info("Port scan completed successfully")

        _print_portscan_summary(scan_results)
        _write_portscan_log(scan_results, log_file)
        return scan_results

    except Exception as e:
        logging.error(f"Port scan failed: {e}", exc_info=True)
        result = {"error": str(e), "timestamp": timestamp}
        _write_portscan_log(result, log_file)
        return result


def _print_portscan_summary(data: dict):
    """Print port scan results to console."""
    print("\n=== PORT SCAN RESULTS ===")
    print(f"Target: {data['target_input']} ({data['resolved_ip']})")
    print(f"Ports Scanned: {data['ports_scanned']}")
    print(f"Status: {data['status']}")
    
    for proto, ports in data.get("protocols", {}).items():
        open_ports = [p for p in ports if p['state'] == 'open']
        if open_ports:
            print(f"\nOpen {proto.upper()} Ports:")
            for p in open_ports:
                line = f"  {p['port']}/{proto} - {p['service']}"
                if "banner" in p:
                    line += f" | Banner: {p['banner'][:50]}..."
                print(line)
    
    print("=========================\n")


def _write_portscan_log(data: dict, log_file: str | None):
    if not log_file:
        return

    logging.info(f"Writing port scan results to {log_file}")

    with open(log_file, "a") as f:
        f.write(f"\n[{data.get('timestamp')} UTC]\n")

        if data.get("status") == "down/no-response":
            f.write(f"Target: {data.get('target')}\n")
            f.write(f"Ports Scanned: {data.get('ports_scanned', 'N/A')}\n")
            f.write("Status: No response\n")
            f.write("-" * 40 + "\n")
            return

        if "error" in data:
            f.write("Port Scan Error:\n")
            f.write(f"{data['error']}\n")
            f.write("-" * 40 + "\n")
            return

        f.write(f"Target Input  : {data['target_input']}\n")
        f.write(f"Resolved IP   : {data['resolved_ip']}\n")
        f.write(f"Ports Scanned : {data['ports_scanned']}\n")
        f.write(f"Status        : {data['status']}\n")

        for proto, ports in data.get("protocols", {}).items():
            f.write(f"\n{proto.upper()} Ports:\n")
            for p in ports:
                line = f"  {p['port']}/"
                line += proto
                line += f" [{p['state']}] {p['service']}"
                if "banner" in p:
                    line += f" | Banner: {p['banner']}"
                f.write(line + "\n")

        f.write("-" * 40 + "\n")


def grab_banner(host, port, timeout=2):
    """
    Attempts to grab the banner from an open port.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        return banner if banner else None
    except (socket.timeout, socket.error, ConnectionRefusedError):
        return None
    except Exception as e:
        return None


def tech_detect(target: str):
    logging.info(f"[DUMMY] Technology detection for {target}")
    pass


def generate_report(target: str):
    logging.info(f"[DUMMY] Report generation for {target}")
    pass


# -------------------------
# Utility
# -------------------------
def resolve_ip(target: str):
    try:
        ip = socket.gethostbyname(target)
        logging.info(f"Resolved {target} to {ip}")
        return ip
    except Exception:
        logging.warning(f"Could not resolve IP for {target}")
        return None


# -------------------------
# Main
# -------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Modular Recon Tool (Intern Assignment)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Port specification examples:
  --ports 80              Single port
  --ports 1-1000          Port range
  --ports 22,80,443       Comma-separated ports
  --ports 22,80,100-200   Mixed format

Subdomain enumeration examples:
  --subdomains                          Use passive sources + default wordlist
  --subdomains --wordlist custom.txt    Use custom wordlist for brute-force
  --subdomains --passive-only           Only use passive sources (no brute-force)
  --subdomains --bruteforce-only        Only use brute-force (no passive)
  --subdomains --check-http             Check HTTP/HTTPS status of found subdomains

Examples:
  %(prog)s example.com --ports 80,443 --banner
  %(prog)s 192.168.1.1 --ports 1-65535
  %(prog)s example.com --subdomains --check-http
  %(prog)s example.com --whois --dns --subdomains --ports 1-1000 --report
        """
    )

    parser.add_argument("target", help="Target domain or IP")
    parser.add_argument("--whois", action="store_true", help="Perform WHOIS lookup")
    parser.add_argument("--dns", action="store_true", help="Perform DNS enumeration")
    
    # Subdomain enumeration options
    parser.add_argument("--subdomains", action="store_true", help="Enumerate subdomains")
    parser.add_argument("--wordlist", metavar="FILE", help="Custom wordlist for subdomain brute-force")
    parser.add_argument("--passive-only", action="store_true", help="Only use passive sources for subdomains")
    parser.add_argument("--bruteforce-only", action="store_true", help="Only use brute-force for subdomains")
    parser.add_argument("--check-http", action="store_true", help="Check HTTP/HTTPS status of subdomains")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads for brute-force (default: 10)")
    
    # Port scan options
    parser.add_argument(
        "--ports",
        nargs="?",
        const="1-1000",
        default=None,
        metavar="PORTS",
        help="Scan ports. Specify range (e.g., '1-1000', '22,80,443'). Default: 1-1000"
    )
    parser.add_argument("--banner", action="store_true", help="Grab service banners (use with --ports)")
    
    parser.add_argument("--tech", action="store_true", help="Detect technologies")
    parser.add_argument("--report", action="store_true", help="Generate report")
    parser.add_argument("--output", default="recon.log", help="Output file for report (default: recon.log)")
    parser.add_argument("-v", "--verbose", action="count", default=1, help="Increase verbosity (-v, -vv)")

    args = parser.parse_args()

    if not args.target:
        parser.print_help()
        sys.exit(1)

    setup_logging(args.verbose)

    logging.info("Recon started")
    logging.info(f"Timestamp: {datetime.datetime.utcnow().isoformat()} UTC")

    resolve_ip(args.target)

    if args.whois:
        log_file = args.output if args.report else None
        whois_lookup(args.target, log_file=log_file)

    if args.dns:
        log_file = args.output if args.report else None
        dns_enumeration(args.target, log_file=log_file)

    if args.subdomains:
        # Determine which methods to use
        use_passive = not args.bruteforce_only
        use_bruteforce = not args.passive_only
        
        log_file = args.output if args.report else None
        
        subdomain_enum(
            args.target,
            wordlist_path=args.wordlist,
            use_passive=use_passive,
            use_bruteforce=use_bruteforce,
            threads=args.threads,
            check_http=args.check_http,
            log_file=log_file
        )

    if args.ports is not None:
        log_file = args.output if args.report else None
        port_scan(
            args.target,
            ports=args.ports,
            grab_banners=args.banner,
            log_file=log_file
        )

    if args.tech:
        verbose = args.verbose >= 2
        detector = TechDetector(args.target, verbose=verbose)
        detector.run_detection()
        detector.print_results()
        if args.report:
            detector.generate_report(args.output)

    if args.report:
        generate_report(args.target)

    logging.info("Recon completed")


if __name__ == "__main__":
    main()