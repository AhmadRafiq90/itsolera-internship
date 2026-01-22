#!/usr/bin/env python3

import argparse
import logging
import datetime
import socket
import nmap
import sys
import json
import dns.resolver
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


def subdomain_enum(domain: str):
    logging.info(f"[DUMMY] Subdomain enumeration for {domain}")
    pass

def port_scan(
    target_input: str,
    ports="1-1000",
    scan_args="-sT -Pn",
    grab_banners=False,
    log_file: str | None = None
):
    """
    Performs a port scan using Nmap.
    Returns structured data including resolved IP, open ports, and service names.
    """
    logging.info(f"Starting port scan on {target_input}")
    logging.debug(
        f"Scan config → ports={ports}, args='{scan_args}', grab_banners={grab_banners}"
    )

    nm = nmap.PortScanner()
    timestamp = datetime.datetime.utcnow().isoformat()

    try:
        nm.scan(hosts=target_input, ports=ports, arguments=scan_args)
        hosts_list = nm.all_hosts()

        logging.debug(f"Nmap returned hosts: {hosts_list}")

        if not hosts_list:
            logging.warning("No hosts responded to scan")
            result = {
                "target": target_input,
                "timestamp": timestamp,
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

                logging.debug(
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

        _write_portscan_log(scan_results, log_file)
        return scan_results

    except Exception as e:
        logging.error(f"Port scan failed: {e}", exc_info=True)
        result = {"error": str(e), "timestamp": timestamp}
        _write_portscan_log(result, log_file)
        return result

def _write_portscan_log(data: dict, log_file: str | None):
    if not log_file:
        return

    logging.info(f"Writing port scan results to {log_file}")

    with open(log_file, "a") as f:
        f.write(f"\n[{data.get('timestamp')} UTC]\n")

        if data.get("status") == "down/no-response":
            f.write(f"Target: {data.get('target')}\n")
            f.write("Status: No response\n")
            f.write("-" * 40 + "\n")
            return

        if "error" in data:
            f.write("Port Scan Error:\n")
            f.write(f"{data['error']}\n")
            f.write("-" * 40 + "\n")
            return

        f.write(f"Target Input : {data['target_input']}\n")
        f.write(f"Resolved IP  : {data['resolved_ip']}\n")
        f.write(f"Status       : {data['status']}\n")

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
    Returns the banner string or None if unable to grab.
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
        description="Modular Recon Tool (Intern Assignment)"
    )

    parser.add_argument("target", help="Target domain or IP")
    parser.add_argument("--whois", action="store_true", help="Perform WHOIS lookup")
    parser.add_argument("--dns", action="store_true", help="Perform DNS enumeration")
    parser.add_argument("--subdomains", action="store_true", help="Enumerate subdomains")
    parser.add_argument("--ports", action="store_true", help="Scan ports")
    parser.add_argument("--banner", action="store_true", help="Grab service banners")
    parser.add_argument("--tech", action="store_true", help="Detect technologies")
    parser.add_argument("--report", action="store_true", help="Generate report")
    parser.add_argument("-v", "--verbose", action="count", default=0)

    args = parser.parse_args()

    if not args.target:
        parser.print_help()
        sys.exit(1)

    setup_logging(args.verbose)

    logging.info("Recon started")
    logging.info(f"Timestamp: {datetime.datetime.utcnow().isoformat()} UTC")

    resolve_ip(args.target)

    if args.whois:
        if args.report:
            whois_lookup(args.target, log_file="recon.log")
        else:
            whois_lookup(args.target)

    if args.dns:
        if args.report:
            dns_enumeration(args.target, log_file="recon.log")
        else:
            dns_enumeration(args.target)

    if args.subdomains:
        subdomain_enum(args.target)

    if args.ports:
        if args.banner:
            if args.report:
                port_scan(args.target, grab_banners=True, log_file="recon.log")
            else:
                port_scan(args.target, grab_banners=True)
        else:
            if args.report:
                port_scan(args.target, log_file="recon.log")
            else:
                port_scan(args.target)

    if args.tech:
        if args.verbose == 1:
            detector = TechDetector(args.target, verbose=False)
        else:
            detector = TechDetector(args.target, verbose=True)
        detector.run_detection()
        detector.print_results()
        if args.report:
            detector.generate_report(args.output)

    if args.report:
        generate_report(args.target)

    logging.info("Recon completed")


if __name__ == "__main__":
    main()
