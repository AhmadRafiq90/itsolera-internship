#!/usr/bin/env python3

import argparse
import logging
import datetime
import socket
import nmap
import sys
import json
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
# WHOIS Lookup (REAL)
# -------------------------
def whois_lookup(domain: str):
    """
    Perform a WHOIS lookup for the given domain.
    """
    logging.info(f"Starting WHOIS lookup for {domain}")

    if whois is None:
        logging.error("python-whois module not installed")
        return

    try:
        result = whois.whois(domain)

        print("\n=== WHOIS INFORMATION ===")
        print(f"Domain Name   : {result.domain_name}")
        print(f"Registrar     : {result.registrar}")
        print(f"Creation Date : {result.creation_date}")
        print(f"Expiry Date   : {result.expiration_date}")
        print(f"Name Servers  : {result.name_servers}")
        print("=========================\n")

        logging.debug(f"Raw WHOIS data: {result}")

    except Exception as e:
        logging.error(f"WHOIS lookup failed: {e}")


# -------------------------
# Dummy Recon Functions
# -------------------------
def dns_enum(domain: str):
    logging.info(f"[DUMMY] DNS enumeration for {domain}")
    pass


def subdomain_enum(domain: str):
    logging.info(f"[DUMMY] Subdomain enumeration for {domain}")
    pass


def port_scan(target_input: str,ports="1-1000", scan_args="-sT -Pn", grab_banners=False):
    logging.info(f"[DUMMY] Port scanning for {target_input}")
    """
    Performs a port scan using Nmap.
    Returns structured data including resolved IP, open ports, and service names.
    """
    nm = nmap.PortScanner()
    
    start_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    print(f"[*] Starting Scan at {start_time}")
    print(f"[*] Target: {target_input} | Ports: {ports} | Args: {scan_args}")
    
    try:
        nm.scan(hosts=target_input, ports=ports, arguments=scan_args)
        hosts_list = nm.all_hosts()

        if not hosts_list:
             return {
                 "target": target_input, 
                 "timestamp": start_time,
                 "status": "down/no-response"
             }

        actual_ip = hosts_list[0]
        
        scan_results = {
            "target_input": target_input,
            "resolved_ip": actual_ip,
            "timestamp": start_time,
            "status": "up",
            "protocols": {}
        }

        for proto in nm[actual_ip].all_protocols():
            scan_results["protocols"][proto] = []
            
            lport = nm[actual_ip][proto].keys()
            for port in sorted(lport):
                state = nm[actual_ip][proto][port]['state']
                service = nm[actual_ip][proto][port]['name']
                
                port_info = {
                    "port": port,
                    "state": state,
                    "service": service
                }

                # Grab banner if flag is enabled and port is open
                if grab_banners and state == "open":
                    banner = grab_banner(actual_ip, port)
                    if banner:
                        port_info["banner"] = banner

                scan_results["protocols"][proto].append(port_info)
        
        return scan_results

    except Exception as e:
        return {"error": str(e)}
    pass


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
        whois_lookup(args.target)

    if args.dns:
        dns_enum(args.target)

    if args.subdomains:
        subdomain_enum(args.target)

    if args.ports:
        if args.banner:
            port_scan(args.target, grab_banners=True)
        else:
            port_scan(args.target)

    if args.tech:
        detector = TechDetector(args.target, verbose=args.verbose)
        detector.run_detection()
        detector.print_results()
        detector.generate_report(args.output)

    if args.report:
        generate_report(args.target)

    logging.info("Recon completed")


if __name__ == "__main__":
    main()
