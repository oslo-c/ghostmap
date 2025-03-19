#!/usr/bin/env python3
import argparse
import json
import os
import socket
import sys
import logging
import requests

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

CONFIG_FILE = os.path.expanduser("~/.ghostmap_config.json")

def save_config(shodan_key):
    config = {"shodan_key": shodan_key}
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f)
        logging.info(f"Shodan API key saved in {CONFIG_FILE}")
    except Exception as e:
        logging.error(f"Error saving config: {e}")

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Error reading config: {e}")
    return {}

def query_crt(domain):
    """
    Query crt.sh for the given domain and extract unique subdomains.
    """
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raises HTTPError for bad responses
    except requests.exceptions.RequestException as e:
        logging.error(f"Error connecting to crt.sh: {e}")
        return []
    
    try:
        data = response.json()
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from crt.sh: {e}")
        return []
    
    subdomains = set()
    for entry in data:
        names = entry.get("name_value", "")
        for name in names.splitlines():
            if '*' in name:
                continue
            subdomains.add(name.strip())
    return list(subdomains)

def resolve_domain(domain):
    """
    Resolve the domain to get its associated IP addresses.
    """
    try:
        _, _, ip_addresses = socket.gethostbyname_ex(domain)
        return ip_addresses
    except socket.gaierror as e:
        logging.error(f"Error resolving {domain}: {e}")
        return []
    except Exception as e:
        logging.error(f"Unexpected error resolving {domain}: {e}")
        return []

def query_shodan(ip, shodan_key):
    """
    Query Shodan for host information for the given IP.
    """
    url = f"https://api.shodan.io/shodan/host/{ip}?key={shodan_key}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error connecting to Shodan for {ip}: {e}")
        return None

    try:
        return response.json()
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from Shodan for {ip}: {e}")
        return None

def run_scan(args):
    results = {"domain": args.domain}

    # Perform crt.sh subdomain enumeration if requested
    if args.crt:
        logging.info(f"Querying crt.sh for subdomains of {args.domain} ...")
        subdomains = query_crt(args.domain)
        results["subdomains"] = subdomains
        logging.info(f"Found {len(subdomains)} unique subdomains.")
    else:
        subdomains = [args.domain]

    # Determine which Shodan API key to use
    shodan_key = args.shodan_key
    if args.shodan:
        if not shodan_key:
            config = load_config()
            shodan_key = config.get("shodan_key")
        if not shodan_key:
            logging.error("Shodan API key is required. Please run 'init' command or provide --shodan-key.")
            sys.exit(1)

    # If Shodan flag is set, query each resolved IP
    if args.shodan:
        shodan_data = {}
        for sub in subdomains:
            logging.info(f"Resolving {sub} ...")
            ips = resolve_domain(sub)
            if not ips:
                continue
            for ip in ips:
                logging.info(f"Querying Shodan for {ip} ...")
                data = query_shodan(ip, shodan_key)
                if data:
                    shodan_data[ip] = data
        results["shodan"] = shodan_data

    # Output results in JSON format either to stdout or to a file
    output_str = json.dumps(results, indent=2)
    if args.output:
        try:
            with open(args.output, "w") as f:
                f.write(output_str)
            logging.info(f"Results saved to {args.output}")
        except Exception as e:
            logging.error(f"Error writing to file {args.output}: {e}")
    else:
        print("\n=== Results ===")
        print(output_str)

def main():
    parser = argparse.ArgumentParser(
        description="GhostMap: Mapping the Digital Shadows"
    )
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # 'init' sub-command: prompt the user to input their Shodan API key
    subparsers.add_parser("init", help="Store your Shodan API key for future use.")

    # 'scan' sub-command: run crt.sh and/or Shodan queries
    parser_scan = subparsers.add_parser("scan", help="Run OSINT scans using crt.sh and Shodan.")
    parser_scan.add_argument("--domain", "-d", required=True, help="Target domain (e.g. example.com)")
    parser_scan.add_argument("--crt", action="store_true", help="Query crt.sh for subdomains")
    parser_scan.add_argument("--shodan", action="store_true", help="Query Shodan for each resolved IP")
    parser_scan.add_argument("--shodan-key", help="Optional: override stored Shodan API key")
    parser_scan.add_argument("--output", "-o", help="Output file to save JSON results")

    args = parser.parse_args()

    if args.command == "init":
        key = input("Enter your Shodan API key: ").strip()
        if key:
            save_config(key)
        else:
            logging.error("No key entered. Exiting.")
    elif args.command == "scan":
        run_scan(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
