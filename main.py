#!/usr/bin/env python3
import argparse
import json
import os
import socket
import sys
import requests

CONFIG_FILE = os.path.expanduser("~/.osint_tool_config.json")

def save_config(shodan_key):
    config = {"shodan_key": shodan_key}
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f)
        print(f"[+] Shodan API key saved in {CONFIG_FILE}")
    except Exception as e:
        print(f"Error saving config: {e}")

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            print(f"Error reading config: {e}")
    return {}

def query_crt(domain):
    """
    Query crt.sh for the given domain and extract unique subdomains.
    """
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            print(f"Error: Received status code {response.status_code} from crt.sh")
            return []
        data = response.json()
        subdomains = set()
        for entry in data:
            names = entry.get("name_value", "")
            for name in names.splitlines():
                if '*' in name:
                    continue
                subdomains.add(name.strip())
        return list(subdomains)
    except Exception as e:
        print(f"Error querying crt.sh: {e}")
        return []

def resolve_domain(domain):
    """
    Resolve the domain to get its associated IP addresses.
    """
    try:
        _, _, ip_addresses = socket.gethostbyname_ex(domain)
        return ip_addresses
    except Exception as e:
        print(f"Error resolving {domain}: {e}")
        return []

def query_shodan(ip, shodan_key):
    """
    Query Shodan for host information for the given IP.
    """
    url = f"https://api.shodan.io/shodan/host/{ip}?key={shodan_key}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error: Received status code {response.status_code} for IP {ip}")
            return None
    except Exception as e:
        print(f"Error querying Shodan for {ip}: {e}")
        return None

def run_scan(args):
    results = {"domain": args.domain}

    # If crt.sh flag is set, perform subdomain enumeration
    if args.crt:
        print(f"[+] Querying crt.sh for subdomains of {args.domain} ...")
        subdomains = query_crt(args.domain)
        results["subdomains"] = subdomains
        print(f"[+] Found {len(subdomains)} unique subdomains.")
    else:
        subdomains = [args.domain]

    # Determine which Shodan API key to use
    shodan_key = args.shodan_key
    if args.shodan:
        if not shodan_key:
            config = load_config()
            shodan_key = config.get("shodan_key")
        if not shodan_key:
            print("Error: Shodan API key is required. Please run 'init' command or provide --shodan-key.")
            sys.exit(1)

    # If Shodan flag is set, query each resolved IP
    if args.shodan:
        shodan_data = {}
        for sub in subdomains:
            print(f"[+] Resolving {sub} ...")
            ips = resolve_domain(sub)
            if not ips:
                continue
            for ip in ips:
                print(f"[+] Querying Shodan for {ip} ...")
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
            print(f"[+] Results saved to {args.output}")
        except Exception as e:
            print(f"Error writing to file {args.output}: {e}")
    else:
        print("\n=== Results ===")
        print(output_str)

def main():
    parser = argparse.ArgumentParser(
        description="OSINT Tool: Combine crt.sh and Shodan queries in one tool."
    )
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # 'init' sub-command: prompt the user to input their Shodan API key
    parser_init = subparsers.add_parser("init", help="Store your Shodan API key for future use.")

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
            print("No key entered. Exiting.")
    elif args.command == "scan":
        run_scan(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
