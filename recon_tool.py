#!/usr/bin/env python3
"""
WHOIS & DNS Information Gathering Tool
----------------------------------------
A simple recon script for domain reconnaissance during authorized
security assessments / lab work.

Usage:
    python3 recon_tool.py example.com
    python3 recon_tool.py example.com --json
    python3 recon_tool.py example.com -o report.txt

Requires:
    pip install python-whois dnspython
"""

import sys
import json
import argparse
import socket
from datetime import datetime

import whois
import dns.resolver
import dns.reversename


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV"]


def banner(domain):
    line = "=" * 60
    return f"{line}\n WHOIS & DNS RECON REPORT\n Target : {domain}\n Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n{line}"


def get_whois(domain):
    """Fetch WHOIS registration data for a domain."""
    try:
        data = whois.whois(domain)
        # Normalize into a clean dict (whois lib returns odd types sometimes)
        result = {}
        for key, value in data.items():
            if value is None:
                continue
            if isinstance(value, list):
                value = [str(v) for v in value]
            else:
                value = str(value)
            result[key] = value
        return result
    except Exception as e:
        return {"error": f"WHOIS lookup failed: {e}"}


def get_dns_records(domain):
    """Query common DNS record types for a domain."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    records = {}
    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            records[rtype] = [rdata.to_text() for rdata in answers]
        except dns.resolver.NoAnswer:
            records[rtype] = []
        except dns.resolver.NXDOMAIN:
            records[rtype] = ["DOMAIN DOES NOT EXIST"]
            break
        except dns.exception.Timeout:
            records[rtype] = ["TIMEOUT"]
        except Exception as e:
            records[rtype] = [f"error: {e}"]
    return records


def get_reverse_dns(ip):
    """Resolve PTR record for an IP address."""
    try:
        rev_name = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev_name, "PTR")
        return [rdata.to_text() for rdata in answers]
    except Exception as e:
        return [f"error: {e}"]


def resolve_ip(domain):
    """Get the primary IP of a domain via plain socket resolution."""
    try:
        return socket.gethostbyname(domain)
    except Exception as e:
        return f"error: {e}"


def format_text_report(domain, whois_data, dns_data, ip, ptr):
    out = [banner(domain)]

    out.append("\n[+] PRIMARY IP ADDRESS")
    out.append(f"    {ip}")

    out.append("\n[+] REVERSE DNS (PTR)")
    if ptr:
        for p in ptr:
            out.append(f"    {p}")
    else:
        out.append("    None found")

    out.append("\n[+] DNS RECORDS")
    for rtype, values in dns_data.items():
        out.append(f"    {rtype}:")
        if values:
            for v in values:
                out.append(f"        {v}")
        else:
            out.append("        (none)")

    out.append("\n[+] WHOIS DATA")
    if "error" in whois_data:
        out.append(f"    {whois_data['error']}")
    else:
        # Print the most useful fields first, if present
        priority_fields = [
            "domain_name", "registrar", "whois_server", "creation_date",
            "expiration_date", "updated_date", "name_servers", "status",
            "emails", "org", "name", "country"
        ]
        printed = set()
        for field in priority_fields:
            if field in whois_data:
                out.append(f"    {field:15}: {whois_data[field]}")
                printed.add(field)
        # Print anything else not already covered
        for field, value in whois_data.items():
            if field not in printed:
                out.append(f"    {field:15}: {value}")

    out.append("\n" + "=" * 60)
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(
        description="WHOIS & DNS information gathering tool for domain recon."
    )
    parser.add_argument("domain", help="Target domain (e.g. example.com)")
    parser.add_argument(
        "--json", action="store_true",
        help="Output raw results as JSON instead of formatted text"
    )
    parser.add_argument(
        "-o", "--output", metavar="FILE",
        help="Write report to a file instead of only printing to stdout"
    )
    args = parser.parse_args()

    domain = args.domain.strip().lower()
    domain = domain.replace("http://", "").replace("https://", "").split("/")[0]

    print(f"[*] Gathering WHOIS data for {domain} ...")
    whois_data = get_whois(domain)

    print(f"[*] Querying DNS records ...")
    dns_data = get_dns_records(domain)

    print(f"[*] Resolving IP address ...")
    ip = resolve_ip(domain)

    ptr = []
    if ip and not str(ip).startswith("error"):
        print(f"[*] Performing reverse DNS lookup on {ip} ...")
        ptr = get_reverse_dns(ip)

    if args.json:
        combined = {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "ip": ip,
            "reverse_dns": ptr,
            "dns_records": dns_data,
            "whois": whois_data,
        }
        report = json.dumps(combined, indent=2)
    else:
        report = format_text_report(domain, whois_data, dns_data, ip, ptr)

    print("\n" + report)

    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(f"\n[*] Report saved to {args.output}")


if __name__ == "__main__":
    main()
