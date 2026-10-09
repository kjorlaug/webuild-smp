#!/usr/bin/env python3
"""
Wait until every authoritative nameserver of the BDXL zone serves the NAPTR records
in dist/dns/naptr.json (BDXL-03).

Run after a DNS sync, before the smoke test. Asking the authoritative servers directly
keeps resolvers from caching an NXDOMAIN for a record the provider has not published
yet (negative TTL = SOA minimum, typically an hour).

  python scripts/wait_dns.py [--timeout 600]
"""
import argparse
import json
import sys
import time
from pathlib import Path

import dns.message
import dns.query
import dns.rdatatype
import dns.resolver
import yaml

ROOT = Path(__file__).resolve().parent.parent


def rdata(r) -> str:
    return f'{r["order"]} {r["preference"]} "{r["flags"]}" "{r["service"]}" "{r["regexp"]}" {r["replacement"]}'


def served(server: str, name: str, want: str) -> bool:
    try:
        resp = dns.query.udp(dns.message.make_query(name, "NAPTR"), server, timeout=5)
    except Exception:  # noqa: BLE001 - timeouts and network errors: try again next round
        return False
    return any(rr.to_text() == want for rrset in resp.answer
               if rrset.rdtype == dns.rdatatype.NAPTR for rr in rrset)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", type=Path, default=ROOT / "dist" / "dns" / "naptr.json")
    ap.add_argument("--timeout", type=int, default=600)
    args = ap.parse_args()

    zone = yaml.safe_load((ROOT / "config.yaml").read_text())["bdxl_zone"].rstrip(".")
    servers = {ns.target.to_text(): dns.resolver.resolve(ns.target, "A")[0].address
               for ns in dns.resolver.resolve(zone, "NS")}
    pending = {(ns, r["name"]): rdata(r) for r in json.loads(args.input.read_text()) for ns in servers}
    print(f"Waiting for {len(pending)} NAPTR answer(s) from {', '.join(sorted(servers))}")

    start = time.monotonic()
    while pending:
        pending = {k: v for k, v in pending.items() if not served(servers[k[0]], k[1], v)}
        if not pending:
            break
        if time.monotonic() - start > args.timeout:
            for ns, name in sorted(pending):
                print(f"  not served by {ns}: {name}", file=sys.stderr)
            sys.exit(f"{len(pending)} NAPTR answer(s) still missing after {args.timeout}s")
        time.sleep(15)
    print(f"All NAPTR records served after {time.monotonic() - start:.0f}s")


if __name__ == "__main__":
    main()
