#!/usr/bin/env python3
"""
Sync dist/dns/naptr.json to a deSEC zone (BDXL-03, BDXL-05, REG-04).

The deSEC domain is the BDXL zone itself (config.yaml bdxl_zone), delegated from the
parent with NS records. Makes the zone's Meta:SMP NAPTR records exactly match the
generated list in one atomic bulk request: creates missing, updates changed, deletes
removed. Other RRsets are never touched.

Env: DESEC_TOKEN
  python scripts/sync_dns_desec.py --dry-run
  python scripts/sync_dns_desec.py
"""
import argparse
import json
import os
import sys
from pathlib import Path

import requests
import yaml

ROOT = Path(__file__).resolve().parent.parent
API = "https://desec.io/api/v1"


def rdata(r) -> str:
    """NAPTR record in presentation format, as the deSEC API expects it."""
    return f'{r["order"]} {r["preference"]} "{r["flags"]}" "{r["service"]}" "{r["regexp"]}" {r["replacement"]}'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--input", type=Path, default=ROOT / "dist" / "dns" / "naptr.json")
    args = ap.parse_args()

    token = os.environ.get("DESEC_TOKEN")
    if not token:
        sys.exit("DESEC_TOKEN must be set")
    zone = yaml.safe_load((ROOT / "config.yaml").read_text())["bdxl_zone"].rstrip(".").lower()
    s = requests.Session()
    s.headers.update({"Authorization": f"Token {token}", "Content-Type": "application/json"})
    url = f"{API}/domains/{zone}/rrsets/"

    wanted = {}
    for r in json.loads(args.input.read_text()):
        n = r["name"].rstrip(".").lower()
        if not n.endswith("." + zone):
            sys.exit(f"{n} is outside the BDXL zone {zone}")
        wanted[n.removesuffix("." + zone)] = r

    existing, next_url, params = {}, url, {"type": "NAPTR"}
    while next_url:
        resp = s.get(next_url, params=params)
        if resp.status_code != 200:
            sys.exit(f"deSEC list failed: {resp.status_code} {resp.text}")
        for rrset in resp.json():
            if any('"Meta:SMP"' in rec for rec in rrset["records"]):
                existing[rrset["subname"]] = rrset
        next_url, params = resp.links.get("next", {}).get("url"), None

    def changed(sub):
        w = wanted[sub]
        return existing[sub]["records"] != [rdata(w)] or existing[sub]["ttl"] != w["ttl"]

    creates = [n for n in wanted if n not in existing]
    deletes = [n for n in existing if n not in wanted]
    updates = [n for n in wanted if n in existing and changed(n)]
    print(f"NAPTR sync: +{len(creates)} ~{len(updates)} -{len(deletes)} (unchanged {len(wanted) - len(creates) - len(updates)})")
    if args.dry_run:
        for n in creates: print("  +", n)
        for n in updates: print("  ~", n)
        for n in deletes: print("  -", n)
        return

    # Empty "records" deletes an RRset; deSEC applies the whole bulk PATCH atomically.
    body = ([{"subname": n, "type": "NAPTR", "ttl": wanted[n]["ttl"], "records": [rdata(wanted[n])]}
             for n in creates + updates]
            + [{"subname": n, "type": "NAPTR", "records": []} for n in deletes])
    if body:
        resp = s.patch(url, json=body)
        if resp.status_code != 200:
            sys.exit(f"deSEC update failed: {resp.status_code} {resp.text}")
    print("done")


if __name__ == "__main__":
    main()
