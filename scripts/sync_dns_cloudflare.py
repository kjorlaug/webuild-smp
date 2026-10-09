#!/usr/bin/env python3
"""
Sync dist/dns/naptr.json to a Cloudflare DNS zone (BDXL-03, BDXL-05, REG-04).

Makes the zone's Meta:SMP NAPTR records under the BDXL zone exactly match
the generated list: creates missing, updates changed, deletes removed.
Records that are not Meta:SMP NAPTR, or are outside the BDXL zone, are never touched.

Env: CLOUDFLARE_API_TOKEN (Zone.DNS edit), CLOUDFLARE_ZONE_ID
  python scripts/sync_dns_cloudflare.py --dry-run
  python scripts/sync_dns_cloudflare.py

Another DNS provider: replace this script. The input format (naptr.json /
naptr.zone) stays the same.
"""
import argparse
import json
import os
import sys
from pathlib import Path

import requests
import yaml

ROOT = Path(__file__).resolve().parent.parent
API = "https://api.cloudflare.com/client/v4"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--input", type=Path, default=ROOT / "dist" / "dns" / "naptr.json")
    args = ap.parse_args()

    token, zone_id = os.environ.get("CLOUDFLARE_API_TOKEN"), os.environ.get("CLOUDFLARE_ZONE_ID")
    if not token or not zone_id:
        sys.exit("CLOUDFLARE_API_TOKEN and CLOUDFLARE_ZONE_ID must be set")
    bdxl_zone = yaml.safe_load((ROOT / "config.yaml").read_text())["bdxl_zone"].rstrip(".").lower()
    s = requests.Session()
    s.headers.update({"Authorization": f"Bearer {token}", "Content-Type": "application/json"})

    wanted = {r["name"].lower(): r for r in json.loads(args.input.read_text())}

    existing, page = {}, 1
    while True:
        resp = s.get(f"{API}/zones/{zone_id}/dns_records",
                     params={"type": "NAPTR", "per_page": 500, "page": page}).json()
        if not resp.get("success"):
            sys.exit(f"Cloudflare list failed: {resp.get('errors')}")
        for rec in resp["result"]:
            n = rec["name"].lower()
            if (n.endswith("." + bdxl_zone) and rec.get("data", {}).get("service") == "Meta:SMP"):
                existing[n] = rec
        if page >= resp["result_info"]["total_pages"]:
            break
        page += 1

    def body(r):
        return {"type": "NAPTR", "name": r["name"], "ttl": r["ttl"],
                "data": {"order": r["order"], "preference": r["preference"], "flags": r["flags"],
                         "service": r["service"], "regex": r["regexp"], "replacement": r["replacement"]}}

    creates = [n for n in wanted if n not in existing]
    deletes = [n for n in existing if n not in wanted]
    updates = [n for n in wanted if n in existing and (
        existing[n]["data"].get("regex") != wanted[n]["regexp"] or existing[n]["ttl"] != wanted[n]["ttl"])]
    print(f"NAPTR sync: +{len(creates)} ~{len(updates)} -{len(deletes)} (unchanged {len(wanted) - len(creates) - len(updates)})")
    if args.dry_run:
        for n in creates: print("  +", n)
        for n in updates: print("  ~", n)
        for n in deletes: print("  -", n)
        return

    for n in creates:
        r = s.post(f"{API}/zones/{zone_id}/dns_records", json=body(wanted[n])).json()
        if not r.get("success"): sys.exit(f"create {n}: {r.get('errors')}")
    for n in updates:
        r = s.put(f"{API}/zones/{zone_id}/dns_records/{existing[n]['id']}", json=body(wanted[n])).json()
        if not r.get("success"): sys.exit(f"update {n}: {r.get('errors')}")
    for n in deletes:
        r = s.delete(f"{API}/zones/{zone_id}/dns_records/{existing[n]['id']}").json()
        if not r.get("success"): sys.exit(f"delete {n}: {r.get('errors')}")
    print("done")


if __name__ == "__main__":
    main()
