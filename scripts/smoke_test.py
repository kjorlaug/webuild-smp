#!/usr/bin/env python3
"""
Sender-side conformance probe for the WE BUILD BDXL + SMP 2.0 service.

For every entry in the published index.json:
  1. BDXL U-NAPTR lookup                       (BDXL-02..04)
  2. GET ServiceMetadata, two encodings        (ID-05, ID-06, SMP-02)
  3. Content-Type is application/xml           (SMP-05)
  4. Verify XMLDSig + chain to trust anchor    (SIG-01..05, SIG-08)
  5. GET ServiceGroup (signed, redirect ok)    (SMP-04)
  6. Negative tests: unknown participant       (SMP-03, BDXL-05)

This is "the spike": run it against the live host before relying on it.

  python scripts/smoke_test.py
  python scripts/smoke_test.py --base-url http://localhost:8000 --no-dns
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import re
import sys
from pathlib import Path
from urllib.parse import quote

import requests
import yaml
from lxml import etree
from signxml import XMLVerifier

ROOT = Path(__file__).resolve().parent.parent
PREFIX = "bdxr-smp-2"
NS = {"smb": "http://docs.oasis-open.org/bdxr/ns/SMP/2/BasicComponents"}
results: list[tuple[str, bool]] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append((name, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  - {detail}" if detail else ""))
    return ok


def bdxl_host(participant: str, zone: str) -> str:
    h = base64.b32encode(hashlib.sha256(participant.lower().encode()).digest()).decode().rstrip("=")
    return f"{h.lower()}.{zone}"


def resolve_smp(participant: str, zone: str) -> str | None:
    import dns.resolver
    host = bdxl_host(participant, zone)
    try:
        answers = dns.resolver.resolve(host, "NAPTR")
    except Exception as ex:  # noqa: BLE001
        check(f"BDXL NAPTR {participant}", False, f"{host}: {ex.__class__.__name__}")
        return None
    for r in sorted(answers, key=lambda r: (r.order, r.preference)):
        if r.flags.decode().upper() == "U" and r.service.decode() == "Meta:SMP":
            m = re.match(r"^!(.*)!(.*)!$", r.regexp.decode())
            if m:
                check(f"BDXL NAPTR {participant}", True, f"-> {m.group(2)}")
                return m.group(2).rstrip("/")
    check(f"BDXL NAPTR {participant}", False, "no U / Meta:SMP record")
    return None


def is_xml_ct(r) -> bool:
    return r.headers.get("content-type", "").split(";")[0].strip() == "application/xml"


def verify(xml: bytes, ca: Path) -> tuple[bool, str]:
    try:
        XMLVerifier().verify(xml, ca_pem_file=str(ca))
        return True, "signature and chain to trust anchor OK"
    except Exception as ex:  # noqa: BLE001
        return False, f"{ex.__class__.__name__}: {ex}"


def probe(smp: str, participant: str, service: str, ca: Path):
    variants = {"full-encoded (ID-05)": (quote(participant, safe=""), quote(service, safe="")),
                "':' unencoded (ID-06)": (quote(participant, safe=":"), quote(service, safe=":")),
                "service lower-cased (ID-04)": (quote(participant, safe=""), quote(service.lower(), safe=""))}
    body = None
    for label, (pseg, sseg) in variants.items():
        url = f"{smp}/{PREFIX}/{pseg}/services/{sseg}"
        try:
            r = requests.get(url, timeout=15)
            check(f"GET ServiceMetadata {label}", r.status_code == 200,
                  f"{r.status_code} {r.headers.get('content-type', '-')}")
            if r.status_code == 200 and body is None:
                body = r.content
                check("Content-Type application/xml (SMP-05)", is_xml_ct(r), r.headers.get("content-type", "-"))
        except Exception as ex:  # noqa: BLE001
            check(f"GET ServiceMetadata {label}", False, ex.__class__.__name__)
    if body:
        doc = etree.fromstring(body)
        pid = doc.find("smb:ParticipantID", NS)
        got = f"{pid.get('schemeID')}::{pid.text}" if pid.get("schemeID") else pid.text
        check("ParticipantID matches", got.lower() == participant.lower(), got)
        check("SMPVersionID 2.0", doc.findtext("smb:SMPVersionID", namespaces=NS) == "2.0")
        check("ServiceMetadata signature (SIG)", *verify(body, ca))

    url = f"{smp}/{PREFIX}/{quote(participant, safe='')}"
    try:
        # No redirects: phoss and other SMP clients do not follow them (SMP-04)
        r = requests.get(url, timeout=15, allow_redirects=False)
        ok = r.status_code == 200 and b"ServiceGroup" in r.content
        check("GET ServiceGroup without redirect (SMP-04)", ok,
              f"{r.status_code} {r.headers.get('location', '')} {r.headers.get('content-type')}".strip())
        if ok:
            check("ServiceGroup Content-Type (SMP-05)", is_xml_ct(r), r.headers.get("content-type", "-"))
            check("ServiceGroup signature (SIG)", *verify(r.content, ca))
    except Exception as ex:  # noqa: BLE001
        check("GET ServiceGroup", False, str(ex))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", help="SMP base URL for index.json (default: config smp_base_url)")
    ap.add_argument("--no-dns", action="store_true", help="skip BDXL, use --base-url directly")
    ap.add_argument("--ca", type=Path, default=ROOT / "trust" / "webuild-smp-ca.pem")
    args = ap.parse_args()
    cfg = yaml.safe_load((ROOT / "config.yaml").read_text())
    base = (args.base_url or cfg["smp_base_url"]).rstrip("/")

    for e in requests.get(f"{base}/index.json", timeout=15).json():
        smp = base if args.no_dns else (resolve_smp(e["participant"], cfg["bdxl_zone"]) or base)
        probe(smp, e["participant"], e["service"], args.ca)

    unknown = "urn:oasis:names:tc:ebcore:partyid-type:iso6523:0192::000000000"
    r = requests.get(f"{base}/{PREFIX}/{quote(unknown, safe='')}/services/x", timeout=15)
    check("unknown participant -> 404 (SMP-03)", r.status_code == 404, str(r.status_code))
    if not args.no_dns:
        import dns.resolver
        try:
            dns.resolver.resolve(bdxl_host(unknown, cfg["bdxl_zone"]), "NAPTR")
            check("unknown participant DNS (BDXL-05)", cfg.get("bdxl_mode") == "wildcard", "resolves")
        except dns.resolver.NXDOMAIN:
            check("unknown participant DNS (BDXL-05)", cfg.get("bdxl_mode", "explicit") == "explicit", "NXDOMAIN")

    failed = sum(1 for _, ok in results if not ok)
    print(f"\n{len(results) - failed}/{len(results)} checks passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
