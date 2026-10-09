#!/usr/bin/env python3
"""
WE BUILD SMP 2.0 / BDXL registry builder.

Reads YAML participant records from registry/participants/, validates them,
generates OASIS SMP 2.0 XML (ServiceGroup + ServiceMetadata), signs both, and writes:

  dist/site/   static site (Cloudflare Pages / Netlify / GitHub Pages)
  dist/dns/    BDXL U-NAPTR records (zone-file snippet + JSON for API sync)

Usage:
  python scripts/build.py --validate-only
  python scripts/build.py --key smp.key.pem --cert smp.cert.pem [--xsd-dir xsd/]
  python scripts/build.py --ephemeral-key      # PR builds: throwaway self-signed key

Requirement IDs in comments refer to the WE BUILD SMP/BDXL Conformance Specification.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import shutil
import sys
from pathlib import Path
from urllib.parse import quote

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from jsonschema import Draft202012Validator
from lxml import etree
from signxml import XMLSigner, XMLVerifier, methods
from signxml.algorithms import CanonicalizationMethod, DigestAlgorithm, SignatureMethod

ROOT = Path(__file__).resolve().parent.parent
RESOURCE_PREFIX = "bdxr-smp-2"                                   # SMP 2.0 REST binding path
NS_SG = "http://docs.oasis-open.org/bdxr/ns/SMP/2/ServiceGroup"
NS_SM = "http://docs.oasis-open.org/bdxr/ns/SMP/2/ServiceMetadata"
NS_SMB = "http://docs.oasis-open.org/bdxr/ns/SMP/2/BasicComponents"
NS_SMA = "http://docs.oasis-open.org/bdxr/ns/SMP/2/AggregateComponents"
NS_EXT = "http://docs.oasis-open.org/bdxr/ns/SMP/2/ExtensionComponents"
SMP_VERSION = "2.0"


# --------------------------------------------------------------------------
# Identifiers (spec section 4)
# --------------------------------------------------------------------------
def full_id(ident: dict) -> str:
    """'{scheme}::{value}', or just '{value}' when there is no scheme (SMP 2.0 §5.3)."""
    return f"{ident['scheme']}::{ident['value']}" if ident.get("scheme") else ident["value"]


def norm_participant(p: dict) -> dict:
    """ID-01/ID-02: participant scheme and value are compared in lower case."""
    out = {"value": p["value"].lower()}
    if p.get("scheme"):
        out["scheme"] = p["scheme"].lower()
    return out


def encode_segment(ident: dict) -> str:
    """ID-05: each path segment percent-encoded individually; nothing left unencoded."""
    return quote(full_id(ident), safe="")


def bdxl_label(p: dict) -> str:
    """BDXL-02: base32(sha256(lower('{scheme}::{value}'))) without '=' padding."""
    digest = hashlib.sha256(full_id(norm_participant(p)).encode("utf-8")).digest()
    return base64.b32encode(digest).decode("ascii").rstrip("=").lower()


# --------------------------------------------------------------------------
# Loading and validation (REG-01, REG-02, REG-05)
# --------------------------------------------------------------------------
def load_config() -> dict:
    return yaml.safe_load((ROOT / "config.yaml").read_text(encoding="utf-8"))


def load_schema() -> dict:
    return json.loads((ROOT / "schema" / "record.schema.json").read_text(encoding="utf-8"))


def load_records() -> list[tuple[Path, dict]]:
    return [(p, yaml.safe_load(p.read_text(encoding="utf-8")))
            for p in sorted((ROOT / "registry" / "participants").rglob("*.y*ml"))]


def load_cert(ref: str, record_path: Path):
    """Endpoint certificate: inline PEM, or a path relative to the record or repo root."""
    if "-----BEGIN CERTIFICATE-----" in ref:
        pem = ref.encode()
    else:
        p = record_path.parent / ref
        pem = (p if p.exists() else ROOT / ref).read_bytes()
    cert = x509.load_pem_x509_certificate(pem)
    return cert.public_bytes(serialization.Encoding.DER), cert


def parse_date(v) -> dt.date:
    if isinstance(v, dt.datetime):
        return v.date()
    if isinstance(v, dt.date):
        return v
    return dt.date.fromisoformat(str(v)[:10])


def check_crl(config, signing_cert_pem: bytes | None = None) -> list[str]:
    """SIG-09: CRL signed by the trust anchor, not past nextUpdate, signing cert not revoked."""
    crl_path, ta_path = ROOT / config.get("crl_file", ""), ROOT / config.get("trust_anchor_file", "")
    if not config.get("crl_file") or not crl_path.is_file():
        return [f"SIG-09: CRL file {config.get('crl_file')!r} missing"]
    crl = x509.load_der_x509_crl(crl_path.read_bytes())
    ta = x509.load_pem_x509_certificate(ta_path.read_bytes())
    errors = []
    if not crl.is_signature_valid(ta.public_key()):
        errors.append(f"SIG-09: {config['crl_file']} is not signed by {config['trust_anchor_file']}")
    days_left = (crl.next_update_utc - dt.datetime.now(dt.timezone.utc)).days
    if days_left < 0:
        errors.append(f"SIG-09: CRL expired {crl.next_update_utc:%Y-%m-%d}; re-sign it (make_test_pki.py --crl-only)")
    elif days_left < 30:
        print(f"::warning::CRL nextUpdate {crl.next_update_utc:%Y-%m-%d} is in {days_left} days; "
              f"re-sign it (make_test_pki.py --crl-only)", file=sys.stderr)
    if signing_cert_pem:
        cert = x509.load_pem_x509_certificate(signing_cert_pem)
        if crl.get_revoked_certificate_by_serial_number(cert.serial_number) is not None:
            errors.append(f"SIG-09: the signing certificate (serial {cert.serial_number:x}) is revoked")
        try:
            dps = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
            urls = [n.value for dp in dps for n in (dp.full_name or [])]
        except x509.ExtensionNotFound:
            urls = []
        want = f"{config['smp_base_url'].rstrip('/')}/trust/webuild-smp-ca.crl"
        if want not in urls:
            errors.append(f"SIG-09: signing certificate has no CRL distribution point {want} (has {urls})")
    return errors


def validate(records, config, schema) -> list[str]:
    errors: list[str] = []
    validator = Draft202012Validator(schema)
    profiles = set(config["transport_profiles"])
    pilot_end = parse_date(config["pilot_end_date"])
    today = dt.date.today()
    seen: dict[str, Path] = {}

    for path, rec in records:
        where = path.relative_to(ROOT)
        schema_errors = [f"{where}: schema: {'/'.join(map(str, e.path))} {e.message}"
                         for e in validator.iter_errors(rec)]
        if schema_errors:
            errors += schema_errors
            continue

        p = rec["participant"]
        if p["value"] != p["value"].lower() or (p.get("scheme") or "") != (p.get("scheme") or "").lower():
            errors.append(f"{where}: participant scheme and value must be lower case (ID-01)")
        if p.get("scheme") and p["scheme"] not in config["participant_schemes"]:
            errors.append(f"{where}: participant scheme {p['scheme']} not allowed (ID-03)")
        key = full_id(norm_participant(p))
        if key in seen:
            errors.append(f"{where}: duplicate participant, also in {seen[key].relative_to(ROOT)}")
        seen[key] = path
        # +5: the ServiceGroup is also stored as '{participant}.html'
        if len(encode_segment(norm_participant(p)).encode()) + 5 > 255:
            errors.append(f"{where}: encoded participant identifier exceeds 250 bytes")

        service_keys = set()
        for s in rec["services"]:
            sk = full_id(s["service"])
            if sk in service_keys:
                errors.append(f"{where}: duplicate service {sk}")
            service_keys.add(sk)
            # Static hosting stores each identifier as one file name; most filesystems cap at 255 bytes.
            if len(encode_segment(s["service"]).encode()) > 255:
                errors.append(f"{where}: encoded service identifier exceeds 255 bytes "
                              f"and cannot be a static file name ({sk[:60]}...)")
            for pm in s["processMetadata"]:
                for ep in pm["endpoints"]:
                    if ep["transportProfile"] not in profiles:                      # TP-01
                        errors.append(f"{where}: unknown transport profile {ep['transportProfile']} (TP-01)")
                    for c in ep.get("certificates", []):
                        try:
                            _, cert = load_cert(c["certificate"], path)
                            if cert.not_valid_after_utc.date() < today:
                                errors.append(f"{where}: endpoint certificate expired "
                                              f"{cert.not_valid_after_utc:%Y-%m-%d}")
                        except Exception as ex:  # noqa: BLE001
                            errors.append(f"{where}: cannot read endpoint certificate: {ex}")
                    exp = parse_date(ep["expirationDate"])
                    act = parse_date(ep.get("activationDate", today))
                    if exp < today:
                        errors.append(f"{where}: expirationDate is in the past (REG-05)")
                    if exp > pilot_end:
                        errors.append(f"{where}: expirationDate after pilot end {pilot_end} (REG-05)")
                    if act > exp:
                        errors.append(f"{where}: activationDate after expirationDate")
    return errors


# --------------------------------------------------------------------------
# XML generation (spec section 6)
# --------------------------------------------------------------------------
def root_el(ns: str, tag: str):
    return etree.Element(f"{{{ns}}}{tag}",
                         nsmap={None: ns, "smb": NS_SMB, "sma": NS_SMA, "ext": NS_EXT})


def sub(parent, ns, tag, text=None, **attrs):
    el = etree.SubElement(parent, f"{{{ns}}}{tag}")
    for k, v in attrs.items():
        el.set(k, v)
    if text is not None:
        el.text = text
    return el


def id_el(parent, tag, ident):
    attrs = {"schemeID": ident["scheme"]} if ident.get("scheme") else {}
    return sub(parent, NS_SMB, tag, ident["value"], **attrs)


def process_el(parent, proc):
    pe = sub(parent, NS_SMA, "Process")
    id_el(pe, "ID", proc)
    for role in proc.get("roles", []):
        id_el(pe, "RoleID", role)


def service_group(rec):
    p = norm_participant(rec["participant"])
    sg = root_el(NS_SG, "ServiceGroup")
    sub(sg, NS_SMB, "SMPVersionID", SMP_VERSION)
    id_el(sg, "ParticipantID", p)
    for s in rec["services"]:
        ref = sub(sg, NS_SMA, "ServiceReference")
        id_el(ref, "ID", s["service"])
        for pm in s["processMetadata"]:
            if pm.get("process"):
                process_el(ref, pm["process"])
    return sg


def service_metadata(rec, service, record_path: Path):
    p = norm_participant(rec["participant"])
    sm = root_el(NS_SM, "ServiceMetadata")
    sub(sm, NS_SMB, "SMPVersionID", SMP_VERSION)
    id_el(sm, "ID", service["service"])
    id_el(sm, "ParticipantID", p)
    for pm in service["processMetadata"]:
        pme = sub(sm, NS_SMA, "ProcessMetadata")
        if pm.get("process"):
            process_el(pme, pm["process"])
        for ep in pm["endpoints"]:                                  # SMP-08: never Redirect
            e = sub(pme, NS_SMA, "Endpoint")
            sub(e, NS_SMB, "TransportProfileID", ep["transportProfile"])
            if ep.get("description"):
                sub(e, NS_SMB, "Description", ep["description"])
            if ep.get("contact"):
                sub(e, NS_SMB, "Contact", ep["contact"])
            sub(e, NS_SMB, "AddressURI", ep["address"])
            if ep.get("activationDate"):
                sub(e, NS_SMB, "ActivationDate", parse_date(ep["activationDate"]).isoformat())
            sub(e, NS_SMB, "ExpirationDate", parse_date(ep["expirationDate"]).isoformat())
            for c in ep.get("certificates", []):
                der, cert = load_cert(c["certificate"], record_path)
                ce = sub(e, NS_SMA, "Certificate")
                if c.get("typeCode"):
                    sub(ce, NS_SMB, "TypeCode", c["typeCode"])
                if c.get("description"):
                    sub(ce, NS_SMB, "Description", c["description"])
                sub(ce, NS_SMB, "ActivationDate", cert.not_valid_before_utc.date().isoformat())
                sub(ce, NS_SMB, "ExpirationDate", cert.not_valid_after_utc.date().isoformat())
                sub(ce, NS_SMB, "ContentBinaryObject", base64.b64encode(der).decode(),
                    mimeCode="application/base64")
    return sm


# --------------------------------------------------------------------------
# Signing (spec section 7)
# --------------------------------------------------------------------------
def sign(el, key_pem: bytes, cert_pem: bytes):
    signer = XMLSigner(                                             # SIG-01, SIG-02
        method=methods.enveloped,
        signature_algorithm=SignatureMethod.RSA_SHA256,
        digest_algorithm=DigestAlgorithm.SHA256,
        c14n_algorithm=CanonicalizationMethod.CANONICAL_XML_1_1,
    )
    signed = signer.sign(el, key=key_pem, cert=cert_pem)            # SIG-03: cert in X509Data
    assert etree.QName(signed[-1]).localname == "Signature"         # SIG-01: last child
    return signed


def ephemeral_key() -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "WE BUILD SMP (ephemeral CI key)")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    return (key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()),
            cert.public_bytes(serialization.Encoding.PEM))


def to_bytes(el) -> bytes:
    # SMP 2.0: UTF-8 with an XML declaration carrying encoding="UTF-8"
    return etree.tostring(el, xml_declaration=True, encoding="UTF-8")


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------
def path_variants(ident: dict, layouts: list[str]) -> list[str]:
    """
    File/dir names for one identifier, one per configured layout:
      decoded -> 'urn:oasis:...:0192::991825827'          (host decodes %XX before file lookup)
      encoded -> 'urn%3Aoasis%3A...%3A0192%3A%3A991825827' (host maps the raw path to a file)
    Keep both until the smoke test shows which one the host uses.
    """
    names = {"decoded": full_id(ident), "encoded": encode_segment(ident)}
    return list(dict.fromkeys(names[l] for l in layouts))


def write(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def xsd_validator(xsd_dir: Path | None):
    if not xsd_dir:
        return None
    return {"ServiceGroup": etree.XMLSchema(etree.parse(str(xsd_dir / "ServiceGroup-2.0.xsd"))),
            "ServiceMetadata": etree.XMLSchema(etree.parse(str(xsd_dir / "ServiceMetadata-2.0.xsd")))}


def build_site(records, config, key_pem, cert_pem, out: Path, xsd) -> int:
    site = out / "site"
    if site.exists():
        shutil.rmtree(site)
    site.mkdir(parents=True)
    base = config["smp_base_url"].rstrip("/")
    layouts = config.get("path_layouts", ["decoded", "encoded"])
    index = []

    def emit(el, kind):
        signed = sign(el, key_pem, cert_pem)
        if xsd:
            xsd[kind].assertValid(etree.fromstring(to_bytes(signed)))   # SMP-02
        return to_bytes(signed)

    for path, rec in records:
        p = norm_participant(rec["participant"])
        sg = emit(service_group(rec), "ServiceGroup")
        pdirs = path_variants(p, layouts)
        for pdir in pdirs:
            # '/bdxr-smp-2/{participant}' is both a resource and the parent of 'services/'.
            # Cloudflare Pages serves '{participant}.html' at '/{participant}' with 200 and no
            # redirect; clients such as phoss do not follow HTTP redirects (SMP-04).
            # index.html keeps '/{participant}/' working.
            write(site / RESOURCE_PREFIX / f"{pdir}.html", sg)
            write(site / RESOURCE_PREFIX / pdir / "index.html", sg)
        for s in rec["services"]:
            data = emit(service_metadata(rec, s, path), "ServiceMetadata")
            # SMP 2.0 identifiers are case-insensitive unless their scheme says otherwise, and
            # clients fold them to lower case (phoss does for bdx-docid-qns). A static host cannot
            # fold, so also store the lower-cased name (ID-04).
            snames = dict.fromkeys(v for n in path_variants(s["service"], layouts) for v in (n, n.lower()))
            for pdir in pdirs:
                for sdir in snames:
                    write(site / RESOURCE_PREFIX / pdir / "services" / sdir, data)
            index.append({"participant": full_id(p), "service": full_id(s["service"]),
                          "url": f"{base}/{RESOURCE_PREFIX}/{encode_segment(p)}/services/"
                                 f"{encode_segment(s['service'])}"})

    # Host configuration
    (site / ".nojekyll").write_text("")                              # GitHub Pages: no Jekyll
    (site / "_headers").write_text(                                  # Cloudflare Pages / Netlify (SMP-05)
        f"/{RESOURCE_PREFIX}/*\n  Content-Type: application/xml; charset=utf-8\n"
        f"  Cache-Control: public, max-age=300\n  X-Content-Type-Options: nosniff\n"
        f"/trust/*.crl\n  Content-Type: application/pkix-crl\n  Cache-Control: public, max-age=3600\n")
    write(site / "index.json", json.dumps(index, indent=2).encode())
    write(site / "trust" / "smp-signing-cert.pem", cert_pem)
    ta = ROOT / config.get("trust_anchor_file", "")
    if ta.is_file():
        shutil.copy(ta, site / "trust" / "trust-anchor.pem")
    crl = ROOT / config.get("crl_file", "")
    if crl.is_file():
        shutil.copy(crl, site / "trust" / "webuild-smp-ca.crl")      # SIG-09: CRL distribution point
    return len(index)


def build_dns(records, config, out: Path) -> int:
    dns = out / "dns"
    dns.mkdir(parents=True, exist_ok=True)
    zone = config["bdxl_zone"].rstrip(".")
    ttl = int(config.get("dns_ttl", 3600))
    regexp = f"!^.*$!{config['smp_base_url'].rstrip('/')}!"
    if config.get("bdxl_mode", "explicit") == "wildcard":            # BDXL-05
        names = [f"*.{zone}"]
    else:
        names = [f"{bdxl_label(r['participant'])}.{zone}" for _, r in records]
    rows = [{"name": n, "ttl": ttl, "order": 100, "preference": 10, "flags": "U",
             "service": "Meta:SMP", "regexp": regexp, "replacement": "."} for n in names]
    (dns / "naptr.json").write_text(json.dumps(rows, indent=2))
    (dns / "naptr.zone").write_text("".join(
        f'{r["name"]}. {r["ttl"]} IN NAPTR {r["order"]} {r["preference"]} "{r["flags"]}" '
        f'"{r["service"]}" "{r["regexp"]}" {r["replacement"]}\n' for r in rows))
    return len(rows)


def self_check(site: Path, cert_pem: bytes) -> int:
    n = 0
    for f in (site / RESOURCE_PREFIX).rglob("*"):
        if f.is_file():
            XMLVerifier().verify(f.read_bytes(), x509_cert=cert_pem)
            n += 1
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--validate-only", action="store_true")
    ap.add_argument("--key", type=Path, help="SMP signing key (PEM)")
    ap.add_argument("--cert", type=Path, help="SMP signing certificate (PEM)")
    ap.add_argument("--ephemeral-key", action="store_true", help="sign with a throwaway key (PR builds)")
    ap.add_argument("--xsd-dir", type=Path, help="dir with OASIS ServiceGroup-2.0.xsd / ServiceMetadata-2.0.xsd")
    ap.add_argument("--out", type=Path, default=ROOT / "dist")
    args = ap.parse_args()

    config, schema, records = load_config(), load_schema(), load_records()
    errors = validate(records, config, schema) + check_crl(config)
    if errors:
        print("Validation failed:", *errors, sep="\n  ", file=sys.stderr)
        sys.exit(1)
    print(f"Validated {len(records)} participant record(s).")
    if args.validate_only:
        return

    if args.ephemeral_key:
        key_pem, cert_pem = ephemeral_key()
    elif args.key and args.cert:
        key_pem, cert_pem = args.key.read_bytes(), args.cert.read_bytes()
        if b"-----BEGIN CERTIFICATE-----" not in cert_pem:
            sys.exit(f"{args.cert}: no PEM certificate (-----BEGIN CERTIFICATE-----); check SMP_SIGNING_CERT")
        if b"PRIVATE KEY-----" not in key_pem:
            sys.exit(f"{args.key}: no PEM private key (...PRIVATE KEY-----); check SMP_SIGNING_KEY")
        if crl_errors := check_crl(config, cert_pem):
            sys.exit("\n".join(crl_errors))
    else:
        ap.error("need --key and --cert, or --ephemeral-key")

    n = build_site(records, config, key_pem, cert_pem, args.out, xsd_validator(args.xsd_dir))
    n_dns = build_dns(records, config, args.out)
    n_ok = self_check(args.out / "site", cert_pem)
    print(f"Built {n} ServiceMetadata entries; {n_ok} signed files verified"
          f"{'; XSD-valid' if args.xsd_dir else ''}; {n_dns} NAPTR record(s).")


if __name__ == "__main__":
    main()
