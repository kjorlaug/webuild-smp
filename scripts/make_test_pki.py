#!/usr/bin/env python3
"""
Create the WE BUILD SMP test PKI (SIG-04): a CA and an SMP signing certificate.

  python scripts/make_test_pki.py --out ../webuild-smp-pki

Writes ca.key.pem, ca.cert.pem, smp.key.pem, smp.cert.pem into --out.
- Commit ONLY ca.cert.pem, as trust/webuild-smp-ca.pem.
- Put smp.key.pem and smp.cert.pem in GitHub secrets SMP_SIGNING_KEY / SMP_SIGNING_CERT.
- Keep ca.key.pem offline; it is needed only to issue a new signing cert (rotation, SIG-06).
Use --ca-key/--ca-cert to issue a new signing cert from an existing CA.
"""
import argparse
import datetime as dt
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "WE BUILD LSP (pilot)"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def pem_key(k):
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--ca-key", type=Path)
    ap.add_argument("--ca-cert", type=Path)
    ap.add_argument("--signing-days", type=int, default=400)
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc)

    if a.ca_key and a.ca_cert:
        ca_key = serialization.load_pem_private_key(a.ca_key.read_bytes(), None)
        ca = x509.load_pem_x509_certificate(a.ca_cert.read_bytes())
    else:
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        ca = (x509.CertificateBuilder()
              .subject_name(name("WE BUILD SMP Test CA")).issuer_name(name("WE BUILD SMP Test CA"))
              .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now).not_valid_after(now + dt.timedelta(days=5 * 365))
              .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
              .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                           key_encipherment=False, data_encipherment=False,
                                           key_agreement=False, key_cert_sign=True, crl_sign=True,
                                           encipher_only=False, decipher_only=False), critical=True)
              .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
              .sign(ca_key, hashes.SHA256()))
        (a.out / "ca.key.pem").write_bytes(pem_key(ca_key))
        (a.out / "ca.cert.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (x509.CertificateBuilder()
            .subject_name(name("WE BUILD SMP signing")).issuer_name(ca.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=a.signing_days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=False, crl_sign=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                           critical=False)
            .sign(ca_key, hashes.SHA256()))
    (a.out / "smp.key.pem").write_bytes(pem_key(key))
    (a.out / "smp.cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Wrote test PKI to {a.out}")


if __name__ == "__main__":
    main()
