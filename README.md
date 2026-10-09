# WE BUILD SMP 2.0 / BDXL registry

This is the reference implementation of the [WE BUILD SMP/BDXL Conformance Specification](SPEC.md). It is an OASIS SMP 2.0 service that is read-only and serves static files, with an OASIS BDXL (U-NAPTR) zone for discovery. It has no Peppol dependencies.

- Registrants add a YAML record to this repository through a pull request.
- CI validates the record, generates the SMP 2.0 XML, signs it, validates it against the OASIS XSDs and publishes it. It then updates DNS and probes the live service.
- There is no back office, database or management API.

```
registry/participants/*.yaml       one file per participant (REG-01)
registry/certs/                    endpoint certificates (PEM)
registry/erds/*.yaml               one file per (Q)ERDS: ETSI ERDS capability metadata (ERDS-01)
trust/webuild-smp-ca.pem           SMP trust anchor (SIG-04), public
trust/webuild-smp-ca.crl           CRL for SMP signing certificates (SIG-09), public
config.yaml                        SMP URL, BDXL zone, mode, allowed schemes and transport profiles
schema/record.schema.json          record schema (REG-02)
schema/erds.schema.json            ERDS record schema (ERDS-01)
schema/etsi/                       ETSI EN 319 522-3 XSD (vendored, see its README)
scripts/build.py                   validate, generate SMP 2.0 XML, sign, BDXL records
scripts/smoke_test.py              sender-side conformance probe
scripts/sync_dns_desec.py          pushes NAPTR records to a deSEC zone
scripts/sync_dns_cloudflare.py     pushes NAPTR records to Cloudflare DNS
scripts/wait_dns.py                waits until the BDXL zone's nameservers serve the records
scripts/make_test_pki.py           test CA, SMP signing certificate and CRL
tests/phoss-client/                real SMP 2.0 client test (phoss smp-client, Docker)
.github/workflows/publish.yml      the pipeline
```

Resources are published at `{smp_base_url}/bdxr-smp-2/{participant}` (ServiceGroup) and `{smp_base_url}/bdxr-smp-2/{participant}/services/{service}` (ServiceMetadata).

## Registering a participant

1. Copy `registry/participants/0192_991825827.yaml`.
2. Use an allowed participant scheme from `config.yaml`, in lower case. Add one entry per service (document type), with its process and endpoint(s).
3. Put endpoint certificates in `registry/certs/` and reference them by relative path.
4. If an endpoint belongs to an (Q)ERDS, add `erds: <name>` and, once per ERDS, a `registry/erds/<name>.yaml` (copy `example-qerds.yaml`). The SMP then publishes the ETSI `ERDSMetadata` for that endpoint (SPEC section 8.1).
5. Open a PR. The `validate` check must pass, and an operator other than you approves it.

After the merge, changes are live within minutes; CI waits for new BDXL records before it probes them. Changed or removed DNS records follow their TTL, at most 1 hour.

To remove a participant, delete its file.

## Hosting

The default host is Cloudflare Pages. SMP 2.0 requires `Content-Type: application/xml`. Cloudflare Pages sets that from the generated `_headers` file, and GitHub Pages cannot.

GitHub Pages also works (repository variable `HOSTING=github`). In that case the service deviates from SMP-05, and the smoke test reports it. The repository and pipeline stay on GitHub either way.

## Pilot deployment

| | |
| --- | --- |
| SMP | `https://smp.webuild.kjorlaug.no`: Cloudflare Pages project `webuild-smp`, CNAME at Domeneshop |
| BDXL zone | `bdxl.webuild.kjorlaug.no`: deSEC, delegated with NS and DS records at Domeneshop (DNSSEC-signed) |
| Trust anchor | `trust/webuild-smp-ca.pem`, test CA from `make_test_pki.py` (2026-10-09) |
| CRL | `https://smp.webuild.kjorlaug.no/trust/webuild-smp-ca.crl`, next update 2027-10-09 |

## Setting up (operator)

1. Create the PKI: `python scripts/make_test_pki.py --out ../webuild-smp-pki`
   - Commit only `ca.cert.pem`, as `trust/webuild-smp-ca.pem`, and `ca.crl`, as `trust/webuild-smp-ca.crl`.
   - Store `smp.key.pem` and `smp.cert.pem` as secrets `SMP_SIGNING_KEY` and `SMP_SIGNING_CERT`. The build fails fast if either is empty or not PEM.
   - Keep `ca.key.pem` offline.
   - Re-sign the CRL before its `nextUpdate` (yearly; CI warns 30 days ahead), and add `--revoke <serial>` when retiring a signing cert:
     `python scripts/make_test_pki.py --out ../webuild-smp-pki --ca-key ../webuild-smp-pki/ca.key.pem --ca-cert ../webuild-smp-pki/ca.cert.pem --crl-only`
2. Cloudflare Pages:
   - Add the secrets `CLOUDFLARE_API_TOKEN` (Pages:Edit) and `CLOUDFLARE_ACCOUNT_ID`, and the variable `CF_PAGES_PROJECT`. The first deploy creates the project.
   - Then add the host of `smp_base_url` as the project's custom domain, with a CNAME to `<project>.pages.dev` at your DNS host.
3. BDXL zone for `bdxl_zone`. It needs a DNS host with NAPTR records and an API. Use one of:
   - **deSEC** (pilot): create the zone, add NS and DS records for it in the parent zone, and add the secret `DESEC_TOKEN`.
   - **Cloudflare DNS**: the zone must be on Cloudflare. Add the secret `CLOUDFLARE_ZONE_ID` and give the token Zone.DNS:Edit.
   - Without either, CI skips the sync; load `dist/dns/naptr.zone` by hand.
4. Branch protection on `main`: require a PR, 1 approval, and the `validate` check (REG-03).
5. Set `smp_base_url`, `bdxl_zone` and the remaining placeholders in `config.yaml`.

## Local build and test

```bash
pip install -r requirements.txt
python scripts/build.py --validate-only
python scripts/build.py --ephemeral-key                       # or --key/--cert; add --xsd-dir for XSD validation
npx wrangler pages dev dist/site --port 8788 &                # emulates Cloudflare Pages incl. _headers
python scripts/smoke_test.py --base-url http://localhost:8788 --no-dns --ca <ca used to sign>
```

## The spike: run this before relying on the host

Identifiers contain `:` and `#`, which senders percent-encode (ID-05). The host must map those URLs to files. `build.py` writes each resource under two file names:

- a *decoded* name (`urn:oasis:...::991825827`);
- an *encoded* name (`urn%3Aoasis%3A...`).

Results so far:

- On the Cloudflare Pages emulator (`wrangler pages dev`), all 10 checks pass. It serves the **decoded** layout.
- Python's `http.server` also serves the decoded layout, but it fails SMP-05 because it sends the wrong Content-Type.

- On live Cloudflare Pages (2026-10-09), all 12 checks pass, including BDXL, with only the decoded layout deployed. `path_layouts` is now `[decoded]`.

- phoss smp-client 13.2.0 (`tests/phoss-client/run.sh`, needs Docker) passes with default settings. It needed three changes: the ServiceGroup is served without a redirect, service IDs are also served lower-cased, and the signing cert has a CRL.

## Known limitations of static hosting

- The ServiceGroup is stored as `{participant}.html`, which Cloudflare Pages serves at `/{participant}` without a redirect (SMP-04). Hosts without that mapping would answer with a redirect, which phoss rejects.
- The encoded service or participant identifier must be 255 bytes or less, because it becomes a file name. `build.py` rejects longer ones.
- Lookups are case-sensitive, so participant identifiers are forced to lower case (ID-01).
- The signing key is a CI secret. Anyone with admin rights on the repository can reach it indirectly (SIG-06).
