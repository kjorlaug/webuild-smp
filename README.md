# WE BUILD SMP 2.0 / BDXL registry

This is the reference implementation of the [WE BUILD SMP/BDXL Conformance Specification](SPEC.md). It is an OASIS SMP 2.0 service that is read-only and serves static files, with an OASIS BDXL (U-NAPTR) zone for discovery. It has no Peppol dependencies.

- Registrants add a YAML record to this repository through a pull request.
- CI validates the record, generates the SMP 2.0 XML, signs it, validates it against the OASIS XSDs and publishes it. It then updates DNS and probes the live service.
- There is no back office, database or management API.

```
registry/participants/*.yaml       one file per participant (REG-01)
registry/certs/                    endpoint certificates (PEM)
trust/webuild-smp-ca.pem           SMP trust anchor (SIG-04), public
config.yaml                        SMP URL, BDXL zone, mode, allowed schemes and transport profiles
schema/record.schema.json          record schema (REG-02)
scripts/build.py                   validate, generate SMP 2.0 XML, sign, BDXL records
scripts/smoke_test.py              sender-side conformance probe
scripts/sync_dns_cloudflare.py     pushes NAPTR records to Cloudflare DNS
scripts/make_test_pki.py           test CA and SMP signing certificate
.github/workflows/publish.yml      the pipeline
```

Resources are published at `{smp_base_url}/bdxr-smp-2/{participant}` (ServiceGroup) and `{smp_base_url}/bdxr-smp-2/{participant}/services/{service}` (ServiceMetadata).

## Registering a participant

1. Copy `registry/participants/0192_991825827.yaml`.
2. Use an allowed participant scheme from `config.yaml`, in lower case. Add one entry per service (document type), with its process and endpoint(s).
3. Put endpoint certificates in `registry/certs/` and reference them by relative path.
4. Open a PR. The `validate` check must pass, and an operator other than you approves it.

After the merge, changes are live within minutes. DNS follows its TTL, at most 1 hour.

To remove a participant, delete its file.

## Hosting

The default host is Cloudflare Pages. SMP 2.0 requires `Content-Type: application/xml`. Cloudflare Pages sets that from the generated `_headers` file, and GitHub Pages cannot.

GitHub Pages also works (repository variable `HOSTING=github`). In that case the service deviates from SMP-05, and the smoke test reports it. The repository and pipeline stay on GitHub either way.

## Setting up (operator)

1. Create the PKI: `python scripts/make_test_pki.py --out ../webuild-smp-pki`
   - Commit only `ca.cert.pem`, as `trust/webuild-smp-ca.pem`. **Replace the file shipped here, which is a throwaway.**
   - Store `smp.key.pem` and `smp.cert.pem` as secrets `SMP_SIGNING_KEY` and `SMP_SIGNING_CERT`.
   - Keep `ca.key.pem` offline.
2. Cloudflare:
   - Create a Pages project (direct upload) with the host of `smp_base_url` as its custom domain.
   - Create the DNS zone for `bdxl_zone`.
   - Add the secrets `CLOUDFLARE_API_TOKEN` (Pages:Edit and Zone.DNS:Edit), `CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_ZONE_ID`, and the variable `CF_PAGES_PROJECT`.
3. Branch protection on `main`: require a PR, 1 approval, and the `validate` check (REG-03).
4. Edit the placeholders in `config.yaml`.

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

After the first real deploy, the `smoke` job runs the same probe against the live service. If the job is green, set `path_layouts: [decoded]`.

Also run one real SMP 2.0 client (e.g. the BDXR2 client in phoss smp-client), configured with the WE BUILD BDXL zone and trust anchor.

## Known limitations of static hosting

- The ServiceGroup is stored as `/{participant}/index.html` and reached through a 308 redirect (SMP-04).
- The encoded service or participant identifier must be 255 bytes or less, because it becomes a file name. `build.py` rejects longer ones.
- Lookups are case-sensitive, so participant identifiers are forced to lower case (ID-01).
- The signing key is a CI secret. Anyone with admin rights on the repository can reach it indirectly (SIG-06).
