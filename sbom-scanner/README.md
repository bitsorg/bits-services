# sbom-scanner

Matches the SBOMs of published bits builds with a vulnerability database
([grype](https://github.com/anchore/grype)) for the orchestrator. The worker
sends each build's `sbom.cdx.json`; the service returns the same SBOM with a
CycloneDX `vulnerabilities` section whose `affects` name the SBOM's own
components (with the versions that fix each, as `unaffected`), and counts by
severity. Each vulnerability carries grype's risk score, EPSS and CISA KEV date
as `grype:risk`, `grype:epss` and `grype:kev` properties. The backend shows them
in the console's Vulnerabilities page and in the SBOM report, and plans upgrades
from them.

It holds no secret. It is on `scan-net` with the worker alone; its only traffic
out is grype's database download (`grype.anchore.io`), refreshed every
`SCANNER_DB_REFRESH_HOURS` (6) into the `scanner-db` volume. A build is scanned
again whenever the database is newer than the one of its last scan.

    POST /v1/scan   CycloneDX JSON -> {"db", "summary", "sbom"}
    GET  /v1/status the database's date and schema
    GET  /healthz   200 once a database is loaded

What it finds depends on the SBOM: grype matches purls (PyPI and the like) and
CPEs, which recipes give with `references:` (bits REFERENCE.md). A package with
neither is not checked.

Tests (standard library, a fake grype): `python3 -m unittest -v test_scanner`.
Switching it on: DEPLOYMENT.md, "Vulnerability scans".
