# Trivy / TeamPCP supply-chain compromise

## Confirmed scope

Aqua's advisory confirms that compromised credentials were used on 2026-03-19 to publish malicious Trivy `v0.69.4`, force-push 76 of 77 `trivy-action` tags, and replace all seven `setup-trivy` tags. On 2026-03-22, malicious Docker Hub images `0.69.5` and `0.69.6` were also published.

Exposure windows (UTC): Trivy v0.69.4 about 3 hours; trivy-action about 12 hours; setup-trivy about 4 hours; Docker Hub 0.69.5/0.69.6 about 10 hours. The malicious code was not on Trivy main; artifacts may remain in caches.

## Malware behavior

- release commit `1885610c` substituted `actions/checkout` with imposter commit `70379aad` and bypassed validation;
- action payload dumped `Runner.Worker` memory via `/proc/<pid>/mem` and swept 50+ secret locations;
- collections were protected using AES-256-CBC and RSA-4096 before exfiltration;
- primary infrastructure: `scan.aquasecurtiy.org` and `45.148.10.212`;
- fallback: create a public `tpcp-docs-*` repository and upload `data-<timestamp>` release assets when `INPUT_GITHUB_PAT` was available.

The reported Cisco source-code theft is plausibly downstream of this incident, but no Cisco primary disclosure confirming the quoted repository count, source scope, or stolen AWS keys was located. Those details remain `unverified/reporting-only` and must not be merged into Aqua's confirmed scope.

## High-value hashes

- Windows ZIP: `0376b98064636c30f5fbe60fb3b1225516e23e88dd7e909937f81d9265292e7d`
- Linux amd64 binary: `822dd269ec10459572dfaaefe163dae693c344249a0161953f0d5cdd110bd2a0`
- Linux 64-bit tar: `385d498d18a3a7c67878ca7322716f9da25683eb1a4bf9e9592da0d5f2ab09f6`
- image 0.69.4: `sha256:27f446230c60bbf0b70e008db798bd4f33b7826f9f76f756606f5417100beef3`
- image 0.69.5: `sha256:5aaa1d7cfa9ca4649d6ffad165435c519dc836fa6e21b729a2174ad10b057d2b`
- image 0.69.6: `sha256:425cd3e1a2846ac73944e891250377d2b03653e6f028833e30fc00c1abbc6d33`

## Triage and detection

1. Identify workflow runs inside the official exposure windows.
2. Resolve actual action commits and pulled image digests; do not rely only on current mutable tag targets.
3. Treat every secret accessible to an exposed runner as compromised and rotate atomically.
4. Search organization audit logs for public `tpcp-docs-*` repositories, release creation, and `data-*` assets.
5. Hunt runner network telemetry for the typosquat/IP and `/proc/*/mem` access by action shells.

False-positive assessment:

- **Low**: exact malicious artifact/image digest, typosquat, or unexpected `tpcp-docs-*` release asset.
- **Medium**: old mutable trivy-action/setup-trivy reference executed during the exposure window; current tags alone do not prove historical execution.
- **High**: generic access to credential files or `/proc` without runner/process/time correlation.

Use `analysis-framework/common/supply_chain_audit.py` to find manifest/workflow evidence offline. Rules: [Sigma](rules/trivy_teampcp.yml), [YARA](rules/trivy_release_hashes.yar), [IOCs](iocs.json).

Source: https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23
