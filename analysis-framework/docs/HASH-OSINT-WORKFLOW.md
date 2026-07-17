# Hash OSINT enrichment workflow

## Purpose and safety boundary

`common/osint_hash_enricher.py` turns low-confidence or unidentified static
cases into auditable family leads by querying exact SHA-256 metadata. It does
not upload files, execute samples, or contact infrastructure extracted from a
sample. Raw provider responses are retained only under the ignored `.work/`
cache; repository output contains normalized evidence.

The workflow is deliberately conservative:

- one family-specific provider is a low-confidence lead;
- two independent agreeing providers are required for medium confidence;
- an aggregator is not counted in addition to its named underlying providers;
- any competing family lead demotes the result to low confidence;
- a tie remains `unknown` with status `conflicting`;
- high confidence additionally requires reviewed local family evidence.

## Inputs and information management

The source and safety policy is defined in
`osint/hash_sources.yaml`. The current adapters support:

| Source | Evidence retained | Interpretation |
|---|---|---|
| MalwareBazaar | catalog/YARA labels and normalized named-provider labels | MalwareBazaar is a transport; named providers remain distinct |
| OTX | pulse names and tags | all pulses together are one community-provider vote |
| CIRCL hashlookup | known-file context | never supplies a malware-family vote |
| VirusTotal | popular classification and sandbox family labels | lookup only; no upload fallback |

Analyst research that cannot be obtained from an API is stored in a
publishable, hash-keyed YAML file and supplied with `--curated-evidence`.
Each record must be marked `reviewed: true`; every family observation records
the provider, evidence type, bounded label, strength, and optional query-free
reference. Context references are retained without becoming family votes.

```yaml
schema_version: 1
policy:
  sample_submission: prohibited
records:
  <sha256>:
    reviewed: true
    reviewed_at: YYYY-MM-DD
    evidence:
      - provider: external_researcher
        transport: external_research
        family: ExampleFamily
        label: Exact-hash report and distinctive static structure agree.
        strength: 4
        reference: https://example.org/report
      - provider: local_reviewed_static
        transport: local_static_review
        family: ExampleFamily
        label: Static review confirmed the distinctive structure.
        strength: 4
    context_references:
      - https://vendor.example/advisory
```

Do not include passwords, tokens, API keys, URL user information, query
strings, fragments, email addresses, or recovered attacker secrets. Describe a
distinctive constant without publishing its value when the value is not needed
for detection.

## Execution order

Run the start safety gate before reading sample archives. After the static batch
has produced `summary.json`, enrich the unresolved cases:

```powershell
python common/osint_hash_enricher.py `
  --summary ..\analysis-results\unclassified\<batch>\summary.json `
  --output ..\analysis-results\unclassified\<batch> `
  --registry osint\hash_sources.yaml `
  --cache ..\.work\<batch>\osint-cache `
  --private-manifest ..\.work\<batch>\manifest.json `
  --history ..\analysis_history.yaml `
  --curated-evidence ..\analysis-results\unclassified\<batch>\research-evidence.yaml
```

Use `--source malwarebazaar --refresh` to refresh only one source. Existing
source responses remain in the cache. Use `--offline` to replay cached API
responses plus curated evidence without network access. The optional
VirusTotal adapter requires its configured environment credential; absence is
reported as unavailable and never triggers a file submission.

## Outputs

- `cases/<sha256>/osint-evidence.json`: normalized evidence, source status,
  confidence, conflicts, and safety assertions.
- `cases/<sha256>/README.md`: generated `Hash OSINT enrichment` section.
- `osint-summary.json`: machine-readable aggregate and per-case records.
- `OSINT.md`: human-readable counts, source coverage, and case table.
- `summary.json`, `README.md`, and matching `analysis_history.yaml` blocks:
  combined attribution references.
- `.work/<batch>/osint-cache/<sha256>.json`: private raw API cache; never
  commit this directory.

## Manual escalation for remaining unknowns

1. Search the exact SHA-256 and prefer an original technical report over a
   derivative IOC list.
2. Record whether the source actually identifies that exact hash. A generic
   family article is context, not a family vote.
3. Compare distinctive local static structure: protocol constants, validation
   flow, service/port split, configuration layout, imports, or deobfuscated
   code. Do not execute the file.
4. Add reviewed evidence with provenance to the curated YAML and replay the
   batch offline.
5. Keep one-source labels at low confidence. Preserve conflicts explicitly.

YARA-only matches, generic AV terms, filenames, file type, entropy, TCP-open
state, and a URL alone are insufficient for a supported family attribution.

## Failure checks

| Symptom | Check |
|---|---|
| 401/403 | Confirm the configured environment credential is present and valid; never put it in command history or reports |
| 404/not found | Treat it as no result from that source, not as benign evidence |
| Empty OTX pulses | Preserve `pulse_count: 0`; continue with other sources |
| Rate limit/timeout | Refresh only that source later; cached sources are merged |
| Conflicting labels | Inspect provider provenance and retain `conflicting`; do not choose by vendor count alone |
| Public output contains raw fields | Stop publication and check for `response`, provider raw metadata, URL queries, tokens, and environment-variable names |
| Family alias missing | Add a reviewed alias and unit test; do not infer unrelated similarly named families |

After report generation, regenerate and check IOC lists, run the unit/pydoc
suite, scan repository output for secrets/raw fields, and run the end safety
gate. Safety-gate output remains stdout-only and is never committed.

## 2026-07-17 batch outcome

The newest-first 100-case batch had 93 low-confidence or unidentified targets.
Hash OSINT recovered 69 family leads; six have medium support. Twenty-four
remain unknown and one retains a family conflict. These counts are an audit
snapshot, not a claim that unresolved samples are benign.
