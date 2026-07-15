# Formbook behavior and C2 assessment

## Reviewed set

- 10 recent MalwareBazaar submissions: 6 scripts, 3 XLSM containers, and 1 .NET PE.
- Four script submissions exposed loader behavior; six cases yielded additional static layers.
- The direct PE was high entropy and remained protected. FLOSS reported that .NET deobfuscation was unsupported for that case.

## Behavior model

Formbook/XLoader payloads are expected to collect browser and mail credentials and to use process-injection APIs. In this set, most submissions were delivery stages, so those payload-level behaviors were not uniformly visible. Script and Office indicators must therefore be kept separate from final-payload attribution.

## Infrastructure

One recursively decoded JavaScript layer contained:

- `https://misty-cherry-cea3.uploadsimg.workers.dev/EzUaK`

This is classified as candidate delivery/infrastructure, not confirmed C2. No active request was made. Certificate, Microsoft, and other vendor-reference URLs were filtered.

## Detection

- High FP: `wscript`/PowerShell usage, XLSM macros, or Cloudflare Workers in isolation.
- Medium FP: a script host downloading a binary and spawning `rundll32`, `regsvr32`, or `mshta`.
- Lower FP: correlate delivery URL, family payload strings, credential-store access, and process-injection telemetry.
