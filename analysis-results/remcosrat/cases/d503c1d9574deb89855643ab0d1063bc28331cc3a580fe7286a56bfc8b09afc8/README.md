# RemcosRAT case d503c1d9574d

## Overview

- SHA-256: `d503c1d9574deb89855643ab0d1063bc28331cc3a580fe7286a56bfc8b09afc8`
- Artifact: HTA
- Delivery/campaign pattern: `hta_png_stage`
- Analysis mode: static analysis plus public sandbox evidence; the sample was not executed locally
- Recovered family version: 6.0.0 Pro

## Delivery and behavior

- The stage host is preserved as an observed literal and was not validated as routable
- Final configuration contains four fallback ports

## Network observables

- Confirmed configuration/sandbox endpoint: `141.98.10.150:14641`
- Confirmed configuration/sandbox endpoint: `141.98.10.150:14642`
- Confirmed configuration/sandbox endpoint: `141.98.10.150:14643`
- Confirmed configuration/sandbox endpoint: `141.98.10.150:14644`
- Loader/stage URL: `http://010013116117/img/MSI_PRO.png`
- Confidence: endpoints labeled confirmed were extracted from malware configuration or process-attributed sandbox evidence. Exact-byte duplicate containers inherit the inner payload result explicitly.
- No live C2 check was performed. Current availability and server identity are therefore unknown.

## Shodan pivots

- `ip:"141.98.10.150" port:14641` — infrastructure pivot; not a protocol fingerprint
- `ip:"141.98.10.150" port:14642` — infrastructure pivot; not a protocol fingerprint
- `ip:"141.98.10.150" port:14643` — infrastructure pivot; not a protocol fingerprint
- `ip:"141.98.10.150" port:14644` — infrastructure pivot; not a protocol fingerprint
- Banner hash, HTTP title, certificate hash and JARM: not available from static/sandbox evidence. Do not invent these values; collect only under an approved live-network procedure.

## Detection guidance

- High confidence / low false-positive risk: exact SHA-256, a reviewed YARA match combining loader structure with family-specific strings, or an endpoint plus matching process ancestry.
- Medium confidence / medium false-positive risk: script host spawning hidden PowerShell together with remote image retrieval, in-memory .NET loading, or a double-extension executable from an ISO.
- Low confidence / high false-positive risk: a single domain/IP, FTP/SMTP use, PowerShell, WScript, HTA, or image-named download alone. These are common administrative or application behaviors.
- Credential material extracted from configurations is intentionally not published. Preserve it only in access-controlled evidence and rotate/notify an owner when appropriate.

## Rule-building fields

- Family: `RemcosRAT`
- Campaign pattern: `hta_png_stage`
- Artifact type: `HTA`
- SHA-256: `d503c1d9574deb89855643ab0d1063bc28331cc3a580fe7286a56bfc8b09afc8`
- C2 values: `141.98.10.150:14641`, `141.98.10.150:14642`, `141.98.10.150:14643`, `141.98.10.150:14644`
- Stage URLs: `http://010013116117/img/MSI_PRO.png`
- Correlate parent/child process, command line, file origin, signer/prevalence and network destination before blocking.

## Reproduction

Run the family batch workflow against the original password-protected MalwareBazaar ZIP. Outputs must retain `executed=false` and `network_contacted=false` unless a separately approved dynamic-analysis workflow was used.
