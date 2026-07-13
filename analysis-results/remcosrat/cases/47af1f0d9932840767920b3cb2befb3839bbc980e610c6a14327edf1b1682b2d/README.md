# RemcosRAT case 47af1f0d9932

## Overview

- SHA-256: `47af1f0d9932840767920b3cb2befb3839bbc980e610c6a14327edf1b1682b2d`
- Artifact: HTA
- Delivery/campaign pattern: `hta_png_stage`
- Analysis mode: static analysis plus public sandbox evidence; the sample was not executed locally
- Recovered family version: 6.0.0 Pro

## Delivery and behavior

- HTA retrieves an image-named stage
- One configuration contains multiple fallback ports

## Network observables

- Confirmed configuration/sandbox endpoint: `pavementmg.duckdns.org:4450`
- Confirmed configuration/sandbox endpoint: `pavementmg.duckdns.org:4551`
- Confirmed configuration/sandbox endpoint: `pavementmg.duckdns.org:4553`
- Loader/stage URL: `http://64.44.156.79/img/MSI_PRO.png`
- Confidence: endpoints labeled confirmed were extracted from malware configuration or process-attributed sandbox evidence. Exact-byte duplicate containers inherit the inner payload result explicitly.
- No live C2 check was performed. Current availability and server identity are therefore unknown.

## Shodan pivots

- `hostname:"pavementmg.duckdns.org" port:4450` — infrastructure pivot; not a protocol fingerprint
- `hostname:"pavementmg.duckdns.org" port:4551` — infrastructure pivot; not a protocol fingerprint
- `hostname:"pavementmg.duckdns.org" port:4553` — infrastructure pivot; not a protocol fingerprint
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
- SHA-256: `47af1f0d9932840767920b3cb2befb3839bbc980e610c6a14327edf1b1682b2d`
- C2 values: `pavementmg.duckdns.org:4450`, `pavementmg.duckdns.org:4551`, `pavementmg.duckdns.org:4553`
- Stage URLs: `http://64.44.156.79/img/MSI_PRO.png`
- Correlate parent/child process, command line, file origin, signer/prevalence and network destination before blocking.

## Reproduction

Run the family batch workflow against the original password-protected MalwareBazaar ZIP. Outputs must retain `executed=false` and `network_contacted=false` unless a separately approved dynamic-analysis workflow was used.
