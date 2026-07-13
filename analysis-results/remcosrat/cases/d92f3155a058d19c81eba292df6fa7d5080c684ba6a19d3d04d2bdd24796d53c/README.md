# RemcosRAT case d92f3155a058

## Overview

- SHA-256: `d92f3155a058d19c81eba292df6fa7d5080c684ba6a19d3d04d2bdd24796d53c`
- Artifact: JavaScript
- Delivery/campaign pattern: `js_activex_staged_loader`
- Analysis mode: static analysis plus public sandbox evidence; the sample was not executed locally
- Recovered family version: 7.2.6 Pro

## Delivery and behavior

- Large UTF-16 JavaScript padded with plausible library comments
- Instantiates ActiveXObject, writes/launches a secondary JavaScript path, and leads to PowerShell in sandbox telemetry

## Network observables

- Confirmed configuration/sandbox endpoint: `79.141.165.55:2404`
- Confidence: endpoints labeled confirmed were extracted from malware configuration or process-attributed sandbox evidence. Exact-byte duplicate containers inherit the inner payload result explicitly.
- No live C2 check was performed. Current availability and server identity are therefore unknown.

## Shodan pivots

- `ip:"79.141.165.55" port:2404` — infrastructure pivot; not a protocol fingerprint
- Banner hash, HTTP title, certificate hash and JARM: not available from static/sandbox evidence. Do not invent these values; collect only under an approved live-network procedure.

## Detection guidance

- High confidence / low false-positive risk: exact SHA-256, a reviewed YARA match combining loader structure with family-specific strings, or an endpoint plus matching process ancestry.
- Medium confidence / medium false-positive risk: script host spawning hidden PowerShell together with remote image retrieval, in-memory .NET loading, or a double-extension executable from an ISO.
- Low confidence / high false-positive risk: a single domain/IP, FTP/SMTP use, PowerShell, WScript, HTA, or image-named download alone. These are common administrative or application behaviors.
- Credential material extracted from configurations is intentionally not published. Preserve it only in access-controlled evidence and rotate/notify an owner when appropriate.

## Rule-building fields

- Family: `RemcosRAT`
- Campaign pattern: `js_activex_staged_loader`
- Artifact type: `JavaScript`
- SHA-256: `d92f3155a058d19c81eba292df6fa7d5080c684ba6a19d3d04d2bdd24796d53c`
- C2 values: `79.141.165.55:2404`
- Stage URLs: none recovered
- Correlate parent/child process, command line, file origin, signer/prevalence and network destination before blocking.

## Reproduction

Run the family batch workflow against the original password-protected MalwareBazaar ZIP. Outputs must retain `executed=false` and `network_contacted=false` unless a separately approved dynamic-analysis workflow was used.
