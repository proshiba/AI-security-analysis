# RemcosRAT case 3682d8c43801

## Overview

- SHA-256: `3682d8c438017249510aba8865e979b666265be3ffae760d503f17ccb391afac`
- Artifact: JavaScript
- Delivery/campaign pattern: `unicode_marker_powershell_stage`
- Analysis mode: static analysis plus public sandbox evidence; the sample was not executed locally
- Recovered family version: 7.2.6 Pro

## Delivery and behavior

- Unicode junk marker reconstruction
- Remote stage is transformed and loaded in memory

## Network observables

- Confirmed configuration/sandbox endpoint: `thrillermotion.4nmn.com:2022`
- Loader/stage URL: `https://misty-cherry-cea3.uploadsimg.workers.dev/mNHLb`
- Confidence: endpoints labeled confirmed were extracted from malware configuration or process-attributed sandbox evidence. Exact-byte duplicate containers inherit the inner payload result explicitly.
- No live C2 check was performed. Current availability and server identity are therefore unknown.

## Shodan pivots

- `hostname:"thrillermotion.4nmn.com" port:2022` — infrastructure pivot; not a protocol fingerprint
- Banner hash, HTTP title, certificate hash and JARM: not available from static/sandbox evidence. Do not invent these values; collect only under an approved live-network procedure.

## Detection guidance

- High confidence / low false-positive risk: exact SHA-256, a reviewed YARA match combining loader structure with family-specific strings, or an endpoint plus matching process ancestry.
- Medium confidence / medium false-positive risk: script host spawning hidden PowerShell together with remote image retrieval, in-memory .NET loading, or a double-extension executable from an ISO.
- Low confidence / high false-positive risk: a single domain/IP, FTP/SMTP use, PowerShell, WScript, HTA, or image-named download alone. These are common administrative or application behaviors.
- Credential material extracted from configurations is intentionally not published. Preserve it only in access-controlled evidence and rotate/notify an owner when appropriate.

## Rule-building fields

- Family: `RemcosRAT`
- Campaign pattern: `unicode_marker_powershell_stage`
- Artifact type: `JavaScript`
- SHA-256: `3682d8c438017249510aba8865e979b666265be3ffae760d503f17ccb391afac`
- C2 values: `thrillermotion.4nmn.com:2022`
- Stage URLs: `https://misty-cherry-cea3.uploadsimg.workers.dev/mNHLb`
- Correlate parent/child process, command line, file origin, signer/prevalence and network destination before blocking.

## Reproduction

Run the family batch workflow against the original password-protected MalwareBazaar ZIP. Outputs must retain `executed=false` and `network_contacted=false` unless a separately approved dynamic-analysis workflow was used.
