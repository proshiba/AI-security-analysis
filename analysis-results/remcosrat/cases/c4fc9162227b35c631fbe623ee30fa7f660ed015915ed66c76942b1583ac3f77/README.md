# RemcosRAT case c4fc9162227b

## Overview

- SHA-256: `c4fc9162227b35c631fbe623ee30fa7f660ed015915ed66c76942b1583ac3f77`
- Artifact: PE32
- Delivery/campaign pattern: `direct_native_pe`
- Analysis mode: static analysis plus public sandbox evidence; the sample was not executed locally
- Recovered family version: not recovered

## Delivery and behavior

- Native x86 Remcos with browser theft, keylogging, mutex and IP-geolocation strings
- MalwareBazaar tag mentions 37.27.30.5, but no port/config was independently recovered; do not promote the tag pivot to confirmed C2

## Network observables

- No independently confirmed final C2 endpoint was recovered.
- Confidence: endpoints labeled confirmed were extracted from malware configuration or process-attributed sandbox evidence. Exact-byte duplicate containers inherit the inner payload result explicitly.
- No live C2 check was performed. Current availability and server identity are therefore unknown.

## Shodan pivots

- Confirmed host/port was not recovered, so no defensible Shodan query is emitted.
- Banner hash, HTTP title, certificate hash and JARM: not available from static/sandbox evidence. Do not invent these values; collect only under an approved live-network procedure.

## Detection guidance

- High confidence / low false-positive risk: exact SHA-256, a reviewed YARA match combining loader structure with family-specific strings, or an endpoint plus matching process ancestry.
- Medium confidence / medium false-positive risk: script host spawning hidden PowerShell together with remote image retrieval, in-memory .NET loading, or a double-extension executable from an ISO.
- Low confidence / high false-positive risk: a single domain/IP, FTP/SMTP use, PowerShell, WScript, HTA, or image-named download alone. These are common administrative or application behaviors.
- Credential material extracted from configurations is intentionally not published. Preserve it only in access-controlled evidence and rotate/notify an owner when appropriate.

## Rule-building fields

- Family: `RemcosRAT`
- Campaign pattern: `direct_native_pe`
- Artifact type: `PE32`
- SHA-256: `c4fc9162227b35c631fbe623ee30fa7f660ed015915ed66c76942b1583ac3f77`
- C2 values: none confirmed
- Stage URLs: none recovered
- Correlate parent/child process, command line, file origin, signer/prevalence and network destination before blocking.

## Reproduction

Run the family batch workflow against the original password-protected MalwareBazaar ZIP. Outputs must retain `executed=false` and `network_contacted=false` unless a separately approved dynamic-analysis workflow was used.
