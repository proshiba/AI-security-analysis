# RemcosRAT case b3d07e47793a

## Overview

- SHA-256: `b3d07e47793a40bf3d99133b7a58feffe5bf8d27ea42a8e45eba322bc02cf8fb`
- Artifact: ISO9660
- Delivery/campaign pattern: `iso_double_extension_pe`
- Analysis mode: static analysis plus public sandbox evidence; the sample was not executed locally
- Recovered family version: 7.2.6 Pro

## Delivery and behavior

- ISO contains Bonifico n.1101252230290346.docx.exe
- Contained PE SHA-256 equals 52bd61ba...acf5 exactly; configuration is inherited from that identical payload

## Network observables

- Confirmed configuration/sandbox endpoint: `37.27.30.5:2404`
- Confirmed configuration/sandbox endpoint: `37.27.30.5:2405`
- Confirmed configuration/sandbox endpoint: `37.27.30.5:2406`
- Confidence: endpoints labeled confirmed were extracted from malware configuration or process-attributed sandbox evidence. Exact-byte duplicate containers inherit the inner payload result explicitly.
- No live C2 check was performed. Current availability and server identity are therefore unknown.

## Shodan pivots

- `ip:"37.27.30.5" port:2404` — infrastructure pivot; not a protocol fingerprint
- `ip:"37.27.30.5" port:2405` — infrastructure pivot; not a protocol fingerprint
- `ip:"37.27.30.5" port:2406` — infrastructure pivot; not a protocol fingerprint
- Banner hash, HTTP title, certificate hash and JARM: not available from static/sandbox evidence. Do not invent these values; collect only under an approved live-network procedure.

## Detection guidance

- High confidence / low false-positive risk: exact SHA-256, a reviewed YARA match combining loader structure with family-specific strings, or an endpoint plus matching process ancestry.
- Medium confidence / medium false-positive risk: script host spawning hidden PowerShell together with remote image retrieval, in-memory .NET loading, or a double-extension executable from an ISO.
- Low confidence / high false-positive risk: a single domain/IP, FTP/SMTP use, PowerShell, WScript, HTA, or image-named download alone. These are common administrative or application behaviors.
- Credential material extracted from configurations is intentionally not published. Preserve it only in access-controlled evidence and rotate/notify an owner when appropriate.

## Rule-building fields

- Family: `RemcosRAT`
- Campaign pattern: `iso_double_extension_pe`
- Artifact type: `ISO9660`
- SHA-256: `b3d07e47793a40bf3d99133b7a58feffe5bf8d27ea42a8e45eba322bc02cf8fb`
- C2 values: `37.27.30.5:2404`, `37.27.30.5:2405`, `37.27.30.5:2406`
- Stage URLs: none recovered
- Correlate parent/child process, command line, file origin, signer/prevalence and network destination before blocking.

## Reproduction

Run the family batch workflow against the original password-protected MalwareBazaar ZIP. Outputs must retain `executed=false` and `network_contacted=false` unless a separately approved dynamic-analysis workflow was used.
