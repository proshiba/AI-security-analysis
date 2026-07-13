# RemcosRAT case 09cc1c776574

## Overview

- SHA-256: `09cc1c77657400e803310dd7ba58a91854fb275e5b29adf53a6ee2827f848366`
- Artifact: VBS
- Delivery/campaign pattern: `vbs_file_carving_powershell_loader`
- Analysis mode: static analysis plus public sandbox evidence; the sample was not executed locally
- Recovered family version: 7.2.6 Pro

## Delivery and behavior

- Reads bytes from a benign Windows binary and reconstructs a PowerShell command
- Launches through Shell.Application.ShellExecute

## Network observables

- Confirmed configuration/sandbox endpoint: `103.67.163.108:2404`
- Confidence: endpoints labeled confirmed were extracted from malware configuration or process-attributed sandbox evidence. Exact-byte duplicate containers inherit the inner payload result explicitly.
- No live C2 check was performed. Current availability and server identity are therefore unknown.

## Shodan pivots

- `ip:"103.67.163.108" port:2404` — infrastructure pivot; not a protocol fingerprint
- Banner hash, HTTP title, certificate hash and JARM: not available from static/sandbox evidence. Do not invent these values; collect only under an approved live-network procedure.

## Detection guidance

- High confidence / low false-positive risk: exact SHA-256, a reviewed YARA match combining loader structure with family-specific strings, or an endpoint plus matching process ancestry.
- Medium confidence / medium false-positive risk: script host spawning hidden PowerShell together with remote image retrieval, in-memory .NET loading, or a double-extension executable from an ISO.
- Low confidence / high false-positive risk: a single domain/IP, FTP/SMTP use, PowerShell, WScript, HTA, or image-named download alone. These are common administrative or application behaviors.
- Credential material extracted from configurations is intentionally not published. Preserve it only in access-controlled evidence and rotate/notify an owner when appropriate.

## Rule-building fields

- Family: `RemcosRAT`
- Campaign pattern: `vbs_file_carving_powershell_loader`
- Artifact type: `VBS`
- SHA-256: `09cc1c77657400e803310dd7ba58a91854fb275e5b29adf53a6ee2827f848366`
- C2 values: `103.67.163.108:2404`
- Stage URLs: none recovered
- Correlate parent/child process, command line, file origin, signer/prevalence and network destination before blocking.

## Reproduction

Run the family batch workflow against the original password-protected MalwareBazaar ZIP. Outputs must retain `executed=false` and `network_contacted=false` unless a separately approved dynamic-analysis workflow was used.
