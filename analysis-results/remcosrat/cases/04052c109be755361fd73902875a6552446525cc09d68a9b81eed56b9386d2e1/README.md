# RemcosRAT case 04052c109be7

## Overview

- SHA-256: `04052c109be755361fd73902875a6552446525cc09d68a9b81eed56b9386d2e1`
- Artifact: VBS
- Delivery/campaign pattern: `vbs_wmi_powershell_loader`
- Analysis mode: static analysis plus public sandbox evidence; the sample was not executed locally
- Recovered family version: not recovered

## Delivery and behavior

- Obfuscated VBS with WScript/WMI-oriented execution path
- External sandbox observed WScript and PowerShell before Remcos configuration extraction

## Network observables

- Confirmed configuration/sandbox endpoint: `102.220.160.21:2404`
- Confidence: endpoints labeled confirmed were extracted from malware configuration or process-attributed sandbox evidence. Exact-byte duplicate containers inherit the inner payload result explicitly.
- No live C2 check was performed. Current availability and server identity are therefore unknown.

## Shodan pivots

- `ip:"102.220.160.21" port:2404` — infrastructure pivot; not a protocol fingerprint
- Banner hash, HTTP title, certificate hash and JARM: not available from static/sandbox evidence. Do not invent these values; collect only under an approved live-network procedure.

## Detection guidance

- High confidence / low false-positive risk: exact SHA-256, a reviewed YARA match combining loader structure with family-specific strings, or an endpoint plus matching process ancestry.
- Medium confidence / medium false-positive risk: script host spawning hidden PowerShell together with remote image retrieval, in-memory .NET loading, or a double-extension executable from an ISO.
- Low confidence / high false-positive risk: a single domain/IP, FTP/SMTP use, PowerShell, WScript, HTA, or image-named download alone. These are common administrative or application behaviors.
- Credential material extracted from configurations is intentionally not published. Preserve it only in access-controlled evidence and rotate/notify an owner when appropriate.

## Rule-building fields

- Family: `RemcosRAT`
- Campaign pattern: `vbs_wmi_powershell_loader`
- Artifact type: `VBS`
- SHA-256: `04052c109be755361fd73902875a6552446525cc09d68a9b81eed56b9386d2e1`
- C2 values: `102.220.160.21:2404`
- Stage URLs: none recovered
- Correlate parent/child process, command line, file origin, signer/prevalence and network destination before blocking.

## Reproduction

Run the family batch workflow against the original password-protected MalwareBazaar ZIP. Outputs must retain `executed=false` and `network_contacted=false` unless a separately approved dynamic-analysis workflow was used.
