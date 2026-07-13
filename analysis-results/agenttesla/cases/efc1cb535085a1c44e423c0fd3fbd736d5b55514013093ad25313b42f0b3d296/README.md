# AgentTesla case efc1cb535085

## Overview

- SHA-256: `efc1cb535085a1c44e423c0fd3fbd736d5b55514013093ad25313b42f0b3d296`
- Artifact: JavaScript
- Delivery/campaign pattern: `unicode_marker_powershell_png_stage`
- Analysis mode: static analysis plus public sandbox evidence; the sample was not executed locally

## Delivery and behavior

- Shares stage URL with 1fe1d42d but has a different final FTP endpoint
- Illustrates why delivery and payload/config clustering must remain separate

## Network observables

- Confirmed configuration/sandbox endpoint: `ftp.cyberflor.co:21`
- Loader/stage URL: `https://misty-cherry-cea3.uploadsimg.workers.dev/yIPUi`
- Confidence: endpoints labeled confirmed were extracted from malware configuration or process-attributed sandbox evidence. Exact-byte duplicate containers inherit the inner payload result explicitly.
- No live C2 check was performed. Current availability and server identity are therefore unknown.

## Shodan pivots

- `hostname:"ftp.cyberflor.co" port:21` — infrastructure pivot; not a protocol fingerprint
- Banner hash, HTTP title, certificate hash and JARM: not available from static/sandbox evidence. Do not invent these values; collect only under an approved live-network procedure.

## Detection guidance

- High confidence / low false-positive risk: exact SHA-256, a reviewed YARA match combining loader structure with family-specific strings, or an endpoint plus matching process ancestry.
- Medium confidence / medium false-positive risk: script host spawning hidden PowerShell together with remote image retrieval, in-memory .NET loading, or a double-extension executable from an ISO.
- Low confidence / high false-positive risk: a single domain/IP, FTP/SMTP use, PowerShell, WScript, HTA, or image-named download alone. These are common administrative or application behaviors.
- Credential material extracted from configurations is intentionally not published. Preserve it only in access-controlled evidence and rotate/notify an owner when appropriate.

## Rule-building fields

- Family: `AgentTesla`
- Campaign pattern: `unicode_marker_powershell_png_stage`
- Artifact type: `JavaScript`
- SHA-256: `efc1cb535085a1c44e423c0fd3fbd736d5b55514013093ad25313b42f0b3d296`
- C2 values: `ftp.cyberflor.co:21`
- Stage URLs: `https://misty-cherry-cea3.uploadsimg.workers.dev/yIPUi`
- Correlate parent/child process, command line, file origin, signer/prevalence and network destination before blocking.

## Reproduction

Run the family batch workflow against the original password-protected MalwareBazaar ZIP. Outputs must retain `executed=false` and `network_contacted=false` unless a separately approved dynamic-analysis workflow was used.
