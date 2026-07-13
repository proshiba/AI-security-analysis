# AgentTesla case e059c100a917

## Overview

- SHA-256: `e059c100a917af58168b1e63ebe75cb4558ec144efd91f1ecb145bd9ad79529e`
- Artifact: RAR
- Delivery/campaign pattern: `rar_wrapped_javascript`
- Analysis mode: static analysis plus public sandbox evidence; the sample was not executed locally

## Delivery and behavior

- RAR member SHA-256 equals 7f31b2c4...74d8 exactly
- C2 is inherited from the byte-identical inner payload

## Network observables

- Confirmed configuration/sandbox endpoint: `ftp.4bagh.net:21`
- Confidence: endpoints labeled confirmed were extracted from malware configuration or process-attributed sandbox evidence. Exact-byte duplicate containers inherit the inner payload result explicitly.
- No live C2 check was performed. Current availability and server identity are therefore unknown.

## Shodan pivots

- `hostname:"ftp.4bagh.net" port:21` — infrastructure pivot; not a protocol fingerprint
- Banner hash, HTTP title, certificate hash and JARM: not available from static/sandbox evidence. Do not invent these values; collect only under an approved live-network procedure.

## Detection guidance

- High confidence / low false-positive risk: exact SHA-256, a reviewed YARA match combining loader structure with family-specific strings, or an endpoint plus matching process ancestry.
- Medium confidence / medium false-positive risk: script host spawning hidden PowerShell together with remote image retrieval, in-memory .NET loading, or a double-extension executable from an ISO.
- Low confidence / high false-positive risk: a single domain/IP, FTP/SMTP use, PowerShell, WScript, HTA, or image-named download alone. These are common administrative or application behaviors.
- Credential material extracted from configurations is intentionally not published. Preserve it only in access-controlled evidence and rotate/notify an owner when appropriate.

## Rule-building fields

- Family: `AgentTesla`
- Campaign pattern: `rar_wrapped_javascript`
- Artifact type: `RAR`
- SHA-256: `e059c100a917af58168b1e63ebe75cb4558ec144efd91f1ecb145bd9ad79529e`
- C2 values: `ftp.4bagh.net:21`
- Stage URLs: none recovered
- Correlate parent/child process, command line, file origin, signer/prevalence and network destination before blocking.

## Reproduction

Run the family batch workflow against the original password-protected MalwareBazaar ZIP. Outputs must retain `executed=false` and `network_contacted=false` unless a separately approved dynamic-analysis workflow was used.
