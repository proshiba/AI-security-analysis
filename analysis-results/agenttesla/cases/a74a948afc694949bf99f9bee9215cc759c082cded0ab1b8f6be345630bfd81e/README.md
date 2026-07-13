# AgentTesla case a74a948afc69

## Overview

- SHA-256: `a74a948afc694949bf99f9bee9215cc759c082cded0ab1b8f6be345630bfd81e`
- Artifact: JavaScript
- Delivery/campaign pattern: `javascript_aes_inmemory_dotnet`
- Analysis mode: static analysis plus public sandbox evidence; the sample was not executed locally

## Delivery and behavior

- Large one-line obfuscated JavaScript
- Shares SMTP infrastructure and loader pattern with a01716c2

## Network observables

- Confirmed configuration/sandbox endpoint: `server275.web-hosting.com:587`
- Confidence: endpoints labeled confirmed were extracted from malware configuration or process-attributed sandbox evidence. Exact-byte duplicate containers inherit the inner payload result explicitly.
- No live C2 check was performed. Current availability and server identity are therefore unknown.

## Shodan pivots

- `hostname:"server275.web-hosting.com" port:587` — infrastructure pivot; not a protocol fingerprint
- Banner hash, HTTP title, certificate hash and JARM: not available from static/sandbox evidence. Do not invent these values; collect only under an approved live-network procedure.

## Detection guidance

- High confidence / low false-positive risk: exact SHA-256, a reviewed YARA match combining loader structure with family-specific strings, or an endpoint plus matching process ancestry.
- Medium confidence / medium false-positive risk: script host spawning hidden PowerShell together with remote image retrieval, in-memory .NET loading, or a double-extension executable from an ISO.
- Low confidence / high false-positive risk: a single domain/IP, FTP/SMTP use, PowerShell, WScript, HTA, or image-named download alone. These are common administrative or application behaviors.
- Credential material extracted from configurations is intentionally not published. Preserve it only in access-controlled evidence and rotate/notify an owner when appropriate.

## Rule-building fields

- Family: `AgentTesla`
- Campaign pattern: `javascript_aes_inmemory_dotnet`
- Artifact type: `JavaScript`
- SHA-256: `a74a948afc694949bf99f9bee9215cc759c082cded0ab1b8f6be345630bfd81e`
- C2 values: `server275.web-hosting.com:587`
- Stage URLs: none recovered
- Correlate parent/child process, command line, file origin, signer/prevalence and network destination before blocking.

## Reproduction

Run the family batch workflow against the original password-protected MalwareBazaar ZIP. Outputs must retain `executed=false` and `network_contacted=false` unless a separately approved dynamic-analysis workflow was used.
