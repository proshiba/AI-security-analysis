# AgentTesla case 98287949544f

## Overview

- SHA-256: `98287949544f5d5e814f0febc7e87f3085a24405c3f193f60514d7231ea19bce`
- Artifact: JavaScript
- Delivery/campaign pattern: `fromcharcode_eval_loader`
- Analysis mode: static analysis plus public sandbox evidence; the sample was not executed locally

## Delivery and behavior

- fromCharCode/eval-style JavaScript loader
- AgentTesla SMTP exfiltration configuration

## Behavior and C2 assessment

- Observed in this case: fromCharCode/eval-style JavaScript loader; AgentTesla SMTP exfiltration configuration.
- Expected payload behavior: After the .NET payload is loaded, AgentTesla is expected to collect credentials and host/application data and exfiltrate them through its configured channel. This is family/config-derived capability unless process-attributed evidence says otherwise.
- C2 role assumption: SMTP exfiltration/configuration endpoint used to upload stolen information; it is not assumed to be an interactive tasking server.
- Endpoint provenance: external sandbox configuration or process-attributed evidence; the submitted loader alone did not establish the final endpoint.
- Liveness: no live C2 check was performed for this case; current availability and server ownership remain unknown.
- Confidence labels: delivery behavior is `confirmed` from static code/container structure; payload capability is `inferred` from family/config; listed final endpoints are `confirmed` only to the provenance stated above.

## Network observables

- Confirmed configuration/sandbox endpoint: `smtp.hostinger.com:587`
- Confidence: endpoints labeled confirmed were extracted from malware configuration or process-attributed sandbox evidence. Exact-byte duplicate containers inherit the inner payload result explicitly.
- No live C2 check was performed. Current availability and server identity are therefore unknown.

## Shodan pivots

- `hostname:"smtp.hostinger.com" port:587` — infrastructure pivot; not a protocol fingerprint
- Banner hash, HTTP title, certificate hash and JARM: not available from static/sandbox evidence. Do not invent these values; collect only under an approved live-network procedure.

## Detection guidance

- High confidence / low false-positive risk: exact SHA-256, a reviewed YARA match combining loader structure with family-specific strings, or an endpoint plus matching process ancestry.
- Medium confidence / medium false-positive risk: script host spawning hidden PowerShell together with remote image retrieval, in-memory .NET loading, or a double-extension executable from an ISO.
- Low confidence / high false-positive risk: a single domain/IP, FTP/SMTP use, PowerShell, WScript, HTA, or image-named download alone. These are common administrative or application behaviors.
- Credential material extracted from configurations is intentionally not published. Preserve it only in access-controlled evidence and rotate/notify an owner when appropriate.

## Rule-building fields

- Family: `AgentTesla`
- Campaign pattern: `fromcharcode_eval_loader`
- Artifact type: `JavaScript`
- SHA-256: `98287949544f5d5e814f0febc7e87f3085a24405c3f193f60514d7231ea19bce`
- C2 values: `smtp.hostinger.com:587`
- Stage URLs: none recovered
- Correlate parent/child process, command line, file origin, signer/prevalence and network destination before blocking.

## Reproduction

Run the family batch workflow against the original password-protected MalwareBazaar ZIP. Outputs must retain `executed=false` and `network_contacted=false` unless a separately approved dynamic-analysis workflow was used.
