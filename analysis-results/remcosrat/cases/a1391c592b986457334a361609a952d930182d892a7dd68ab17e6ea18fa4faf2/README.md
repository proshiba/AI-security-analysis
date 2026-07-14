# RemcosRAT case a1391c592b98

## Overview

- SHA-256: `a1391c592b986457334a361609a952d930182d892a7dd68ab17e6ea18fa4faf2`
- Artifact: JavaScript
- Delivery/campaign pattern: `unicode_marker_powershell_stage`
- Analysis mode: static analysis plus public sandbox evidence; the sample was not executed locally
- Recovered family version: 7.2.6 Pro

## Delivery and behavior

- Unicode junk marker reconstruction
- Remote stage and final C2 are distinct observables

## Behavior and C2 assessment

- Observed in this case: Unicode junk marker reconstruction; Remote stage and final C2 are distinct observables.
- Expected payload behavior: After the payload is loaded, Remcos is expected to provide interactive remote administration such as command execution, file/process control, surveillance and persistence. These are family capabilities; the case report lists only behavior actually observed in its delivery/sandbox evidence.
- C2 role assumption: long-lived outbound Remcos command-and-control channel; multiple host/port entries in one recovered configuration are treated as ordered fallback candidates, not separate malware families.
- Endpoint provenance: external sandbox configuration or process-attributed evidence; the submitted loader alone did not establish the final endpoint.
- Distribution separation: `https://misty-cherry-cea3.uploadsimg.workers.dev/pfCLO` are loader/stage locations and are not final C2 unless separately correlated.
- Liveness: no live C2 check was performed for this case; current availability and server ownership remain unknown.
- Confidence labels: delivery behavior is `confirmed` from static code/container structure; payload capability is `inferred` from family/config; listed final endpoints are `confirmed` only to the provenance stated above.

## Network observables

- Confirmed configuration/sandbox endpoint: `kesmn.com:2404`
- Loader/stage URL: `https://misty-cherry-cea3.uploadsimg.workers.dev/pfCLO`
- Confidence: endpoints labeled confirmed were extracted from malware configuration or process-attributed sandbox evidence. Exact-byte duplicate containers inherit the inner payload result explicitly.
- No live C2 check was performed. Current availability and server identity are therefore unknown.

## Shodan pivots

- `hostname:"kesmn.com" port:2404` — infrastructure pivot; not a protocol fingerprint
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
- SHA-256: `a1391c592b986457334a361609a952d930182d892a7dd68ab17e6ea18fa4faf2`
- C2 values: `kesmn.com:2404`
- Stage URLs: `https://misty-cherry-cea3.uploadsimg.workers.dev/pfCLO`
- Correlate parent/child process, command line, file origin, signer/prevalence and network destination before blocking.

## Reproduction

Run the family batch workflow against the original password-protected MalwareBazaar ZIP. Outputs must retain `executed=false` and `network_contacted=false` unless a separately approved dynamic-analysis workflow was used.
