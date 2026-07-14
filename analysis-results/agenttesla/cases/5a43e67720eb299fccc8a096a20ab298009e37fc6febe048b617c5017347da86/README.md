# AgentTesla case 5a43e67720eb

## Overview

- SHA-256: `5a43e67720eb299fccc8a096a20ab298009e37fc6febe048b617c5017347da86`
- Artifact: HTA
- Delivery/campaign pattern: `unicode_marker_powershell_png_stage`
- Analysis mode: static analysis plus public sandbox evidence; the sample was not executed locally

## Delivery and behavior

- Image-like remote stage
- AgentTesla configuration extracted by external sandbox

## Behavior and C2 assessment

- Observed in this case: Image-like remote stage; AgentTesla configuration extracted by external sandbox.
- Expected payload behavior: After the .NET payload is loaded, AgentTesla is expected to collect credentials and host/application data and exfiltrate them through its configured channel. This is family/config-derived capability unless process-attributed evidence says otherwise.
- C2 role assumption: FTP exfiltration/configuration endpoint used to upload stolen information; it is not assumed to be an interactive tasking server.
- Endpoint provenance: external sandbox configuration or process-attributed evidence; the submitted loader alone did not establish the final endpoint.
- Distribution separation: `https://pub-abe8d802bc744774a9b93d3b00a23598.r2.dev/puazad.png` are loader/stage locations and are not final C2 unless separately correlated.
- Liveness: no live C2 check was performed for this case; current availability and server ownership remain unknown.
- Confidence labels: delivery behavior is `confirmed` from static code/container structure; payload capability is `inferred` from family/config; listed final endpoints are `confirmed` only to the provenance stated above.

## Network observables

- Confirmed configuration/sandbox endpoint: `ftp.dankely.org:21`
- Loader/stage URL: `https://pub-abe8d802bc744774a9b93d3b00a23598.r2.dev/puazad.png`
- Confidence: endpoints labeled confirmed were extracted from malware configuration or process-attributed sandbox evidence. Exact-byte duplicate containers inherit the inner payload result explicitly.
- No live C2 check was performed. Current availability and server identity are therefore unknown.

## Shodan pivots

- `hostname:"ftp.dankely.org" port:21` — infrastructure pivot; not a protocol fingerprint
- Banner hash, HTTP title, certificate hash and JARM: not available from static/sandbox evidence. Do not invent these values; collect only under an approved live-network procedure.

## Detection guidance

- High confidence / low false-positive risk: exact SHA-256, a reviewed YARA match combining loader structure with family-specific strings, or an endpoint plus matching process ancestry.
- Medium confidence / medium false-positive risk: script host spawning hidden PowerShell together with remote image retrieval, in-memory .NET loading, or a double-extension executable from an ISO.
- Low confidence / high false-positive risk: a single domain/IP, FTP/SMTP use, PowerShell, WScript, HTA, or image-named download alone. These are common administrative or application behaviors.
- Credential material extracted from configurations is intentionally not published. Preserve it only in access-controlled evidence and rotate/notify an owner when appropriate.

## Rule-building fields

- Family: `AgentTesla`
- Campaign pattern: `unicode_marker_powershell_png_stage`
- Artifact type: `HTA`
- SHA-256: `5a43e67720eb299fccc8a096a20ab298009e37fc6febe048b617c5017347da86`
- C2 values: `ftp.dankely.org:21`
- Stage URLs: `https://pub-abe8d802bc744774a9b93d3b00a23598.r2.dev/puazad.png`
- Correlate parent/child process, command line, file origin, signer/prevalence and network destination before blocking.

## Reproduction

Run the family batch workflow against the original password-protected MalwareBazaar ZIP. Outputs must retain `executed=false` and `network_contacted=false` unless a separately approved dynamic-analysis workflow was used.
