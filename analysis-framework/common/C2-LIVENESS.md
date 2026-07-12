# C2 liveness and Shodan fingerprint collection

`c2_detector.py` performs bounded, profile-driven liveness checks and writes JSON suitable for case reports.

Supported probes:

- `tcp`: connect and optionally send explicit hex; bounded banner capture.
- `vvas`: send the recovered three-byte check-in, read at most 64 bytes, and require the expected header/stage size before setting `c2_confirmed=true`.
- `http` / `https`: one GET, no redirect, bounded body, status/title/header extraction.
- `tls`: TLS negotiation and certificate metadata without an HTTP request.
- optional Salesforce JARM invocation for TLS services.

Collected detection fields include raw-banner SHA-256, signed MurmurHash3 x86_32 for Shodan `hash:`, HTTP title, TLS version/cipher, certificate SHA-256, JARM, DNS resolution, and generated Shodan query candidates.

## Workflow integration

Live checks are not implicit. A reviewed profile must contain `live_c2_targets`, and the operator must pass `-AllowLiveC2Check`:

```powershell
.\analysis-framework\Invoke-Analysis.ps1 `
  -Sample C:\quarantine\sample.zip `
  -OutputDirectory C:\analysis-output\case `
  -ProfilePath .\analysis-framework\malware\valleyrat\config\profiles\<sha256>.json `
  -AllowLiveC2Check -CollectJarm
```

Outputs are written below `<OutputDirectory>/c2-live/`. `-CollectJarm` causes ten active TLS ClientHello probes and is ignored for non-TLS protocols.

## Interpretation

- `alive=true` means the transport/application endpoint responded sufficiently to the selected probe.
- `c2_confirmed=true` is stricter and requires a malware-protocol-specific match.
- HTTP/TLS reachability alone does not prove C2 ownership.
- An all-zero JARM represents no fingerprint and must never become a Shodan query.
- A custom-protocol banner hash is useful in Shodan only if Shodan used a compatible probe payload.
- Store timestamped results and do not overwrite historical DNS/IP/certificate observations.
