# C2 liveness and Shodan fingerprint collection

`c2_detector.py` performs bounded, profile-driven liveness checks and writes JSON suitable for case reports.

Supported probes:

- `tcp`: connect and optionally send explicit hex; bounded banner capture.
- `vvas`: send the recovered three-byte check-in, read at most 64 bytes, and require the expected header/stage size before setting `c2_confirmed=true`.
- `n520`: negotiate TLS, send no application data, read exactly the 44-byte server-first handshake, and require both its CRC32 and session-derived magic to match before setting `c2_confirmed=true`.
- `http` / `https`: one GET, no redirect, bounded body, status/title/header extraction.
- `tls`: TLS negotiation and certificate metadata without an HTTP request.
- optional Salesforce JARM invocation for TLS services.

Collected detection fields include raw-banner SHA-256, signed MurmurHash3 x86_32 for Shodan `hash:`, HTTP title, TLS version/cipher, certificate SHA-256, JARM, DNS resolution, and generated Shodan query candidates.

N520 server-first detection can be run directly after the target has been reviewed:

```powershell
python .\analysis-framework\common\c2_detector.py 118.107.21.88 9999 --protocol n520 --sni update.microsoft.com --output n520-c2.json
```

This mode sends only the TLS handshake. It does not send the encrypted N520 endpoint check-in.

An explicitly authorized, bounded collection can send one empty command-1 registration and store encrypted frames or command-16/18 plugin payloads only in an AES ZIP:

```powershell
python .\analysis-framework\common\c2_detector.py 118.107.21.88 9999 --protocol n520 --n520-checkin --n520-wait 15 --artifact-zip n520-artifacts.zip --output n520-collection.json
```

The collector sends no station ID, accepts at most 16 MiB for at most 30 seconds, never executes a response, and does not emulate operator/admin commands.

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
- N520 confirmation does not perform the encrypted endpoint check-in or disclose host telemetry; it validates only the server-first handshake.
- HTTP/TLS reachability alone does not prove C2 ownership.
- An all-zero JARM represents no fingerprint and must never become a Shodan query.
- A custom-protocol banner hash is useful in Shodan only if Shodan used a compatible probe payload.
- Store timestamped results and do not overwrite historical DNS/IP/certificate observations.
