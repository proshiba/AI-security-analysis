# ValleyRAT-linked UPX/SilverFox case 6546aad60371

- SHA-256: 6546aad603716ebbe02412440e8d8d8e5fd7af80f212c6fe45e50a76f093c6d1
- Campaign type: upx_nrv2e_silverfox_http_bundle
- Analysis level: deep static recovery
- Analysis date: 2026-07-15

## Observed behavior

The initial component uses UPX NRV2E compression. Static recovery exposed an HTTP bundle path and a modified-RC4 transformation. The recovered bundle contains a signed Tencent-related host, a decoy Bright Food component, and nvml.dll in a layout consistent with DLL side-loading.

## Behavior and C2 assessment

- Confirmed distribution URL: http://43.198.235.91/getinstall64
- Expected role: bundle or stage distribution, not confirmed interactive C2
- Final ValleyRAT C2: not recovered
- Confidence: confirmed_distribution_only
- Evidence: recovered downloader string and decoded bundle structure.
- Limitation: no final implant config or protocol-attributed endpoint was available.

## Detection material

Correlate the UPX/NRV2E loader, modified-RC4 routine, HTTP path getinstall64, signed-host plus nvml.dll co-location, and unexpected DLL load. The IP or URL alone has high false-positive and infrastructure-reuse risk.

See [family behavior and C2 model](../../BEHAVIOR-C2.md).