# ValleyRAT / N520 case d11e793159f0

- SHA-256: d11e793159f0da3c88a9ecebb8e5df88919843a1eeaaf71117377db58224a1ae
- Campaign type: single_pe_n520_managed
- Analysis level: deep static analysis plus bounded protocol validation
- Analysis date: 2026-07-15

## Observed behavior

The sample is a managed N520 backdoor. Static recovery identified an HTTP configuration path, AES-256-CBC configuration handling, a custom TLS client, a server-first 44-byte handshake, encrypted and authenticated command frames, plugin acquisition, and result upload. Recovered plugin labels are consistent with terminal, desktop, file, process, registry, and SOCKS-related capability modules.

## Behavior and C2 assessment

- Configuration distribution: http://118.107.21.88:9000/config.enc
- Interactive C2: 118.107.21.88:9999
- TLS SNI: update.microsoft.com
- Presented certificate CN: Windows Update - A4608A21
- Confidence: confirmed
- Evidence: recovered config and cryptographic routine, decompiled protocol, valid server-first handshake, and one bounded empty command-1 check-in.
- Bounded result on 2026-07-15: no station identifier, response, plugin, fallback C2, or operator command was received within 20 seconds and 16 MiB.
- Safety boundary: no guessed command, arbitrary execution, brute force, or server modification.

## Detection material

Correlate the configuration URL, unusual TLS SNI/certificate mismatch, 44-byte server-first handshake, N520 key derivation strings, plugin labels, and a process making both port-9000 HTTP and port-9999 TLS connections. Endpoint-only detection has medium false-positive risk; protocol and process correlation reduces it.

See [family behavior and C2 model](../../BEHAVIOR-C2.md) and [sanitized live summary](n520-live-summary.json).