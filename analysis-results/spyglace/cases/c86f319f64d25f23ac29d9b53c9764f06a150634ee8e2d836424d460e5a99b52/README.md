# SpyGlace v3.1.15 - c86f319f...

## Identity

- Encoded SHA-256: c86f319f64d25f23ac29d9b53c9764f06a150634ee8e2d836424d460e5a99b52
- Recovered PE SHA-256: 7621e4eff855b2679188b33fe4c71c377f6e2d0b9c25d939452e18992c52e067
- Envelope: repeating XOR with sgznqhtgnghvmzxponum
- Architecture: x64 PE
- Version: 3.1.15

## Static configuration

- C2 IP: 31.58.136.207
- Campaign user ID: EVE
- Request paths: x66hjl.asp, fx72rf.asp, guehry.asp, dmd4n2.asp
- Mutex: K31610KIO9834PG79787
- External-IP discovery: api.ipify.org
- Transport: WinHTTP HTTP POST
- Custom RC4 key: 90b149c69b149c4b99c04d1dc9b940b9

The build-level differentiator from the other EVE samples is the payload hash and mutex suffix. Static command and WinHTTP API sets otherwise match. See config.json for machine-readable details. No C2 request was sent.
