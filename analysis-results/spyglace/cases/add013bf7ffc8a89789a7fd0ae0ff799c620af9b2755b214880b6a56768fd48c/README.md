# SpyGlace v3.1.15 - add013bf...

## Identity

- Encoded SHA-256: add013bf7ffc8a89789a7fd0ae0ff799c620af9b2755b214880b6a56768fd48c
- Recovered PE SHA-256: 88f58087fc7e7a74455d19c0476954c3bd77d36d0683ab57a6598eb72c4ae37c
- Envelope: repeating XOR with sgznqhtgnghvmzxponum
- Architecture: x64 PE
- Version: 3.1.15

## Static configuration

- C2 IP: 31.58.136.207
- Campaign user ID: EVE
- Request paths: x66hjl.asp, fx72rf.asp, guehry.asp, dmd4n2.asp
- Mutex: K31610KIO9834PG79797
- External-IP discovery: api.ipify.org
- Transport: WinHTTP HTTP POST
- Custom RC4 key: 90b149c69b149c4b99c04d1dc9b940b9

The build-level differentiator from the other EVE samples is the payload hash and mutex suffix. Static command and WinHTTP API sets otherwise match. See config.json for machine-readable details. No C2 request was sent.
