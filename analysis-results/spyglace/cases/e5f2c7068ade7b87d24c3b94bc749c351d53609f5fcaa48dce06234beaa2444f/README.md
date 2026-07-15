# SpyGlace v3.1.15 - e5f2c706...

## Identity

- Encoded SHA-256: e5f2c7068ade7b87d24c3b94bc749c351d53609f5fcaa48dce06234beaa2444f
- Recovered PE SHA-256: 7ab9c634216798d50ce3e19bf1650d6b7c2386150340e48ec3af8b38fd30ae4c
- Envelope: repeating XOR with sgznqhtgnghvmzxponum
- Architecture: x64 PE
- Version: 3.1.15

## Static configuration

- C2 IP: 185.18.222.241
- Campaign user ID: SAPPHIRE
- Request paths: 1l8kad.asp, vdlhtr.asp, 7m3yv3.asp, fp4v2i.asp
- Mutex: K31610KIO9834PG79A471
- External-IP discovery: api.ipify.org
- Transport: WinHTTP HTTP POST
- Custom RC4 key: 90b149c69b149c4b99c04d1dc9b940b9

The inferred URLs are the C2 IP combined with each decoded ASP path. They were not contacted. The sample exposes process execution, download/upload, disk enumeration, screenshot and extension-control commands. See config.json for the normalized command/API list, persistence strings, provenance and limitations.

## Detection

High-confidence file detection uses several encoded API, command and config markers together. A single IP or provider access is lower confidence because infrastructure can change and the providers are legitimate. No payload was executed and no credential was collected.
