# VenomRAT case 6d25076b0cf8d493bd252bcfdee87c9ec9e23ddb814cfc671e3e80d31e2bf6f8

- Source: [MalwareBazaar](https://bazaar.abuse.ch/sample/6d25076b0cf8d493bd252bcfdee87c9ec9e23ddb814cfc671e3e80d31e2bf6f8/)
- Original name: `198805306d17118fa6bd5f8444007622.exe`
- Artifact: 1,510,400-byte native x64 PE
- Campaign type: `native_resource_loader`

## Static behavior

The native loader imports process and registry-related functionality and contains 24 PE resources. The main recovery target is resource type `EXPAND`, ID `2499`: 956,928 bytes, SHA-256 `375a5738ea0b982b542ca17d129e0c936cc55203cac206fea28f17b8757b804b`, entropy 6.541. Resource type 3/ID 16 is 61,849 bytes with entropy 7.945.

Certificate and revocation URLs embedded in signatures are excluded from malware infrastructure. No final payload/configuration was independently recovered, so there is no confirmed C2 for this hash in the current static result.

## Detection material

Treat the unusual named `EXPAND` resource, its size/hash, loader APIs, and surrounding execution chain as medium-confidence material. Generic resource entropy or `VirtualAlloc` alone has high false-positive potential.

Bounded Base64, reverse, gzip/zlib, AES-literal, and .NET PE-carving transforms produced no embedded managed payload. Certificate-related URLs returned by generic string scanning were rejected as C2.
