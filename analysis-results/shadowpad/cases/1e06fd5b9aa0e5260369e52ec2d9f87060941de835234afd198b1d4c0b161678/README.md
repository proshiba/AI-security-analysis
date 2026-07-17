# ShadowPad case 1e06fd5b9aa0e5260369e52ec2d9f87060941de835234afd198b1d4c0b161678

- Source: VX-Underground ShadowPad collection and embedded resource in `f7ef194f...`
- Artifact: 231,424-byte x64 PE DLL, not packed by section-shape analysis
- Pattern: `scatterbee_iviewers_loader_component`
- Analysis: static only; no execution and no endpoint contact

## Role in the chain

This hash is the `IVIEWERS.dll` component extracted from the reviewed OLEVIEW resource chain. Its role is DLL sideloading/loading support for the separately encrypted ShadowPad payload. Static PE inspection found 78 imports, a normal `.text` entrypoint, no high-entropy section, and no separate ScatterBee or Casper configuration block.

The absence of a standalone config is meaningful: `TCP://fljhcqwe.com:80` belongs to the encrypted payload in the parent dropper, not to a value independently recovered from this DLL. The report therefore keeps chain inheritance separate from direct artifact evidence.

## C2 and IOC evidence

No network endpoint was directly recovered from this DLL. Its submitted hash and the parent dropper hash are the publishable relationship indicators. See the parent case for the decoded C2 configuration.

## Detection material

Detect OLEVIEW-like processes loading `IVIEWERS.dll` from an unexpected writable directory and correlate with the parent/resource hashes. `IVIEWERS.dll` as a filename alone is insufficient and can produce false positives in copied SDK or inspection-tool environments.

