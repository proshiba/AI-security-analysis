# ShadowPad case ac6938e03f2a076152ee4ce23a39a0bfcd676e4f0b031574d442b6e2df532646

- Source: VX-Underground ShadowPad collection
- Artifact: 108,754-byte x86 PE with `.nsp0/.nsp1/.nsp2` and nsPack-like layout
- Pattern: `casper_nspack_pneword`
- Analysis: static only; no execution and no endpoint contact

## Packing and attribution

The entrypoint is in the 7.996-entropy `.nsp1` section; `.nsp0` has 143,360 virtual bytes and no raw bytes. Only six imports are exposed. The generic Casper stream detector cannot reach the inner loader without an nsPack restoration stage, so `config.json` intentionally reports no local config rather than guessing.

The submitted SHA-256 exactly matches Dr.Web's `BackDoor.ShadowPad.1` technical entry. That primary source documents the same TosBtKbd/Casper module format, four-state plugin/config decryption, QuickLZ compression, 0x858-byte config structure, and config strings for this sample. This report labels those values `confirmed_public_exact_hash`, distinct from the `confirmed_static_config` label used when this repository independently decrypts bytes.

## C2 and IOC evidence

Dr.Web records `www.pneword.net` across HTTP, TCP, and UDP with ports 80, 443, and 53. Resolver `8.8.8.8` is common infrastructure and is excluded from the IOC list. No current liveness test was performed.

## Detection material

Use the exact hash for high-confidence historical detection. A structural rule may combine the `.nsp0/.nsp1/.nsp2` shape, TosBtKbd sideload context, and restored Casper key schedule. nsPack section names or entropy alone are broad packer indicators and have high false-positive risk across unrelated malware and protected software.

Primary source: [Dr.Web BackDoor.ShadowPad.1](https://vms.drweb.com/virus/?i=21995048).

