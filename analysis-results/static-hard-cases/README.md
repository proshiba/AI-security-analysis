# Difficult-sample deep static analysis, 2026-07-17

## Scope and safety

This cross-family batch re-ran 80 historically difficult cases with bounded static
parsing, recursive artifact analysis, native entry-CFG triage, and managed IL
triage. All 80 cases were authenticated and analyzed; 142 root/child layers were
examined.

No submitted or recovered sample was executed. CPU instructions were not emulated,
no URL/IP/C2 was contacted, and no recovered binary was persisted in this public
result directory. The only persistent products are sanitized JSON and Markdown:

- [Machine-readable report](deep-static-triage.json)
- [Generated per-case summary](deep-static-triage.md)
- [Workflow, evidence standard, commands, and failure checks](../../analysis-framework/docs/DEEP-STATIC-ANALYSIS.md)

## Validated result

| Metric | Result |
| --- | ---: |
| Inventory cases | 80 |
| Analyzed | 80 |
| Partial / not found / input error | 0 / 0 / 0 |
| Root and child layers | 142 |
| Cases with an observed protector/obfuscator marker | 16 |
| Budget-limited cases | 0 |
| Cases with a missing expected child | 1 |

The absence of a budget limit means the configured traversal bounds were not hit. The
total-layer byte budget is the sum of unique layer payloads admitted to the queue; it
is not a peak-memory limit and excludes parser/unpacker temporary allocations. The
result does not mean that every protector was removed, every encrypted buffer was
decoded, or every terminal payload/configuration was recovered.

## Recovery relations

The 142 analyzed nodes comprise 80 roots and 62 statically recovered children.

| Relation | Layers | Interpretation |
| --- | ---: | --- |
| `root` | 80 | Authenticated inventory inputs |
| `pe-overlay-rar` | 3 | RAR overlays recognized inside large PE roots |
| `pe-resource-opaque` | 12 | Opaque PE resource blobs, hashed and re-triaged as data |
| `pe-resource-pe` | 2 | PE children recovered from PE resources |
| `pe-inflated-gap-removed` | 1 | Structurally reduced PE child from an inflated root |
| `dotnet-resource-opaque` | 36 | Managed manifest resources retained as hashed data layers |
| `dotnet-bitmap-rgb-pe` | 5 | PE children recovered from managed bitmap RGB data |
| `embedded-pe` | 3 | Embedded PE children recovered from container/carrier roots |
| **Total** | **142** | **80 roots + 62 child relations** |

Opaque resource hashes can repeat because different roots embed identical data. The
only repeated **executable PE candidate child** is
`6f7a3520fb5a30d1c747e7d232b219c1c97a2270429da7aa1f572ac2c60b28be`
(1,348,488 bytes). It was recovered from both RedLine Stealer roots
`7fc964fe47e08d13c158f808d0d68f3f2b9341dfb1ba6fb2a48690fe27e22682`
and `7b2a28e5ecbdeb4e608026e8c548ef5f50e4aad5da5ae7bfcc5e9ee05e91e80a`.
The two report entries therefore describe one unique child, not two independent
payload variants.

## Former size-gate cases

The previous over-32-MiB root skip was removed for all six inventory cases. Bounded
PE structure and reachable CFG analysis now runs without copying or linearly scanning
the entire root, and recovered children are queued separately.

| Family | Roots | Static outcome |
| --- | ---: | --- |
| QuasarRAT | 3 | Three large roots parsed; three RAR overlays and six opaque resource layers were identified |
| RedLine Stealer | 2 | Both roots yielded the same PE resource child, `6f7a3520...b28be` |
| HijackLoader | 1 | An inflated gap was removed and PE child `d11395157a7d11095feeb425d686cf6998530458799785fc00d1ce6f36eef910` was analyzed |

"Size gate resolved" means these roots were no longer skipped. It is not a claim that
the RAR contents, packer logic, or final family configuration was universally
recovered.

## Marker and managed-code findings

Observed marker strings were distributed as follows: KoiVM 10, SmartAssembly 2,
Themida 1, UPX 1, Enigma 1, and nsPack 1. These total 16 marker-bearing cases. A
marker is a routing hint, not proof of protector version, successful unpacking, or
family attribution.

Managed IL triage covered 23 layers. All ten Vidar/KoiVM inventory cases produced a
KoiVM routing hint. This is intentionally reported as `koi_vm: suspected`; it does
not prove that OldRod or another version-specific recipe can reconstruct every
method, string, resource, or modified KoiVM variant.

Five managed layers produced `managed_control_flow_flattening: suspected` because one
or more methods contained corroborated high-fanout switches: one njRAT root and one
njRAT child, two Snake Keylogger children, and one VenomRAT child. These are managed
CFG review hints, not confirmed flattening. None of the five is one of the ten
Vidar/KoiVM hints; the two classifications are separate. Managed resource-obfuscation
triage was `suspected` for 11 layers, `inconclusive` for 4, and `not_observed` for 8.

## Native control-flow interpretation and false-positive controls

Classic native control-flow flattening was **not confirmed**. The native heuristic
produced two low-confidence `suspected` rows, but both rows are the same repeated
RedLine child `6f7a3520...b28be`. Its bounded entry CFG has a dispatcher-like shape;
the dispatcher state and original successor mapping have not been recovered, so the
evidence does not meet the confirmation standard.

The following confounder corrections are part of the result:

- Thirteen managed PE layers expose only a small native CLR entry thunk. Native CFF,
  indirect-flow, anti-disassembly, and VM/protector assessments are therefore
  `not_evaluable` and are routed to managed IL instead.
- Five native CFF assessments and four indirect-flow assessments are marked
  `confounded` where packer/protector/container/loader structure can explain the CFG
  shape. These statuses span five roots and are not positive detections. One StealC
  root remains an indirect-flow `suspected` routing hint; its 15 indirect transfers
  do not prove obfuscation or payload recovery.
- UPX, Themida, nsPack, Enigma, SmartAssembly, and KoiVM strings are never treated as
  successful deobfuscation by themselves.
- `not_observed` means only that the bounded reachable entry CFG did not meet the
  heuristic. It does not establish global absence in callbacks, unvisited functions,
  recovered children, or unavailable code.

## Remaining expected-child gap

The only missing expected child is in RemcosRAT root
`78b21599a83dbfad39c17202d37dd2b6d552c9679755bc199a9826f3dd0e40db`.
The inventory expected raw intermediate layer
`e9ed0be544b08189ceca2ec8e6ae8f74d62335ed006f0b207fb211df6bbdcb3a`,
but this batch did not reproduce it. No traversal budget was exhausted. The result
therefore remains an extractor/NSIS/raw-decoder verification gap; it is not evidence
that the historical child never existed or that the root is benign.

## Interpretation boundary

This result improves static prioritization and layer traceability. It does not claim a
universal static unpacker for Themida/WinLicense, KoiVM, VMProtect, Enigma, nsPack,
UPX/MPRESS, custom state machines, or encrypted payload buffers. Confirmed recovery
requires a coherent child format, a new authenticated hash, a reproducible decoder or
dispatcher proof, and family/config validation on the recovered layer.
