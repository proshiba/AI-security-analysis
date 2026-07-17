# Static unpackers

This directory contains the shared, bounded unpacking pipeline. It does not
launch samples, recovered payloads, installer callbacks, scripts, or packer
stubs, and it never contacts extracted infrastructure.

## Supported recovery paths

| Layer | Static method | Result |
|---|---|---|
| ZIP/CAB/7z/RAR | bounded 7-Zip inventory and extraction | retained members and recursive analysis |
| NSIS | NSIS-aware 7-Zip script decompilation | `[NSIS].nsi`, members, and explicit script transformations |
| NSIS hexadecimal XOR stream | reproduce `IntOp` + `IntFmt %08X` word decoding | System-plugin call stream |
| NSIS native XOR loader | bounded x64 constant propagation, then dword XOR | intermediate loader; never executed |
| UPX | run the trusted UPX utility against a quarantined input | unpacked PE when UPX validates the file |
| PE resources and overlay | parse offsets and sizes; carve valid PE extents | child PE/resources |
| .NET ResourceSet | parse serialized resources without deserializing objects | strings, byte arrays, and images |
| .NET bitmap steganography | reproduce bounded RGB column traversal | embedded managed PE |
| AutoIt A3X | decode literals, RC4, and LZNT1 when the script states the recipe | embedded PE |
| JavaScript string-array obfuscation | parse the array, solve rotation, decode aliases, fold literals | readable script and URLs |
| UTF-16 JavaScript droppers | fold numeric arrays, repeating Unicode key transforms, and environment chunks | PowerShell plus terminal PE |
| JavaScript AES/GZip chain | parse embedded AES-CBC key/IV and GZip recipe | terminal managed PE |
| CMD echo Base64 stream | group redirections by target, join chunks, then validate | terminal PE/archive without fragment noise |
| Jadoo split bundle | validate manifest offsets and lengths | reconstructed file |
| generic base64/hex | size- and format-gated decoding | child layer |
| Mach-O | header and segment inventory | packing assessment only |

static_unpacker.py is the orchestrator. javascript_obfuscator.py handles
script encodings and string-array layers. javascript_dropper_unpacker.py
handles numeric-array, Unicode environment, AES-CBC, and GZip chains.
nsis_unpacker.py handles explicit NSIS script and native constant-XOR layers.
`static_control_flow.py` provides bounded recursive x86/x64 entry-CFG triage.
`managed_il_triage.py` inventories managed metadata, CIL, and resources without CLR loading.

## Tooling

The recommended 7-Zip binary is an NSIS-decompiling build. It is used only as a
trusted archive parser; installers are never run.

```powershell
$Python = 'C:\Users\Administrator\Tools\Python313\python.exe'
$SevenZipNSIS = 'C:\Users\Administrator\Tools\7z-nsis-26.02\7z.exe'
$UPX = 'C:\Users\Administrator\Tools\upx\upx-5.1.1-win64\upx.exe'
$DiE = 'C:\Users\Administrator\Tools\DetectItEasy-3.21\die\diec.exe'

& $Python .\unpackers\static_unpacker.py `
  --input C:\analysis\sample.quarantine.bin `
  --output C:\analysis\unpack.json `
  --artifact-zip C:\analysis\recovered-artifacts.zip `
  --upx $UPX `
  --sevenzip $SevenZipNSIS `
  --diec $DiE
```

Recovered bytes are written only when `--artifact-zip` is supplied. The archive
is AES-encrypted with the analysis password `infected`. Do not add it to Git.
Reports contain hashes, sizes, formats, transformations, confidence, and the
facts that the sample was not executed and no network was contacted.

The NSIS native constant analysis requires the Python `capstone` package. It
performs linear propagation of register/immediate arithmetic only. It does not
emulate memory, calls, branches, or the sample.

## Recursive family pipeline

Use the NSIS-aware binary for a complete offline family pass:

```powershell
& $Python .\analysis-framework\common\analyze_stealer_set.py `
  --manifest C:\Users\Administrator\MalwareSamples\refresh-YYYYMMDD\RemcosRAT\manifest.json `
  --output C:\Users\Administrator\malware-lab\refresh-YYYYMMDD\RemcosRAT `
  --definitions .\analysis-framework\definitions `
  --upx $UPX `
  --sevenzip $SevenZipNSIS `
  --diec $DiE
```

The pipeline recursively inspects a maximum of two recovered generations and
stores recovered bytes only in the encrypted local analysis archive.

## Status interpretation

`artifacts_recovered` means that at least one inner layer was reconstructed. It
does not mean that the final malware payload was unpacked. A case is fully
unpacked only when the terminal executable or script is structurally valid and
no additional packing/protection layer is evidenced.

Use the following blocker classes in reports:

- `unsupported_static_transform`: the decoder is not yet implemented.
- `native_control_flow_obfuscation`: a native loader remains after a verified
  transform; execution or emulation would be required to continue reliably.
- `runtime_derived_key`: the key depends on machine state, timing, or remote
  content.
- `missing_external_payload`: the delivery layer references content that is not
  present in the submitted archive.
- `encrypted_container`: a required password is unknown.
- `corrupt_or_truncated`: declared bounds or headers cannot be validated.
- `not_packed`: high entropy or obfuscation exists, but there is no separate
  packer layer to remove.

## Failure checks

1. Confirm that the outer archive is still AES-encrypted and readable with the
   expected intake password.
2. Use the NSIS-aware 7-Zip build; standard 7-Zip may extract files without the
   decompiled `[NSIS].nsi` control flow.
3. Check `inventory`, `retained_members`, `split_reassembly`, and
   `nsis_script_recovery` before treating an empty `recovered` list as final.
4. Compare the decoder offset, size, key, source offset, output SHA-256, and
   magic with the report. Reject out-of-bounds or ambiguous transforms.
5. Analyze every recovered layer recursively. A valid PE can itself be packed.
6. Treat DiE/entropy findings as hints. They do not independently prove packing.
7. If the remaining stage is a control-flow-obfuscated native loader, record the
   blocker; do not silently label it fully unpacked.

## Verification and API documentation

```powershell
& $Python -m pytest .\unpackers\tests -q
& $Python -m pydoc unpackers.static_unpacker
& $Python -m pydoc unpackers.javascript_obfuscator
& $Python -m pydoc unpackers.javascript_dropper_unpacker
& $Python -m pydoc unpackers.nsis_unpacker
```

The unit tests cover bounded decoding, malformed input, exact hashes/sizes,
JavaScript rotation, UTF-16 normalization, numeric-array and Unicode environment
recovery, AES-CBC/GZip transforms, chunked CMD Base64 reconstruction, .NET
bitmap recovery, AutoIt layers, split reconstruction, NSIS word decoding,
static XOR-loop recognition, and end-to-end synthetic NSIS recovery.

## PureHVNC and CHRD/Donut recovery

- `purehvnc_unpacker.py` finds structurally valid PE files behind the observed first-byte/index-XOR envelope, including sparse stride-four storage.
- `donut_unpacker.py` supports the reviewed modern `0x290` and legacy `0x23c` Donut layouts, Chaskey CTR, uncompressed modules, and optional aPLib recovery.
- `chrd_donut_unpacker.py` reconstructs the reviewed CHRD resource carrier through WAV, numeric segments, outer transform, Donut, a managed TripleDES/GZip resource loader, and the terminal PE.

The CHRD integration fixture recovered terminal SHA-256 `c1a2b48d4f639b46cf6cde8322666f0991531ef32ffe571140418ae40342ffe8` without execution or networking. Generated binaries belong in a quarantine/output path and must not be committed.

## APT-C-60 / SpyGlace recovery

- apt_c60_delivery.py safely inspects LNK strings and strict Base64/TAR carriers, then reproduces only the explicit copy /b fragment concatenation.
- spyglace_unpacker.py recognizes literal PE data and the two reviewed repeating-XOR envelopes, validates PE structure and assigns a static role.
- Neither module launches LNK, JavaScript, Git, scripts, loaders or recovered PEs.

See docs/APT-C60-2026-WORKFLOW.md for command order and failure checks.

## Current Donut, container, and large-file support

- `donut_unpacker.py` supports current `0x240` and `0x230` array layouts in
  addition to the reviewed modern and legacy layouts. It validates the
  call-over-instance prologue, API count, DLL basename list, decrypted PE
  extent, and output hashes.
- `donut_wrapper_unpacker.py` recovers the reviewed 32-byte XOR wrapper only
  after validating its decoded `SystemRoot`, `System32\conhost.exe`, and
  quoted-argument templates.
- `container_recovery.py` handles concatenated XZ streams, bounded XML-plist
  trailers, Mach-O FAT slices, and inflated PE certificate gaps.
- `static_unpacker.py` treats Apple disk images and multi-member malware-owned
  archives as recursive layers. Files larger than 64 MiB use deterministic
  bounded entropy sampling and a bounded marker probe.

All transformations are structure-validated and performed in memory or in
quarantined temporary paths. A recovered PE is analyzed recursively but is
never launched.

## Electron ASAR and Java/Mach-O boundaries

- `asar_unpacker.py` validates Chromium ASAR pickle boundaries, member offsets,
  integrity metadata, traversal-safe names, and total output limits before it
  returns in-memory members.
- `electron_nsis_unpacker.py` uses 7-Zip only as a parser to locate a nested
  Electron archive and recover `resources/app.asar`; it does not launch NSIS,
  Electron, JavaScript, or a recovered payload.
- `static_unpacker.py` applies both paths recursively and can deobfuscate the
  reviewed plain JavaScript string-array rotation without evaluating JavaScript.
- Java class files and universal Mach-O share the `CAFEBABE` magic. The format
  detector now requires a plausible bounded Mach-O architecture table and
  otherwise labels the object `java-class`.

Related tests are `test_asar_unpacker.py`, `test_electron_nsis_unpacker.py`,
`test_javascript_plain_array.py`, and the Java/Mach-O regression in
`test_static_unpacker.py`.
