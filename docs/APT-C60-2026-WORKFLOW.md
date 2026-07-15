# APT-C-60 / SpyGlace offline analysis workflow

This procedure turns an acquired delivery artifact or a local mirror of a public attacker repository into publish-safe hashes, layer metadata, SpyGlace configuration and detection pivots. It never requires malware execution or live C2 access.

## Preconditions

- Work from an isolated analysis directory outside Git.
- Treat every downloaded blob, archive, LNK and recovered PE as malicious.
- Set PYTHONPATH to the repository root and analysis-framework/src.
- Keep Ghidra MCP on localhost, pass an explicit program selector and leave arbitrary script execution disabled.
- Record acquisition source and time before transforming any artifact.

PowerShell setup:

    $Repo = 'C:\Users\Administrator\AI-security-analysis'
    $Python = 'C:\Users\Administrator\Tools\Python313\python.exe'
    $env:PYTHONPATH = "$Repo;$Repo\analysis-framework\src;$Repo\analysis-framework\common"
    Set-Location $Repo

## Execution order

### 1. Inventory a local Git mirror

Acquire a mirror only when collection is authorized, then inventory every reachable historical blob:

    & $Python .\analysis-framework\common\repository_history_collector.py --git-dir C:\analysis\mirrors\owner__repo.git --output C:\analysis\inventory\owner__repo.json --export-dir C:\analysis\blobs\owner__repo

Expected output includes commit_count, commit metadata, every unique blob and its paths, SHA-256, format and literal IOC candidates. The collector does not execute content.

Failure checks:

- "not a git repository": point --git-dir at the bare mirror directory containing HEAD and objects.
- Missing deleted content: confirm the mirror includes all refs and rerun git rev-list --all.
- skipped maximum_blob_size: increase the explicit bound only after confirming available quarantine storage.
- Empty repository: retain the liveness result; do not infer that it was never used.

### 2. Inspect LNK and delivery archives

Inspect an LNK without opening it:

    & $Python .\unpackers\apt_c60_delivery.py --input C:\analysis\quarantine\sample.lnk --kind lnk --report C:\analysis\reports\lnk.json

For a strict Base64 carrier containing the TAR bundle:

    & $Python .\unpackers\apt_c60_delivery.py --input C:\analysis\quarantine\contributing.txt --kind base64-tar --payload-output C:\analysis\quarantine\iconcache.dat --report C:\analysis\reports\delivery.json

Expected delivery output identifies embedded URLs/actions or the TAR, install script, ordered TMI fragments, destination and reconstructed payload hash.

Failure checks:

- carrier is not strict Base64: verify that the correct historical blob was selected and was not HTML or Git LFS metadata.
- decoded data is not a TAR archive: keep the hash and classify the layer as an unknown carrier; do not use permissive deserialization.
- unsafe TAR member or TAR links: stop extraction and report the path-safety violation.
- missing fragments: locate the matching commit/version; do not concatenate fragments from unrelated commits.
- copy /b not found: inspect script encodings and filenames statically, then add a reviewed parser fixture before changing production logic.

### 3. Recover repository envelopes

The unified extractor can recover known envelopes in memory, so writing a decoded PE is optional. For reverse engineering only, write the PE to quarantine:

    & $Python .\unpackers\spyglace_unpacker.py --input C:\analysis\blobs\encoded.tmp --output C:\analysis\quarantine\recovered.bin --report C:\analysis\reports\unpack.json

Expected output is method, input/payload SHA-256, size and role. Supported transforms are a literal PE and repeating XOR with sgznqhtgnghvmzxponum or AadDDRTaSPtyAG57er#$ad!lDKTOPLTEL78pE.

Failure checks:

- no supported envelope: verify the blob hash and file generation, then test it as a container or script instead of guessing a key.
- role unknown_pe: preserve the decoded hash and run generic static PE inspection; do not force a SpyGlace label.
- invalid PE: reject out-of-bounds headers or an implausible section count.

### 4. Extract SpyGlace configuration

Run directly against either the encoded repository blob or decoded PE:

    & $Python -m extractors.config_extractor --family spyglace --input C:\analysis\blobs\encoded.tmp --output C:\analysis\reports\config.json

Expected output includes C2 IP, user ID, request paths, mutex, command/API set, custom-RC4 key, persistence strings, payload hash, envelope method and explicit no-execution/no-network fields.

Failure checks:

- variant unrecognized: confirm a valid SpyGlace PE was recovered and inspect both transform domains.
- C2 missing but commands present: treat it as a possible version/config-layout change and add a hash-scoped fixture before widening regex.
- paths missing: search decoded strings for bounded ASP-like values and verify references in Ghidra.
- AES constants null: null means they were not literal in that binary; do not populate them only because an older report documented them.
- inferred URLs: an IP plus a path is a pivot, not evidence that HTTP or that endpoint is live.

### 5. Reverse engineer a novel build

Import only the quarantined decoded PE. In Ghidra MCP calls, always specify the exact program. Confirm:

1. The command/API decoder implements (encoded XOR 3) minus 1.
2. The config decoder implements (encoded XOR 2) minus 1.
3. References to WinHTTP APIs and each recovered ASP path.
4. Command dispatch comparisons and process, file, screenshot and extension handlers.
5. Loader persistence CLSIDs and payload paths.

Use FLOSS static mode as a secondary string source. A decoded-string timeout or no decoded strings is a tool limitation, not proof that strings are absent.

### 6. Generate passive infrastructure pivots

    & $Python .\analysis-framework\malware\spyglace\c2_detector.py --input C:\analysis\blobs\encoded.tmp --output C:\analysis\reports\passive-c2.json

This step emits Shodan query text only. It does not probe a host. Leave banner hash, title, certificate hash and JARM null unless obtained from an authorized passive source with provenance and observation time.

### 7. Validate detections and regression tests

    & $Python -m pytest .\unpackers\tests\test_spyglace_unpacker.py .\unpackers\tests\test_apt_c60_delivery.py .\extractors\tests\test_spyglace_extractor.py .\emulators\spyglace\tests\test_lab.py .\analysis-framework\malware\spyglace\tests\test_detection.py -q

Validate every Sigma document with a YAML parser and compile the YARA file when yara is available. A detection release must include false-positive analysis at high, medium and low confidence.

## Publish-safe output

Commit only:

- config/report JSON without raw sample bytes, secrets or victim data;
- acquisition hashes and transformation provenance;
- repository liveness at a stated time;
- IOC CSV, Sigma/YARA, family/campaign definitions and limitations;
- unit tests and pydoc.

Never commit raw/decoded malware, repository mirrors, task files named after victim devices, packet captures containing victim data or a live-response body.

## Escalation path for new variants

When a version does not match existing logic, preserve the unknown result and add a separate campaign/layout branch. Do not weaken the existing classifier globally. Create a minimal non-malicious fixture, document the new transform, add unit tests for success and malformed input, regenerate pydoc and rerun the prior v3.1.15 cases.
