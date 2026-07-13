# Safe submission I/O and batch workflow

`common/malware_io.py` is the only default implementation for MalwareBazaar AES-ZIP authentication, archive member path validation, inner hashing, script text decoding, safe output names, JSON output, and static-analysis safety markers.

## Design rules

- Decrypted bytes remain in memory unless `extract_malwarebazaar_member.py` is explicitly invoked.
- Every member name is checked for absolute paths, drive prefixes, and `..` traversal.
- Single-member tools use `read_single_aes_zip_member`; generic triage uses `read_aes_zip_members`.
- UTF-16 is selected from BOM or NUL-byte distribution before UTF-8/Windows-1252 fallback.
- JSON evidence ends with `executed=false` and `network_contacted=false`.
- Family detectors share `detector_support.py`; an unrelated detector failure must not block later detectors.

## Full batch order

`Invoke-FamilyBatch.ps1` performs these stages:

1. authenticated generic triage and exact inner SHA-256;
2. family/campaign classification;
3. for scripts: encoded-layer analysis, logic extraction, and Base64 text extraction;
4. for VBS: sink-oriented variable tracing;
5. for Unicode/image-stage campaigns: marker removal and concatenated-string reconstruction;
6. for ISO/IMG: ISO9660 inventory without mounting;
7. `batch-run-summary.json` with completed stages and safety markers.

RAR remains inventory-only in the default Python path. A reviewed external extractor may be used separately, and any inherited result requires an exact inner SHA-256 match.

## Failure checks

- `cannot authenticate/decrypt archive`: confirm the archive, password, and `pyzipper`; do not bypass authentication.
- `expected one file member`: use generic triage or add a reviewed multi-member handler.
- `member exceeds ...`: inspect declared size and raise the limit only for a reviewed case.
- `unsafe archive member path`: quarantine the archive; do not normalize and extract it.
- `campaign unknown`: stop after generic triage and add a reviewed structural handler.
- missing stage in `validate_batch_outputs.py`: inspect `batch-run-summary.json` and the stage-specific JSON before publishing.
