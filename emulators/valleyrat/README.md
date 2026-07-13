# ValleyRAT emulators

Defensive protocol emulators for ValleyRAT analysis live here. The first tool,
`vvas_client.py`, emulates the observed vvaS check-in without executing malware
code or downloading payload stages by default.

## Safety model

- The emulator sends only the observed vvaS check-in bytes, `33 32 00`, unless
  overridden for a reviewed profile.
- The default read limit is 64 bytes, enough to validate the response header and
  capture a small banner prefix.
- The declared stage body is not downloaded unless `--allow-stage-download` and
  `--i-understand-stage-download-risk` are both supplied.
- Any downloaded stage bytes are potential malware material and must not be
  committed to this repository.
- Live C2 interaction must follow the current case profile, reviewed scope, and
  containment requirements.

## vvaS client usage

Run a direct bounded check-in:

```bash
python emulators/valleyrat/vvas_client.py \
  --host 202.95.8.27 \
  --port 6666 \
  --output out/valleyrat-vvas-6666.json
```

Render reviewed ValleyRAT profile targets without network contact:

```bash
python emulators/valleyrat/vvas_client.py \
  --profile analysis-framework/malware/valleyrat/config/profiles/8bf54a76924ad62e3b5562826f0e491c4c498f166276b071c177b694762199f6.json \
  --dry-run
```

Run from a reviewed ValleyRAT profile when live interaction is authorized:

```bash
python emulators/valleyrat/vvas_client.py \
  --profile analysis-framework/malware/valleyrat/config/profiles/8bf54a76924ad62e3b5562826f0e491c4c498f166276b071c177b694762199f6.json \
  --output out/valleyrat-vvas-profile.json
```

The JSON output records the target, sent bytes, declared stage size, header
match status, response hash, base64 prefix, and whether any stage download was
requested.

## Comparing results

Compare newly collected emulator output with existing `c2-live` evidence:

```bash
python emulators/valleyrat/compare_results.py \
  analysis-results/valleyrat/cases/8bf54a76924ad62e3b5562826f0e491c4c498f166276b071c177b694762199f6/c2-live/2026-07-13_202.95.8.27_6666.json \
  out/valleyrat-vvas-6666.json
```

Use `--json` to emit a machine-readable comparison summary.

## Relationship to `analysis-framework/common/c2_detector.py`

`analysis-framework/common/c2_detector.py` remains the workflow-integrated,
bounded C2 liveness checker. The standalone emulator in this directory is for
profile-driven vvaS protocol emulation, repeatable evidence capture, and
comparison of observations across time or ports.

## Offline tests

The unit tests do not contact any external host:

```bash
python -m pytest emulators/valleyrat/tests
```
