# Python API documentation

This directory contains standard-library `pydoc` HTML for the declarative engine and root `extractors/` public APIs.

Main entry points:

- `asa.cli.html`: definition validation and plan compilation
- `asa.runtime_cli.html`: offline end-to-end analysis
- `asa.discovery.html`: safe intake and normalized discovery
- `asa.runner.html`: allowlisted offline step execution
- `extractors.config_extractor.html`: unified family extractor API
- family-specific `extractors.*.extractor.html`

Regenerate:

```powershell
$env:PYTHONPATH = '<repo-root>\analysis-framework\src;<repo-root>\analysis-framework\common;<repo-root>'
cd <repo-root>\docs\pydoc
python -m pydoc -w asa asa.models asa.conditions asa.loader asa.catalog asa.compiler asa.cli `
  asa.discovery asa.runner asa.runtime_cli `
  malwarebazaar_batch analyze_stealer_set c2_candidate_detector generate_stealer_reports `
  generate_ioc_lists deep_static_triage `
  unpackers.static_unpacker unpackers.static_control_flow unpackers.managed_il_triage `
  unpackers.javascript_obfuscator unpackers.javascript_dropper_unpacker unpackers.nsis_unpacker `
  emulators.stealers.lab `
  extractors extractors.common extractors.config_extractor extractors.stealer_common `
  extractors.formbook.extractor extractors.vidar.extractor `
  extractors.lummastealer.extractor extractors.remusstealer.extractor `
  extractors.amosstealer.extractor `
  extractors.valleyrat.extractor extractors.agenttesla.extractor `
  extractors.remcosrat.extractor extractors.venomrat.extractor `
  extractors.unclassified.mx_go.extractor
```

Regenerate after implementation changes. Tests verify that public functions retain docstrings and that each documented module has an HTML artifact.

## Deep static analysis modules

- `deep_static_triage.html`: bounded inventory orchestration, in-memory layer recovery, and publish-safe reporting
- `unpackers.static_control_flow.html`: bounded native PE and raw x86 control-flow triage
- `unpackers.managed_il_triage.html`: bounded .NET metadata, IL, and managed-obfuscation triage

Regenerate these pages from `docs/pydoc` with the repository root, framework
source, and common-module directories on `PYTHONPATH`:

```powershell
python -m pydoc -w deep_static_triage unpackers.static_control_flow unpackers.managed_il_triage
```


## ShadowPad modules

- `extractors.shadowpad.extractor.html`: unified ScatterBee and legacy Casper config extraction
- `extractors.shadowpad.legacy.html`: offline stream decoding, QuickLZ decompression, and config parsing

Both pages document static-only APIs; they do not execute samples or contact extracted endpoints.
## PureHVNC and DonutLoader modules

Generated pages also cover `unpackers.donut_unpacker`, `unpackers.purehvnc_unpacker`, `unpackers.chrd_donut_unpacker`, `extractors.purehvnc.extractor`, `extractors.donutloader.extractor`, `emulators.purehvnc.lab`, `c2_detector`, and `chain`.

## APT-C-60 / SpyGlace modules

Generated pages include repository_history_collector.html, unpackers.spyglace_unpacker.html, unpackers.apt_c60_delivery.html, extractors.spyglace.extractor.html, and emulators.spyglace.lab.html.

## 2026-04-01 news modules

- `supply_chain_audit.html`
- `extractors.npm_supply_chain.extractor.html`
- `extractors.atlascross.extractor.html`
- `generate_ioc_lists.html`

## StealC module

- `extractors.stealc.extractor.html`: v1 RC4 skip-key and paired-buffer XOR configuration extraction.

## Current family and recovery modules

- `extractors.amadey.extractor.html`
- `extractors.latrodectus.extractor.html`
- `unpackers.container_recovery.html`
- `unpackers.donut_wrapper_unpacker.html`
- `unpackers.index_xor_pe_unpacker.html`

The generated API also documents the raw-directory batch mode and detailed
publish-safe report renderer in `analyze_stealer_set.html` and
`generate_stealer_reports.html`.

## Unclassified batch and Electron recovery modules

- `malwarebazaar_unknown_batch.html`: newest-first tag collection, exclusion,
  resumption, and publish-safe acquisition metadata.
- `analyze_unknown_set.html`: calibrated static family attribution, IOC
  sanitation, clustering, selective cache refresh, and report rendering.
- `update_unknown_analysis_history.html`: idempotent, conservative history
  entries for batch cases.
- `unpackers.asar_unpacker.html`: bounded ASAR validation and recovery.
- `unpackers.electron_nsis_unpacker.html`: targeted NSIS/Electron ASAR recovery.

## Profile-defined family expansion modules

- `extractors.profiled_family.html`: shared bounded config/IOC extraction and role classification
- `profiled_family_detector.html`: exact-hash and structural family routing
- `scaffold_family_expansion.html`: thin modules and declarative definition generation
- `generate_family_expansion_reports.html`: publish-safe case, IOC, and YARA generation
- `validate_family_expansion.html`: 100-case integrity and safety validation
- `emulators.common.html`: shared literal-loopback enforcement and bounded collector
- `emulators.families.lab.html`: non-wire-compatible synthetic family lab
- `unpackers.path_safety.html`: shared untrusted member-path validation

The generated pages must be refreshed whenever a public function changes. The
pydoc test imports each module, requires public-function docstrings, and verifies
that every public function has a matching HTML anchor.

These modules do not execute samples or contact extracted infrastructure.

## Hash OSINT module

- `osint_hash_enricher.html`: exact-hash collection, provider normalization,
  confidence/conflict handling, curated evidence, and publish-safe reporting.
