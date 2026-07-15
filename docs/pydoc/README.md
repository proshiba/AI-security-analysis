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
$env:PYTHONPATH = '<repo-root>\analysis-framework\src;<repo-root>'
cd <repo-root>\docs\pydoc
python -m pydoc -w asa asa.models asa.conditions asa.loader asa.catalog asa.compiler asa.cli `
  asa.discovery asa.runner asa.runtime_cli `
  malwarebazaar_batch analyze_stealer_set c2_candidate_detector generate_stealer_reports `
  unpackers.static_unpacker unpackers.javascript_obfuscator unpackers.javascript_dropper_unpacker unpackers.nsis_unpacker `
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

## PureHVNC and DonutLoader modules

Generated pages also cover `unpackers.donut_unpacker`, `unpackers.purehvnc_unpacker`, `unpackers.chrd_donut_unpacker`, `extractors.purehvnc.extractor`, `extractors.donutloader.extractor`, `emulators.purehvnc.lab`, `c2_detector`, and `chain`.

## APT-C-60 / SpyGlace modules

Generated pages include repository_history_collector.html, unpackers.spyglace_unpacker.html, unpackers.apt_c60_delivery.html, extractors.spyglace.extractor.html, and emulators.spyglace.lab.html.
