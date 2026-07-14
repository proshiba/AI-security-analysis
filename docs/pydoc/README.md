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
  extractors extractors.common extractors.config_extractor `
  extractors.valleyrat.extractor extractors.agenttesla.extractor `
  extractors.remcosrat.extractor extractors.venomrat.extractor `
  extractors.unclassified.mx_go.extractor
```

Regenerate after implementation changes. Tests verify that public functions retain docstrings and that each documented module has an HTML artifact.
