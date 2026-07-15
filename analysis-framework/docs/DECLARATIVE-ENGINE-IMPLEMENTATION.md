# Declarative engine implementation

The `asa/v1alpha1` implementation now includes strict definition validation, deterministic DAG compilation, and an offline static-analysis runner.

## Implemented

- strict Pydantic models and YAML loading
- non-executable condition DSL
- weighted family/campaign scoring with tie-to-unknown behavior
- allowlisted, major-versioned step catalog
- dependency validation and deterministic DAG ordering
- offline capability-policy enforcement
- raw-file and single-member encrypted-ZIP intake
- normalized discovery facts and reviewed family/campaign inference
- offline implementations for intake, inventory, strings, IOCs, PE, .NET, Go, scripts, ISO, family config, and reporting
- FLOSS and Ghidra MCP availability checks without automatic invocation
- `validate`, `plan`, and `asa-analyze` CLIs
- ten malware definitions and twelve pipelines

## Run an offline analysis

```powershell
$env:PYTHONPATH = '<repo-root>\analysis-framework\src;<repo-root>'
python -m asa.runtime_cli `
  --sample C:\samples\submission.zip `
  --definitions .\analysis-framework\definitions `
  --output C:\analysis-output\case
```

Optional reviewed analyst hints are accepted through `--family-hint` and `--campaign-hint`. Unknown or tied classification remains `needs_review`; a hint never bypasses policy or step validation.

Outputs:

- `facts.json`: normalized discovery evidence
- `plan.json`: compiled family/campaign DAG
- `steps/<step-id>/result.json`: per-step static result
- `run.json`: terminal step states and safety flags

## Validate definitions

```powershell
python -m asa.cli validate --definitions .\analysis-framework\definitions
```

## Compile only

```powershell
python -m asa.cli plan `
  --definitions .\analysis-framework\definitions `
  --facts C:\analysis-output\discovery-facts.json `
  --policy offline-default `
  --output C:\analysis-output\plan.json
```

## Safety boundary

- YAML cannot specify Python paths, PowerShell, or shell commands.
- Every step must match the catalog allowlist and declared major version.
- Policy-denied capabilities cannot be restored by a pipeline or malware definition.
- Unknown/tied classification is not forced into a known handler.
- Sample bytes are parsed, never launched or loaded as executable code.
- No runtime step contacts external infrastructure.
- FLOSS and Ghidra MCP steps are preflight-only in this release.
- ZIP contents are retained in memory and archive traversal is rejected.
