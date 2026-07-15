# Lumma Stealer behavior and C2 assessment

## Reviewed set

- 10 PE submissions.
- All ten contained Go loader/runtime evidence; nine met the packing heuristic.
- UPX did not successfully recover any case, so none is labeled UPX-unpacked.

## Behavior model

The reviewed bytes are consistent with protected or Go-based loader stages rather than plaintext Lumma configuration. Expected browser, wallet, build-ID, HWID, and API fields were not sufficiently correlated in the submitted layer to promote a config.

## Infrastructure

No C2 literal survived known-benign filtering and family-context validation. The result is `unresolved`, not “no C2.” A final payload or process-attributed sandbox trace is needed for a stronger conclusion.

## Detection

- High FP: Go runtime strings, large symbol tables, or high-entropy PE sections.
- Medium FP: unsigned Go executable followed by browser/wallet access or staged payload execution.
- Lower FP: recovered Lumma family/config strings plus credential collection and matching network activity.
