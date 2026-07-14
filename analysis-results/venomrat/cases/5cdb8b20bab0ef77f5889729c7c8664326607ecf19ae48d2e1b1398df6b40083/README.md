# VenomRAT case 5cdb8b20bab0ef77f5889729c7c8664326607ecf19ae48d2e1b1398df6b40083

- Source: [Triage 260709-sasqqsdt2x](https://tria.ge/260709-sasqqsdt2x/behavioral1)
- Submitted artifact: `Tax_Notice_36758.img`
- Campaign type: `japan_tax_notice_disk_image`
- Provenance: user-provided Japan-observed submission
- Family evidence: public report labels AsyncRAT/Venom RAT + HVNC + Stealer + Grabber v6.0.3

## Behavior

IMG container exposes Tax_Notice_36758.exe and nvml.dll; sandbox behavior reports DLL hijacking, process enumeration, token activity, hooks, and task-scheduler COM use.

Persistence: Run-key behavior reported. Japan observation is requester-supplied provenance, not inferred from sandbox locale.

## C2 assessment

`192.252.180.45:4449` is confirmed by the public Triage configuration/network evidence for this case. Sandbox-internal addresses, DNS resolvers, certificate service endpoints, and delivery infrastructure are excluded from final C2.

## Detection material

Correlate the lure name, WScript/BITSAdmin or DLL-hijack execution, RuntimeBroker-profile persistence, process enumeration/token adjustment/hooks, and outbound port 4449. A single filename or Run-key write has high false-positive potential; the correlated chain is high-confidence.

## Constraints

No local execution and no live C2 contact were performed. Findings are bounded to public sandbox evidence and the stated provenance.
