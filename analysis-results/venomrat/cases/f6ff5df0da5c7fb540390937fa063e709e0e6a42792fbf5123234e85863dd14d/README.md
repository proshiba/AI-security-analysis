# VenomRAT case f6ff5df0da5c7fb540390937fa063e709e0e6a42792fbf5123234e85863dd14d

- Source: [Triage 260714-mbx4ysds5s](https://tria.ge/260714-mbx4ysds5s/behavioral1)
- Submitted artifact: `Tax_Notice_72642.exe`
- Campaign type: `japan_tax_notice_runtimebroker`
- Provenance: user-provided Japan-observed submission
- Family evidence: public report labels AsyncRAT/Venom RAT + HVNC + Stealer + Grabber v6.0.3

## Behavior

ZIP/EXE to VBS, PING delay, BITSAdmin download, UAC-policy modification, and additional staged tools. Delivery URLs: https://haowelwa.pro/66/56565/kwkw.xlxs and https://baofacai.xyz/spx/sp.zip. A separate 38.207.189.45:443 endpoint is retained as stage infrastructure, not final C2.

Persistence: Run/RunOnce-style persistence and observed administrative policy modification.

## C2 assessment

`192.252.180.45:4449` is confirmed by the public Triage configuration/network evidence for this case. Sandbox-internal addresses, DNS resolvers, certificate service endpoints, and delivery infrastructure are excluded from final C2.

## Detection material

Correlate the lure name, WScript/BITSAdmin or DLL-hijack execution, RuntimeBroker-profile persistence, process enumeration/token adjustment/hooks, and outbound port 4449. A single filename or Run-key write has high false-positive potential; the correlated chain is high-confidence.

## Constraints

No local execution and no live C2 contact were performed. Findings are bounded to public sandbox evidence and the stated provenance.
