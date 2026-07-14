# VenomRAT case 54b18666cff2721220a2aab4aaaef419b3fc22aa263edbbc43d7b3164f562f7d

- Source: [Triage 260713-e6t2sady9y](https://tria.ge/260713-e6t2sady9y/behavioral1)
- Submitted artifact: `Tax_Notice_73774.exe`
- Campaign type: `japan_tax_notice_runtimebroker`
- Provenance: user-provided Japan-observed submission
- Family evidence: public report labels AsyncRAT/Venom RAT + HVNC + Stealer + Grabber v6.0.3

## Behavior

7z-delivered tax-notice executable copies RuntimeBroker.exe below the user roaming profile.

Persistence: RunOnce value RuntimeBroker -> %APPDATA%\Microsoft\Crypto\RuntimeBroker\RuntimeBroker.exe.

## C2 assessment

`192.252.180.45:4449` is confirmed by the public Triage configuration/network evidence for this case. Sandbox-internal addresses, DNS resolvers, certificate service endpoints, and delivery infrastructure are excluded from final C2.

## Detection material

Correlate the lure name, WScript/BITSAdmin or DLL-hijack execution, RuntimeBroker-profile persistence, process enumeration/token adjustment/hooks, and outbound port 4449. A single filename or Run-key write has high false-positive potential; the correlated chain is high-confidence.

## Constraints

No local execution and no live C2 contact were performed. Findings are bounded to public sandbox evidence and the stated provenance.
