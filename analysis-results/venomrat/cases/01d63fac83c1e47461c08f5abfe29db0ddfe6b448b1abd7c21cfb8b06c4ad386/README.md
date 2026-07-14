# VenomRAT case 01d63fac83c1e47461c08f5abfe29db0ddfe6b448b1abd7c21cfb8b06c4ad386

- Source: [Triage 260708-ll6neady6z](https://tria.ge/260708-ll6neady6z/behavioral1)
- Submitted artifact: `Tax_Notice_62850.exe`
- Campaign type: `japan_tax_notice_runtimebroker`
- Provenance: user-provided Japan-observed submission
- Family evidence: public report labels AsyncRAT/Venom RAT + HVNC + Stealer + Grabber v6.0.3

## Behavior

ZIP-delivered tax-notice executable copies RuntimeBroker.exe below the user roaming profile and exhibits token, hook, and process-enumeration behavior.

Persistence: Run value referencing %APPDATA%\Microsoft\Crypto\RuntimeBroker\RuntimeBroker.exe.

## C2 assessment

`192.252.180.45:4449` is confirmed by the public Triage configuration/network evidence for this case. Sandbox-internal addresses, DNS resolvers, certificate service endpoints, and delivery infrastructure are excluded from final C2.

## Detection material

Correlate the lure name, WScript/BITSAdmin or DLL-hijack execution, RuntimeBroker-profile persistence, process enumeration/token adjustment/hooks, and outbound port 4449. A single filename or Run-key write has high false-positive potential; the correlated chain is high-confidence.

## Constraints

No local execution and no live C2 contact were performed. Findings are bounded to public sandbox evidence and the stated provenance.
