# Atomic macOS Stealer behavior and C2 assessment

## Reviewed set

- 10 submissions: 7 Mach-O files and 3 script stages (VBA, VBS, and AppleScript).
- Three script stages exposed keychain, browser, wallet, user-prompt, and AppleScript collection features.
- The Mach-O files were parsed statically but did not expose equivalent plaintext config in this pass.

## Behavior model

The script cases collect or reference macOS keychain material, browser stores, and cryptocurrency-wallet data, and use user prompts/AppleScript as part of the acquisition flow. Script delivery is kept separate from direct Mach-O delivery.

## Probable exfiltration/C2 configuration

Embedded `/ledger/` and `/ledger/live/` pairs were recovered from three scripts:

- `nvoaagent.com` with campaign ID `93ea36a257de15f2fe3f9d5d32fb19ee6e040fa3cd57131dedc33c740d868a89`
- `flwoagent.com` with campaign ID `484e513fdf967e35d2e21b8b88df0a2867c1abf6045e4ec41974ae927abb2140`
- `northernvirginiapainting.com` with campaign ID `2fc78a36ea00d10a6d4fbba34bd924464f978f9598d97014a4a78a90eb3c6525`

These are `probable` embedded exfil/C2 values. No DNS, HTTP, or check-in was performed, so server liveness and ownership remain unknown.

## Detection

- High FP: `osascript`, `security`, `curl`, or browser database access individually.
- Medium FP: AppleScript credential prompt combined with keychain/browser collection and archive creation.
- Lower FP: the collection chain plus `/ledger/<64-hex>` infrastructure and an unusual parent/child sequence.
