# DonutLoader analysis results

Cases in this directory are organized by the requested primary analysis label,
while reports retain separate delivery and terminal-family fields.

| Primary artifact | Static delivery profile | Donut status | Terminal result |
|---|---|---|---|
| `e8a4f202...ad17ea37` | first-byte/index-XOR multi-PE | not confirmed | native `10FX` RAT, `154.82.93.206:8080` |

The `e8a4?` submission was reassigned here after the original two Triage inputs
were reported as reversed. Independent reanalysis recovered four PE artifacts
but no supported Donut call-over-instance layout. It is retained as a disputed
label, not as a positive Donut signature fixture.

All recovery is offline. Samples and recovered bytes are never loaded, and
configured infrastructure is not contacted.

## VX-Underground batch, 2026-07-16

[Two reviewed submissions](vx-underground-20260716/README.md) exercised both a
direct current-layout Donut shellcode and a 32-byte XOR PE wrapper. Both terminal
PE payloads were recovered statically; recovered bytes are not committed.
