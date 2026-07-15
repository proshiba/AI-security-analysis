# Remus Stealer behavior and C2 assessment

## Reviewed set

- 10 submissions: 7 PE files and 3 encrypted 7z archives.
- Five PE files contained Go runtime evidence; two met the packing heuristic.
- One PE resource was recovered as a script-like layer. The three 7z samples rejected empty/infected passwords and were not brute-forced.

## Behavior model

The reviewed set contains distinct encrypted-archive, Go-loader, and native-PE delivery shapes. This separation is retained because they may represent different campaigns or builders. Browser/wallet behavior was not sufficiently exposed in the submitted layer to claim recovered final configuration.

## Infrastructure

No C2 was confirmed. Three bare `host:port` strings occurred among a larger synthetic/random domain corpus and were suppressed as high-false-positive data rather than published as C2.

## Detection

- High FP: archive extraction, Go runtime markers, or random domain test data.
- Medium FP: archive-launched unsigned executable followed by browser database access.
- Lower FP: Remus-specific payload strings plus browser/wallet collection and process-attributed exfiltration.
