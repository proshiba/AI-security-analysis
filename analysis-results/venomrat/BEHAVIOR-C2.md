# VenomRAT behavior and C2 assessment

## Japan-observed delivery chain

The reviewed July 2026 submissions use tax-notice-themed names. Observed stages include `Tax_Notice_*.exe`, a VBS launcher, BITSAdmin retrieval, a disk-image variant, and DLL hijacking. Persistence uses a copied `RuntimeBroker.exe` below `%APPDATA%\Microsoft\Crypto\RuntimeBroker` plus a Run/RunOnce value. The richest chain also changes `ConsentPromptBehaviorAdmin`, which is a high-value detection event when paired with script or download activity.

All four public reports identify Venom RAT + HVNC + Stealer + Grabber v6.0.3/AsyncRAT-derived behavior and converge on `192.252.180.45:4449`. `haowelwa.pro` and `baofacai.xyz` are delivery infrastructure, not promoted to final C2. Public sandbox service endpoints, DNS resolvers, internal `10.127.0.0/16` addresses, certificate endpoints, and unrelated telemetry are excluded.

## Static MalwareBazaar configuration

`6bd804…` contains Quasar/xClient namespaces, reconnect/install/password/mutex setting fields, browser-login SQL, keylogging/UI hooks, process and registry support, and plugin-oriented host handling. The literal endpoints `sznftk1.it.com:1002`, `eeee456.it.com:1002`, and `xelamnces.online:1002` occur in the same managed artifact. They are high-confidence static configuration candidates but were not independently validated with a call-site trace or live traffic.

`3187d3…` contains GZip/AES/CryptoStream/resource-loading primitives and process-memory APIs. Its `Osddmqvmi` resource is 332,036 bytes, SHA-256 `56885090885afb11b855bbdd9cc67eb18fb11dea98559951053d1ce69a1b7dd1`, entropy 7.999. This supports an encrypted payload layer; it does not reveal a final C2 by itself.

`6d2507…` is native x64. The largest resource is type `EXPAND`, ID `2499`, size 956,928, SHA-256 `375a5738ea0b982b542ca17d129e0c936cc55203cac206fea28f17b8757b804b`, entropy 6.541. A second resource (type 3, ID 16) is 61,849 bytes at entropy 7.945. Both require format-specific recovery before final-family configuration claims.

## Detection confidence and false positives

- High: `Tax_Notice_*.exe` followed by WScript/BITSAdmin, RuntimeBroker-path persistence, and connection to port 4449. False positives are unlikely when three signals correlate; single filenames alone are weak.
- Medium: Quasar/xClient namespace plus multiple Venom-like settings fields and port-1002 host literals. Legitimate Quasar forks and research builds can match.
- Medium: high-entropy managed resource plus AES/GZip and process-memory APIs. Commercial protectors and installers can produce the same combination.
- Low: a single Run/RunOnce write, BITSAdmin use, process enumeration, or code-signing/certificate URL. These are common administrative or software behaviors.

## Bounded recovery result

Common non-executing transforms (Base64, byte reversal, gzip/zlib, AES with explicit literal keys/IVs, and PE carving) did not recover a new final payload from either unresolved loader. This narrows the next step to loader-specific key/algorithm reconstruction, not blind execution.
