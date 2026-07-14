# AgentTesla analysis results

Ten MalwareBazaar submissions were triaged without local sample execution. Delivery patterns are kept separate from payload/config clusters because builders and infrastructure may be reused by different operators.

## Evidence provenance

The FTP/SMTP endpoints in the current ten-case table came from external sandbox configuration output or, for the RAR wrapper, inheritance from its byte-identical inner sample. They were not recovered from the submitted scripts alone. Offline analysis recovered stage URLs in four cases, but no final .NET payload in the ten original containers because those stages must be separately acquired.

`agenttesla_recover.py` records loader-derived stage URLs, recovers bounded encoded .NET candidates, and extracts redacted CLR configuration. `agenttesla_payload_fetch.py` provides explicit, bounded stage retrieval. New results must label endpoint provenance as `static_recovered_dotnet_payload`, `external_sandbox`, or `inherited_external_sandbox`.

## Family behavior and C2 model

AgentTesla is primarily an information stealer. In these cases the submitted scripts/HTA/RAR files are delivery layers; after the .NET payload is loaded, recovered FTP or SMTP settings are best understood as stolen-data exfiltration channels rather than interactive operator consoles.

Case reports separate observed delivery behavior, inferred family capability, endpoint provenance, and current liveness. No current case was executed locally or live-probed.

| SHA-256 | Artifact | Pattern | Confirmed C2/config endpoint |
|---|---|---|---|
| [`1fe1d42d2936…`](cases/1fe1d42d293627441517749d73857f49a27224933844bd9cf512de12045e75ed/README.md) | JavaScript | `unicode_marker_powershell_png_stage` | `ftp.ltcresource.com.my:21` |
| [`5a43e67720eb…`](cases/5a43e67720eb299fccc8a096a20ab298009e37fc6febe048b617c5017347da86/README.md) | HTA | `unicode_marker_powershell_png_stage` | `ftp.dankely.org:21` |
| [`7f31b2c417af…`](cases/7f31b2c417af903470a865c011854acb2d0ce9ef3e497973d54e97fb68db74d8/README.md) | JavaScript | `javascript_aes_inmemory_dotnet` | `ftp.4bagh.net:21` |
| [`856e540dd376…`](cases/856e540dd3765d8e1129070615d6104388a4f8c34179b520acfd87d9efa56643/README.md) | JavaScript | `unicode_marker_powershell_png_stage` | `ftp.orangesac.com:21` |
| [`98287949544f…`](cases/98287949544f5d5e814f0febc7e87f3085a24405c3f193f60514d7231ea19bce/README.md) | JavaScript | `fromcharcode_eval_loader` | `smtp.hostinger.com:587` |
| [`a01716c2c7ea…`](cases/a01716c2c7ea5cb234ee8b5b3b831b63274fbee0b76d8ee5d86a788c6caa26e7/README.md) | JavaScript | `javascript_aes_inmemory_dotnet` | `server275.web-hosting.com:587` |
| [`a74a948afc69…`](cases/a74a948afc694949bf99f9bee9215cc759c082cded0ab1b8f6be345630bfd81e/README.md) | JavaScript | `javascript_aes_inmemory_dotnet` | `server275.web-hosting.com:587` |
| [`d5a5eb1de67b…`](cases/d5a5eb1de67b57a59ac715ee92541ac6570191844b315d0b408f86d3e56ea2c5/README.md) | JavaScript | `javascript_aes_inmemory_dotnet` | `server275.web-hosting.com:587` |
| [`e059c100a917…`](cases/e059c100a917af58168b1e63ebe75cb4558ec144efd91f1ecb145bd9ad79529e/README.md) | RAR | `rar_wrapped_javascript` | `ftp.4bagh.net:21` |
| [`efc1cb535085…`](cases/efc1cb535085a1c44e423c0fd3fbd736d5b55514013093ad25313b42f0b3d296/README.md) | JavaScript | `unicode_marker_powershell_png_stage` | `ftp.cyberflor.co:21` |

See `rules/` for family-oriented YARA and Sigma starting points. Rules are hypotheses that require validation against local benign software and telemetry.
