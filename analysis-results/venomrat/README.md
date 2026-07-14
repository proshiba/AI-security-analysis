# VenomRAT analysis results

This dataset separates four user-provided Japan-observed Triage submissions from three independently selected MalwareBazaar samples. A shared family label does not establish a shared campaign.

## Japan-observed cluster

| SHA-256 | Delivery pattern | Final C2 evidence |
|---|---|---|
| `f6ff5df0da5c7fb540390937fa063e709e0e6a42792fbf5123234e85863dd14d` | Tax_Notice executable, VBS/BITSAdmin staging | `192.252.180.45:4449` (Triage config/network) |
| `54b18666cff2721220a2aab4aaaef419b3fc22aa263edbbc43d7b3164f562f7d` | Tax_Notice executable, RuntimeBroker persistence | `192.252.180.45:4449` (Triage config/network) |
| `01d63fac83c1e47461c08f5abfe29db0ddfe6b448b1abd7c21cfb8b06c4ad386` | Tax_Notice executable, RuntimeBroker persistence | `192.252.180.45:4449` (Triage config/network) |
| `5cdb8b20bab0ef77f5889729c7c8664326607ecf19ae48d2e1b1398df6b40083` | IMG container and DLL hijacking | `192.252.180.45:4449` (Triage extracted config) |

The first three reports used Japanese Windows sandbox resources. The fourth is called Japan-observed only because that provenance was supplied by the requester; the sandbox locale is not used as geolocation proof.

## MalwareBazaar static set

| SHA-256 | Static pattern | Configuration status |
|---|---|---|
| `6bd804b150495e241f5791e889b8eaa1c2f16564cca78da4caec91a2d37f2955` | .NET x64 Quasar/xClient-derived module | Three literal port-1002 endpoints recovered; role is static-config candidate |
| `3187d3e3b16a56070801701cb040843b67ee52f3a601be142267fd0ea0d91e3b` | Obfuscated .NET x86 resource loader | Final payload/C2 not recovered; 332,036-byte entropy-7.999 resource inventoried |
| `6d25076b0cf8d493bd252bcfdee87c9ec9e23ddb814cfc671e3e80d31e2bf6f8` | Native x64 resource loader | Final payload/C2 not recovered; 956,928-byte `EXPAND/2499` resource prioritized |

No sample was executed and no extracted infrastructure was contacted.
