# VenomRAT case 6bd804b150495e241f5791e889b8eaa1c2f16564cca78da4caec91a2d37f2955

- Source: [MalwareBazaar](https://bazaar.abuse.ch/sample/6bd804b150495e241f5791e889b8eaa1c2f16564cca78da4caec91a2d37f2955/)
- Original name: `libfilezilla-43.dll`
- Artifact: 12,989,312-byte .NET x64 DLL
- Campaign type: `direct_dotnet_quasar_module`

## Static behavior and configuration

The module contains `Quasar.Client` and `xClient.Core` namespaces, Quasar-style `RECONNECTDELAY`, `PASSWORD`, `INSTALLNAME`, `INSTALL`, and `MUTEX` fields, plugin and socket support, browser-login SQL, registry/process support, and keyboard/UI hook functionality. These are consistent with a feature-rich VenomRAT/Quasar-derived client or plugin.

Static endpoint candidates:

- `sznftk1.it.com:1002`
- `eeee456.it.com:1002`
- `xelamnces.online:1002`

All three are direct literals in the managed artifact. They are classified as high-confidence static configuration candidates, not live-confirmed C2, because this analysis did not execute the sample, trace the final socket call, or contact the hosts.

## Detection material

Use namespace + settings-field combinations for YARA. Do not detect only `Quasar.Client`; legitimate Quasar forks and research samples are plausible false positives. Network analytics can hunt for rare domains on port 1002, but domain-only rules are time-sensitive and may be repurposed.
