# SpyGlace analysis results

This directory separates publish-safe SpyGlace results from reusable analysis code. No raw or decoded malware is stored here.

## Coverage

| Version | JPCERT hashes | Recovered and config-extracted |
|---|---:|---:|
| 3.1.15 | 4 | 4 |
| 3.1.17 | 1 | 0 |
| 3.1.18 | 5 | 0 |

All four v3.1.15 repository artifacts were decoded with the repeating repository key and parsed without execution. Three share the EVE campaign configuration at 31.58.136.207; one uses SAPPHIRE at 185.18.222.241. The six later-version hashes were unavailable in surviving public history and MalwareBazaar at the observation date.

## Results and code

- campaigns/apt-c60-2026/README.md - infection chain, repository survey, protocol notes, IOC coverage and detection assessment.
- campaigns/apt-c60-2026/jpcert-ioc-files.csv - complete JPCERT/CC file-IoC table.
- campaigns/apt-c60-2026/network-and-account-iocs.csv - network and account pivots.
- campaigns/apt-c60-2026/repository-liveness.json - all 29 repository observations.
- cases/ - one config JSON and a detailed README for each recovered SpyGlace sample.
- ../../extractors/spyglace/ - offline config extractor.
- ../../unpackers/spyglace_unpacker.py - repository-envelope recovery.
- ../../unpackers/apt_c60_delivery.py - Base64/TAR, LNK and fragmented-downloader inspection.
- ../../emulators/spyglace/ - loopback-only protocol laboratory.
- ../../analysis-framework/malware/spyglace/ - family detector, passive C2 plan and rules.

C2 availability was not tested. ASP URLs in case files are inferred combinations of static IPs and paths, not proof that an endpoint answered.
