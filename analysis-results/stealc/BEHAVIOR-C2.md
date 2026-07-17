# StealC behavior and C2 model

## v1 reviewed model

1. Decrypt API names, target paths, C2 base URL, PHP gate, dependency directory, and build identifier.
2. Collect host metadata and application data from browsers, messaging clients, email clients, gaming clients, wallets, and configured file paths.
3. Download required native dependencies from the configured directory where needed.
4. Submit multipart HTTP POST requests through WinINet. Reviewed strings expose `hwid`, `build`, `token`, `file_name`, `file`, and `message` fields.
5. Optionally receive a loader task and remove the executable with a delayed `cmd.exe` command.

The complete gate is `base_url + gate_path`; the dependency directory is a separate role and must not be normalized into the gate. Build IDs (`default`, `ZOV`, and `GoogleMaps` in this corpus) are grouping pivots but do not prove common operator ownership.

## v2 family model

Public research describes a version split introduced in March 2025. v2 removes the v1 dependency-DLL request model, uses WinHTTP and JSON, and supports `create`, `upload_file`, `loader`, and `done` operations. Recent variants RC4-encrypt communication. A typical configuration contains a C2 URL, build ID, configuration RC4 key, and communication RC4 key.

The current extractor does not infer a v2 configuration from packer metadata. A complete decoded structure is required before producing a v2 C2 IOC.

## Safe validation boundary

The analysis pipeline is offline by default. Extracted URLs are passed to reporting and detection logic but not fetched. Reachability, banner collection, TLS/JARM, or protocol check-in would be a separate explicitly authorized task; none was performed here.
