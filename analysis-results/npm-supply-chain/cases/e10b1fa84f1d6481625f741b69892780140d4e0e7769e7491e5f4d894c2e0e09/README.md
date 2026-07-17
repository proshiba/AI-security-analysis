# axios / plain-crypto-js supply-chain compromise

## Judgment

The recovered `setup.js` (SHA-256 `e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09`) is a confirmed cross-platform downloader installed through `plain-crypto-js@4.2.1`, which was injected into malicious `axios@1.14.1` and `axios@0.30.4` releases. The terminal downloaded payload is described publicly as a RAT, but its family is not assigned here because no platform payload was recovered.

## Static deobfuscation

`stq[]` values are reversed, `_` is restored to Base64 padding, UTF-8 is decoded, then character codes are XORed with `Number()`-normalized `OrDeR_7077` and decimal 333. The extractor models JavaScript `NaN -> 0` bitwise coercion and never invokes Node.js.

Confirmed output:

- C2/payload endpoint: `http://sfrclak.com:8000/6202033`
- Base endpoint: `http://sfrclak.com:8000/`
- Reported A record: `142.11.206.73`
- campaign/path identifier: `6202033`
- macOS POST marker: `packages.npm.org/product0`
- Windows POST marker: `packages.npm.org/product1`
- Linux POST marker: `packages.npm.org/product2`

## Platform behavior

| Platform | Behavior |
|---|---|
| macOS | writes AppleScript under the temp directory, POSTs the product0 marker, saves `/Library/Caches/com.apple.act.mond`, chmods and launches it with zsh |
| Windows | copies PowerShell to `%PROGRAMDATA%\wt.exe`, writes `%TEMP%\6202033.vbs` and `.ps1`, launches hidden with execution-policy bypass, then deletes temporary scripts |
| Linux/other | POSTs product2, saves `/tmp/ld.py`, and launches it with `python3` under `nohup` |

After dispatch, `setup.js` and `package.json` are removed and `package.md` is renamed to `package.json`, impersonating clean version 4.2.0. Therefore checking only the installed version after execution is insufficient; lockfiles, npm cache, CI logs and the presence/history of `plain-crypto-js` are stronger evidence.

## Supply-chain IOCs

| Artifact | Value |
|---|---|
| axios 1.14.1 npm shasum | `2553649f2322049666871cea80a5d0d6adc700ca` |
| axios 0.30.4 npm shasum | `d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71` |
| plain-crypto-js 4.2.1 npm shasum | `07d889e2dadce6f3910dcbc253317d28ca61c766` |
| setup.js SHA-256 | `e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09` |

## Detection assessment

- **Low false-positive risk**: exact setup.js hash, `plain-crypto-js` dependency under axios, or outbound POST to the full path with a product0/1/2 body.
- **Medium**: `%PROGRAMDATA%\wt.exe` created from PowerShell plus cscript/curl activity. Administrators may legitimately copy or rename interpreters, but the full chain is rare.
- **High**: generic `postinstall`, curl, PowerShell, osascript, or Python execution individually.

Artifacts: [decoded config](config.json), [IOCs](iocs.json), [YARA](rules/npm_axios_supply_chain.yar), [Sigma](rules/npm_axios_windows.yml).

## Limitations

Only `setup.js` was obtained from MalwareBazaar and statically decoded. The removed npm tarballs and second-stage payloads were unavailable. The C2 was not contacted, so current availability and response contents are unverified.
