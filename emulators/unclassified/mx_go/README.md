# MX-Go local protocol lab

This lab reproduces the statically recovered MX-Go HTTP control and content paths without contacting real infrastructure. Both programs enforce loopback-only operation.

## Safety boundaries

- `server.py` refuses non-loopback bind addresses.
- `client.py` refuses non-loopback target URLs.
- `c2_detector.py --protocol mxgo` defaults to an offline request preview.
- Active detector modes require both a loopback host and `--mxgo-allow-loopback-network`.
- Heartbeats use synthetic IDs and `LAB_ONLY`; hostnames, MAC addresses and real machine identifiers are not collected.
- Recipient fixtures use the reserved `.invalid` TLD. Output contains only count/hash, not addresses.
- The lab returns empty, non-operative command flags. It cannot send email or execute commands.

## Start the local C2/content emulator

```powershell
python .\emulators\unclassified\mx_go\server.py --host 127.0.0.1 --port 5000
```

Emulated paths:

- `POST /api/v1/heartbeat_direct`
- `POST /api/v1/activate`
- `POST /api/v1/shutdown`
- `POST /api/v1/selftest_result`
- `GET /api/client_command/<synthetic-client-id>`
- `GET /jp01.txt`, `/html-a.txt`, `/fscs-a.txt`, `/yuming.txt`, `/dimk.txt`

## Standalone client emulator

```powershell
python .\emulators\unclassified\mx_go\client.py `
  --base-url http://127.0.0.1:5000 `
  --mode both `
  --output C:\malware-lab\mx-go-lab-client.json
```

## c2_detector integration

Generate a heartbeat description without network contact. The host may be the reviewed IOC because preview mode never resolves or connects to it:

```powershell
python .\analysis-framework\common\c2_detector.py 43.165.179.173 5000 `
  --protocol mxgo `
  --mxgo-mode preview
```

Validate a synthetic check-in against the local emulator:

```powershell
python .\analysis-framework\common\c2_detector.py 127.0.0.1 5000 `
  --protocol mxgo `
  --mxgo-mode checkin `
  --mxgo-allow-loopback-network
```

Fetch and summarize the synthetic recipient fixture:

```powershell
python .\analysis-framework\common\c2_detector.py 127.0.0.1 5000 `
  --protocol mxgo `
  --mxgo-mode recipients `
  --mxgo-recipient-path /jp01.txt `
  --mxgo-allow-loopback-network
```

A non-loopback active target fails argument validation before DNS or TCP activity.

## Tests

```powershell
python -m pytest .\analysis-framework\tests\test_c2_detector.py .\emulators\unclassified\mx_go\tests
```