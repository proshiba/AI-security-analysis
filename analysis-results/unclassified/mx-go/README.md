# MX-Go provisional cluster

`MX-Go` is an unclassified, Japan-targeted, remotely controlled bulk-email spam bot cluster. It is not registered as a confirmed malware family because only one payload is currently available.

- [Case 462ae2…](cases/462ae2f56a5f3a961be8bdee03497c65cad61ab04c2482ddcb14e6bf6cdd70fb/README.md)
- Payload SHA-256: `e25053585ac5e4f411f954fe7bedc8cb62672a3f9ae96b6022a7b7116700228e`
- Embedded control server: `43.165.179.173:5000` (TCP open and four matching API routes live-confirmed 2026-07-15; no check-in)
- Observed content/config host: `www.iainglespa.com` (TLS alive; known paths currently appear gated/disabled)
- Rules: [YARA](rules/yara/mx_go_bulk_mailer_2026.yar), [Sigma](rules/sigma/)
- Local protocol lab: `emulators/unclassified/mx_go/`

The sample, Triage JSONL, and FLOSS raw output are intentionally excluded. Only normalized evidence and detection material are stored.