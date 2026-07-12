# b433ecdf... case

- Malware type: ValleyRAT
- Campaign type: `msi_embedded_cab_custom_actions`
- Chain: `KL-X86Gicasc.msi → CAB → mesedge.exe → cef_frame.dll!TbsAppInstance`
- Confirmed C2: `www.tq8j.com:443`
- Observed resolution: `103.45.64.246`
- Evidence: static DLL sideload edge correlated with process-attributed Triage DNS/TCP observations
- Sample executed locally: no
- Live C2 contact: no

Traffic attributed to the legitimate LetsVPN process is excluded from the C2 conclusion.
