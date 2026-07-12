# 8bf54a76... case

- Malware type: ValleyRAT
- Campaign type: `dll_sideload_vvas_bundle`
- Chain: `chgport.exe → LoggerCollector.dll → XOR vvaS.bin → rundll32.exe injection`
- Confirmed configuration: `202.95.8.27:6666`, secondary port `8888`
- Evidence: decoded configuration marker `odaktomk` and validated vvaS plaintext hash
- Sample executed during repository workflow: no
- Live network contact represented in committed results: no

The endpoint was historically checked in a separate, explicitly authorized task. This repository's automatic workflow does not perform C2 contact.
