# Information-stealer loopback lab

This lab provides synthetic request/response shapes for Formbook, Vidar,
LummaStealer, RemusStealer, and AMOS. It is not a live-C2 client:

- server binds are restricted to loopback;
- client targets are restricted to loopback;
- requests contain only `LAB-FIXTURE`, no machine/victim identity or collected data;
- responses always contain an empty command list;
- family routes are analysis fixtures and are not claimed to be byte-exact for
  packed samples whose final protocol was not recovered.

```powershell
python .\emulators\stealers\lab.py server --host 127.0.0.1 --port 18080
python .\emulators\stealers\lab.py client --family amosstealer --base-url http://127.0.0.1:18080
```
