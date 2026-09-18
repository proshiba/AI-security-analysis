# Ghidra MCP Windows UDS relay

Windows版Ghidra MCPがUnix domain socket（UDS）だけで待受け、従来の`127.0.0.1:8089`が応答しない場合に、UDSをnumeric loopback TCPへbyte単位で中継します。relayはPython標準ライブラリだけを使用し、HTTP request／responseを書き換えません。このため、`program` selectorも変更せずGhidra MCPへ渡されます。

## 安全境界

- TCP listenerは`127.0.0.1`固定です。hostname、外部interface、IPv6 wildcardは拒否します。
- 同時接続数、UDS接続timeout、idle timeout、request／responseの方向別byte数を上限付きで検証します。
- relayは検体を実行せず、commandやGhidra scriptも生成・実行しません。`GHIDRA_MCP_ALLOW_SCRIPTS`は有効にしません。
- HTTP payloadは無変更で透過します。認証追加、redirect、selector補完は行いません。
- 日次解析側の`--ghidra-mcp-url`もnumeric loopbackのHTTP URLだけを受理し、資格情報、path、query、fragmentを拒否します。
- 選択URLは日次state、collection binding、implementation migration receiptへSHA-256付きoperator pinとして結合されます。既存checkpointは`migrate-run-implementation`で明示移行するまでresumeできません。

## 起動例

Ghidraが作成したsocket名とPIDを確認してから、別terminalでrelayを起動します。

```powershell
py -3.13 -B .\analysis-framework\common\ghidra_mcp_uds_relay.py `
  --uds-path '\tmp\ghidra-mcp-Administrator\ghidra-9924.sock' `
  --listen-port 18089 `
  --max-connections 4 `
  --idle-timeout 185
```

起動時に`status=listening`と`listen_url=http://127.0.0.1:18089`を含むJSONを1行出力します。終了は`Ctrl+C`です。UDS pathはGhidra再起動後のPIDに合わせて毎回確認してください。

既定のrelay portは`18089`です。日次orchestrator自体の既定値は互換性のため`http://127.0.0.1:8089`のままです。relayを利用するrun／resume／migrationでは次を追加します。

```powershell
--ghidra-mcp-url http://127.0.0.1:18089
```

既存checkpointを新実装へ移行するときも、以後のresumeと同じ`--ghidra-mcp-url`を指定します。別URLを指定したresumeはoperator pin不一致としてfail closedになります。

## 障害時の確認

- `relay_transport_failed`の場合はsocket fileのPID、Ghidra process、socketの更新時刻を確認します。
- `ghidra_mcp_url_not_loopback`または`ghidra_mcp_url_invalid`の場合はnumeric loopback、HTTP scheme、明示port以外が混入していないか確認します。
- timeoutやbyte上限超過時は接続を閉じます。上限変更はCLIの固定範囲内で明示指定し、検体実行や任意scriptで回避しません。
