# 情報窃取型マルウェアのループバック検証環境

この検証環境はFormbook、Vidar、LummaStealer、RemusStealer、AMOS向けに、合成した要求／応答の形式を提供します。稼働中C2へ接続するクライアントではありません。

- サーバーのバインド先はループバックに限定します。
- クライアントの接続先はループバックに限定します。
- 要求に含めるのは `LAB-FIXTURE` だけで、端末／被害者識別情報や収集データは含めません。
- 応答のコマンド一覧は常に空です。
- ファミリー別ルートは解析用の合成データです。最終プロトコルを復元できていないパック済み検体について、バイト単位で正確とは主張しません。

```powershell
python .\emulators\stealers\lab.py server --host 127.0.0.1 --port 18080
python .\emulators\stealers\lab.py client --family amosstealer --base-url http://127.0.0.1:18080
```
