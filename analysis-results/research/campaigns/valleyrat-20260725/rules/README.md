# ValleyRAT campaign自動判定規則

## 優先順位

1. 公開資料のSHA-256またはMD5完全一致
2. レビュー済みの親子hash・固有配布chain
3. imphash完全一致のコード近縁cluster
4. 上記がなければ未解決

network IOCだけの一致、ファイル名、取得時期、community tag、genericなDLL side-loadingだけでは公開campaignを確定しません。

## actorの扱い

malware family名、MalwareBazaarのcommunity tag、ファイル名、imphash単独ではactorを帰属しない。

公開campaignに完全一致し、その資料がactorを報告している場合も、`source_reported_for_exact_campaign`として情報源依存であることを残します。

## 実行方法

```powershell
python .\analysis-framework\common\attribute_valleyrat_campaigns.py --repository . --write
python .\analysis-framework\common\attribute_valleyrat_campaigns.py --repository . --check
```
