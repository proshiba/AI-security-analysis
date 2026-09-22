# キャンペーン・アクター相関の再監査（2026-09-22）

## 対象と結論

外部監査メモが対象とした commit `e43ec8c9` の指摘を、現行作業ツリー（監査開始時の HEAD `2eb3cd099`）で再検証した。両commitは同一の直線的履歴ではないため、添付の件数や判定をそのまま転記せず、現行のcatalogと一次資料へ照合した。検体実行とC2接続は行っていない。

現行catalogと相関器が列挙するcaseはともに **3,762件**で、漏れは0件だった。既存の1,125件という値は2026年7月24日の古い相関スナップショットの対象件数であり、現行処理が2,587件を除外していることを示さない。2026年9月22日の新しい全件相関は[別スナップショット](../../campaigns/correlated-20260922/README.md)に保持し、自動生成の集合は「レビュー候補」として扱う。

## 指摘別の措置

| 項目 | 再監査結果と措置 |
|---|---|
| SpyGlace / APT-C-60 | [JPCERT/CCの2026年報告](https://blogs.jpcert.or.jp/en/2026/07/apt-c-60_2026.html)に掲載された符号化ファイル4件の完全一致SHA-256を、2026年活動への出典付き一致として登録した。2024年・2025年の個々の活動日へ、この4件を遡及的に割り当てない。DarkHotelをexact aliasにしない。 |
| Latrodectus / TA577・TA578 | [Proofpoint/Team Cymru](https://www.proofpoint.com/us/blog/threat-insight/latrodectus-spider-bytes-ice)の完全一致SHA-256に限定し、2023年11月のLNK・DLL 2件と2024年3月のDLL 1件を出典付きcampaignへ関連付けた。LNKはSTIX File SCOでありMalware SDOではない。ほかのLatrodectus caseへ帰属を波及させない。 |
| TrueConf / Head Mare | [Kaspersky報告](https://securelist.ru/tr/head-mare-targets-trueconf-server-with-phantomcore/116557/)のMD5とローカルSHA-256の対応がある改ざんinstallerのみ、source-attributedとして記録した。PhantomCore子ファイルやC2の独立復元は未完了。 |
| ShadowPad | [Kaspersky ICS CERT](https://ics-cert.kaspersky.com/publications/reports/2022/06/27/attacks-on-industrial-control-systems-using-shadowpad/)の公開ページで確認できたのは `grandfoodtony.com` の重なりであり、添付メモが主張するcampaign ID、Casper、ポートの公開一致は確認できなかった。低確度のドメイン重複候補とし、caseへの強いラベルやActor帰属は付けない。 |
| ValleyRAT | `22d1b557…` の公開一致は悪性DLLではなく正規side-load hostのハッシュだけだった。判定を「正規host共有文脈」に下げ、公開campaign確定を0件とした。Silver FoxやTA4922への帰属は作らない。 |
| Atlas | 内部ID `atlascross` は互換性のため残すが、これはAtlas RATの知識ディレクトリであり、2023年に[NSFOCUS](https://nsfocusglobal.com/pt-br/warning-newly-discovered-apt-attacker-atlascross-exploits-red-cross-blood-drive-phishing-for-cyberattack/)が報告したアクターAtlasCrossやAtlasAgent・DangerAdsと同一視しない。TA4922とSilver Foxもexact aliasにしない。 |
| WannaCry | 旧 `correlated-wannacry-63b40cc27704` は `0.oj`、`c.wnry` 等の擬似ドメインによる誤相関として無効化した。抽出・IOC一覧・監視対象生成でも無効値を再利用しない。59件へ歴史的Actor帰属を一括付与しない。 |

[レビュー済みcampaignの正本とSTIX](../../../stix/reviewed-campaigns/README.md)は、上記の完全一致と部分一致を別扱いにしている。case別の強いラベル更新はLatrodectus 3件、SpyGlace 4件の計7件だけに限定した。Actor関係は資料による帰属の記録であり、リポジトリが独立に運用主体を確定した意味ではない。

## 件数・生成器の修正

監査前には23ファミリーの生成READMEに古いcase件数が残っていた。ファミリー文書生成器をRedC2の `reported_and_static_correlated` 状態に対応させ、これを静的確定版ではなく「報告値」へ集計したうえで、該当23ファミリーをcatalogから再生成した。主要な現在値はValleyRAT 179、WannaCry 59、Vidar 309、RemusStealer 246件で、件数の不一致は0件である。

全件相関を最初に再実行した際、旧形式の `features.json` 4件に `sha256` がなく処理が停止した。相関器は専用schemaだけを使用し、別用途の旧schemaはcaseから再構築するよう修正した。明示されたSHA-256がcaseと矛盾する場合は停止する。

## 残る境界

- 自動相関のscoreは候補の順位付けであり、campaign・operation・Actorの確定ではない。
- 当日の終端ペイロード未取得caseの解析は別の継続課題であり、この監査で完遂したとは扱わない。現行の[終端ギャップ台帳](../../../../intelligence/terminal-payload-recovery/README.md)には未クローズのギャップが1,015件ある。
- 別リポジトリ `threatactor-intel-analysis` には、TA577・TA578・TA4922の活動と、APT-C-60・AtlasCrossの別個のcanonical actor profileを追加した。DarkHotelやAtlas RATとのexact aliasは作っていない。全件生成器が生じさせた対象外の大量差分を含む元コピーは削除・復元せず保持し、意図した51ファイルだけを別の整理済みworktreeへ移した。対象外差分は0件で、push・PRはしていない。

## 検証

全件派生成果物の書込み後検証は3,762 caseを対象に成功し、catalog、文書件数、IOC、コード類似度、論理類似度、checksum、UI、portalの不一致は0件だった。レビュー済みcampaign生成器とfamily STIX生成器の `--check`、Git差分の空白検査も成功した。対象の回帰テスト74件は成功した。これらは公開出典とcaseの対応・生成物の整合性を確かめるもので、未取得の終端payloadの復元やActor帰属の独立証明を意味しない。

整理済みアクター側はCampaign 10件と2件の新規canonical actor profileを含み、manifestは760 actor・424 Campaign・38 activityで整合した。257件のテストと対象STIX Bundleの構造検査は成功した。新規2 profileにはそれぞれ未確定帰属に伴う警告が1件残り、確定帰属とは扱わない。
