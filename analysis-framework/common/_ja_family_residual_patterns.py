"""レガシー変換後に残る ValleyRAT／VenomRAT 固有表現の限定整形。"""

from __future__ import annotations


_EXACT = {
    "## Sigma／YARA／Shodan用材料":
        "## 検出ルールと受動観測向けの材料",
    "`installer_overlay_dropper` / SysCEO偽装系。x64 インストーラーがwinget風cacheへside-ロード バンドルを配置する。":
        "`installer_overlay_dropper`。シスCEOを偽装する系統で、64ビットインストーラーがウィンゲット風キャッシュへサイドロード用バンドルを配置する。",
    "Triage 設定とPID 5136 `dwmhost.exe`の63016反復接続により2つの630xx C2は高信頼。`27.124.18.142:443`は中信頼。Triage：https://tria.ge/reports/260711-23a6tsa16l/ 。":
        "トリアージ設定とプロセス識別子5136の `dwmhost.exe` による63016番への反復接続から、2つの630xx C2は高信頼と判断した。`27.124.18.142:443` は中信頼である。トリアージ情報：https://tria.ge/reports/260711-23a6tsa16l/ 。",
    "- Sigma：System32外のwinget配下dwmhost、同階層DLL ロード、qt64.dat取得、630xx接続を相関。":
        "- 検出ルール：システムディレクトリ外のウィンゲット配下にある dwmhost、同一階層の DLL 読み込み、qt64.dat取得、630xx番への接続を相関させる。",
    "| 署名済み ホストと同階層の未署名DLL・小容量BINの同時作成 | パス, signature, サイズ, ハッシュ | 中 | 中。自己展開インストーラーをpublisher/パス allowlistで除外 |":
        "| 署名済み実行ファイルと同一階層における未署名 DLL・小容量バイナリの同時作成 | パス、署名、サイズ、ハッシュ | 中 | 中。自己展開インストーラーは発行元とパスの許可一覧で除外 |",
    "## 10. 現在のC2生存確認とShodan条件":
        "## 10. 現在の C2 稼働確認と受動観測条件",
    "- Sentry ingest、Google、Bing、Yandex、Baidu、Ctrip、CloudFront、証明書失効確認。":
        "- セントリーへの取り込み、グーグル、ビング、ヤンデックス、バイドゥ、シートリップ、クラウドフロント、証明書失効確認。",
    "### Windowsインストーラー/CAB構造":
        "### ウィンドウズインストーラー／キャビネット書庫の構造",
    "| スケジュール済み タスク `MyAutoStartApp`がLK配下`mesedge.exe`をonlogon/最高で実行 | TaskName, TaskContent/コマンド | 高 | 低。組織固有タスク名衝突を確認 |":
        "| スケジュールタスク `MyAutoStartApp` が LK 配下の `mesedge.exe` をログオン時に最高権限で実行 | タスク名、タスク内容／コマンド | 高 | 低。組織固有タスク名との衝突を確認 |",
    "## 9. MITRE ATT&CK観点":
        "## 9. 攻撃戦術・技術知識体系の観点",
    "## 11. 現在のC2生存確認とShodan条件":
        "## 11. 現在の C2 稼働確認と受動観測条件",
    "- `confirmed`：キャンペーン reporting および 公開 サンドボックス relations associate archive を伴う `ljowqjd.cn` および 誘導名 対象 `【重要通知】賞与に関する新着情報があります`.":
        "- `confirmed`：キャンペーン報告と公開サンドボックスの関連情報から、アーカイブに関連する `ljowqjd.cn` および誘導名 `【重要通知】賞与に関する新着情報があります` を確認した。",
    "2020年頃から報告される.NET製遠隔操作型で、クエーサー系コードを基にした改変／クローンとして説明され、遠隔操作、画面・キー入力・認証情報・ファイル操作等を備える。[出典：マイクロソフト「トロイの木馬:Win32/VenomRat.AVM!MTB」](<https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan%3AWin32%2FVenomRat.AVM%21MTB&ThreatID=2147902074>) [出典：フォーティネット「スクラブクリプト 配布する Venom を伴う 多数 の プラグイン」](<https://www.fortinet.com/blog/threat-research/scrubcrypt-deploys-venomrat-with-arsenal-of-plugins>)":
        "2020年頃から報告される .NET 製の遠隔操作型トロイで、クエーサー系コードを基にした改変またはクローンとして説明されている。遠隔操作、画面、キー入力、認証情報、ファイル操作などの機能を備える。[出典：マイクロソフト脅威情報「Win32/VenomRat.AVM!MTB」](<https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan%3AWin32%2FVenomRat.AVM%21MTB&ThreatID=2147902074>) [出典：フォーティネット「ScrubCryptによるVenomRATと多数プラグインの配布」](<https://www.fortinet.com/blog/threat-research/scrubcrypt-deploys-venomrat-with-arsenal-of-plugins>)",
    "分類：コモディティマルウェア。地下市場で流通するクエーサークローン型のコモディティ遠隔操作型で、複数配布アクターが使用する。（[出典：マイクロソフト「トロイの木馬:Win32/VenomRat.AVM!MTB」](<https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan%3AWin32%2FVenomRat.AVM%21MTB&ThreatID=2147902074>)、[出典：プルーフポイント「セキュリティ 概説：Venom 無力化」](<https://www.proofpoint.com/us/blog/threat-insight/security-brief-venomrat-defanged>)）":
        "分類：コモディティマルウェア。地下市場で流通するクエーサークローン型のコモディティ遠隔操作型で、複数の配布アクターが使用する。（[出典：マイクロソフト脅威情報「Win32/VenomRat.AVM!MTB」](<https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan%3AWin32%2FVenomRat.AVM%21MTB&ThreatID=2147902074>)、[出典：プルーフポイント「VenomRATの無力化」](<https://www.proofpoint.com/us/blog/threat-insight/security-brief-venomrat-defanged>)）",
    "- `nz-venom-ms`：[出典：マイクロソフト「トロイの木馬:Win32/VenomRat.AVM!MTB」](<https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan%3AWin32%2FVenomRat.AVM%21MTB&ThreatID=2147902074>)／日付未記載／脅威知識ベース":
        "- `nz-venom-ms`：[出典：マイクロソフト脅威情報「Win32/VenomRat.AVM!MTB」](<https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan%3AWin32%2FVenomRat.AVM%21MTB&ThreatID=2147902074>)／日付未記載／脅威知識ベース",
}


def translate_line(line: str) -> str:
    """既知の残存行だけを置換し、未知行は変更しない。"""
    leading = line[: len(line) - len(line.lstrip())]
    trailing = line[len(line.rstrip()):]
    core = line.strip()
    target = _EXACT.get(core)
    return line if target is None else leading + target + trailing
