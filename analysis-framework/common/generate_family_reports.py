from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from result_publication import (
    PublicationError,
    detect_publication_context,
    publication_case_path,
    register_publication_cases,
)

def shodan_lines(case: dict) -> list[str]:
    """ケースの根拠に限定したShodan探索用ピボットを日本語で返す。"""

    lines: list[str] = []
    for endpoint in case.get("c2", []):
        host, port = endpoint.rsplit(":", 1)
        host_filter = f'hostname:"{host}"' if not all(p.isdigit() for p in host.split(".")) else f'ip:"{host}"'
        lines.append(
            f"- `{host_filter} port:{port}` — インフラ探索用のピボットであり、プロトコルのフィンガープリントではありません。"
        )
    if not lines:
        lines.append("- 確認済みのホスト／ポートを復元できなかったため、根拠のあるShodanクエリは出力しません。")
    lines.append(
        "- バナーハッシュ、HTTPタイトル、証明書ハッシュ、JARMは、静的／サンドボックス証拠から取得できません。値を推測で作らず、承認済みのライブネットワーク手順でだけ収集してください。"
    )
    return lines


def behavior_c2_assessment(family: str, case: dict) -> list[str]:
    """観測事実と推定能力を分離した挙動・C2評価を返す。"""

    c2 = case.get("c2", [])
    urls = case.get("stage_urls", [])
    duplicate = case.get("campaign") in {"rar_wrapped_javascript", "iso_double_extension_pe"}
    if duplicate:
        provenance = (
            "バイト単位で同一の内側ペイロードから継承。ラッパーから独立してエンドポイントを抽出したとは評価していません"
        )
    elif c2:
        provenance = "外部サンドボックスの設定またはプロセス帰属付き証拠。提出されたローダーだけでは最終エンドポイントを確定していません"
    else:
        provenance = "未復元。ファミリータグやインフラ探索用ピボットを確認済みC2へ昇格していません"
    if family.lower() == "agenttesla":
        protocol = case.get("protocol", "unknown")
        role = (
            f"`{protocol}` を使って窃取情報をアップロードする流出／設定エンドポイント。対話型タスクサーバーとは仮定しません"
            if c2
            else "最終的な流出エンドポイントを独立して復元できませんでした"
        )
        expected = ".NETペイロードのロード後、AgentTeslaは資格情報とホスト／アプリケーションデータを収集し、設定済みチャネルから流出させると見込まれます。プロセス帰属付き証拠がない限り、これはファミリー／設定から推定した能力です。"
    else:
        role = (
            "長時間維持されるRemcosの外向きコマンド＆コントロールチャネル。復元した1設定内の複数ホスト／ポートは、別々のマルウェアファミリーではなく、順序付き代替候補として扱います"
            if c2
            else "Remcosでは対話型C2が想定されますが、このケースでは根拠のあるホスト／ポートを復元できませんでした"
        )
        expected = "ペイロードのロード後、Remcosはコマンド実行、ファイル／プロセス制御、監視、永続化などの対話型遠隔管理機能を提供すると見込まれます。これらはファミリーの能力であり、ケースレポートには配布／サンドボックス証拠で実際に観測した挙動だけを記載します。"
    observed = "; ".join(case.get("notes", [])) or "コンテナ構造以外の追加挙動は確認されませんでした"
    rows = [
        "## 挙動とC2の評価",
        "",
        f"- このケースでの観測事項: {observed}",
        f"- 想定されるペイロード挙動: {expected}",
        f"- C2の想定役割: {role}。",
        f"- エンドポイントの来歴: {provenance}。",
    ]
    if urls:
        rows.append(
            "- 配布先の分離: "
            + ", ".join(f"`{url}`" for url in urls)
            + " はローダー／段階の取得先です。別の証拠で相関しない限り、最終C2ではありません。"
        )
    rows += [
        "- 稼働状況: このケースではライブC2確認を実施していないため、現在の到達可能性とサーバー所有者は不明です。",
        "- 確度ラベル: 配布挙動は静的コード／コンテナ構造から `confirmed`、ペイロード能力はファミリー／設定から `inferred` とします。記載した最終エンドポイントが `confirmed` である範囲は、上記の来歴に限定します。",
    ]
    return rows


def case_report(family: str, case: dict) -> str:
    """レビュー済みケース情報から公開用Markdownを生成する。"""

    c2 = case.get("c2", [])
    urls = case.get("stage_urls", [])
    version = case.get("version")
    rows = [
        f"# {family} ケース {case['sha256'][:12]}",
        "",
        "## 概要",
        "",
        f"- SHA-256: `{case['sha256']}`",
        f"- 成果物種別: `{case['artifact']}`",
        f"- 配布／キャンペーンパターン: `{case['campaign']}`",
        "- 解析方式: 静的解析と公開サンドボックス証拠。検体はローカルで実行していません。",
    ]
    if version:
        rows.append(f"- 復元したファミリーバージョン: `{version}`")
    rows += ["", "## 配布と挙動", ""]
    rows += [f"- 観測事項: {note}" for note in case.get("notes", [])] or ["- 追加の観測事項はありません。"]
    rows += ["", *behavior_c2_assessment(family, case), "", "## ネットワーク観測値", ""]
    rows += [f"- 確認済み設定／サンドボックスエンドポイント: `{value}`" for value in c2] or [
        "- 独立して確認した最終C2エンドポイントは復元されませんでした。"
    ]
    rows += [f"- ローダー／段階URL: `{value}`" for value in urls]
    rows += [
        "- 確度: 確認済みとしたエンドポイントは、マルウェア設定またはプロセス帰属付きサンドボックス証拠から抽出しました。バイト単位で同一の重複コンテナは、内側ペイロードの結果を明示的に継承します。",
        "- ライブC2確認は実施していません。このため、現在の到達可能性とサーバーの実体は不明です。",
        "",
        "## Shodan探索用ピボット",
        "",
        *shodan_lines(case),
        "",
        "## 検知ガイダンス",
        "",
        "- 確度高／誤検知リスク低: 完全一致SHA-256、ローダー構造とファミリー固有文字列を組み合わせたレビュー済みYARA一致、またはエンドポイントと一致するプロセス系譜。",
        "- 確度中／誤検知リスク中: スクリプトホストから隠しPowerShellを起動し、同時に遠隔画像を取得する挙動、メモリ内.NETロード、またはISO内の二重拡張子実行ファイル。",
        "- 確度低／誤検知リスク高: 単一ドメイン／IP、FTP／SMTP利用、PowerShell、WScript、HTA、画像名のダウンロードのいずれかだけ。これらは一般的な管理／アプリケーション挙動でもあります。",
        "- 設定から抽出した資格情報は意図的に公開しません。アクセス制御した証拠にだけ保持し、必要に応じて所有者への通知とローテーションを行ってください。",
        "",
        "## ルール作成用フィールド",
        "",
        f"- ファミリー: `{family}`",
        f"- キャンペーンパターン: `{case['campaign']}`",
        f"- 成果物種別: `{case['artifact']}`",
        f"- SHA-256: `{case['sha256']}`",
        f"- C2値: {', '.join(f'`{value}`' for value in c2) if c2 else '確認済み値なし'}",
        f"- 段階URL: {', '.join(f'`{value}`' for value in urls) if urls else '復元値なし'}",
        "- 遮断前に、親子プロセス、コマンドライン、ファイル取得元、署名者／普及度、ネットワーク接続先を相関してください。",
        "",
        "## 再現手順",
        "",
        "元のパスワード保護済みMalwareBazaar ZIPに対してファミリー一括処理ワークフローを実行してください。別途承認された動的解析ワークフローを使用した場合を除き、出力では `executed=false` と `network_contacted=false` を維持しなければなりません。",
        "",
    ]
    return "\n".join(rows)


def family_index(
    data: dict, case_links: dict[str, str] | None = None
) -> str:
    """ファミリー集約READMEを、指定されたケースリンクで生成する。"""

    links = case_links or {
        case["sha256"]: f"cases/{case['sha256']}/README.md"
        for case in data["cases"]
    }
    family = data["family"]
    rows = [
        f"# {family}解析結果",
        "",
        f"MalwareBazaar提出物{len(data['cases'])}件を、検体をローカル実行せずにトリアージしました。ビルダーやインフラは異なる運用者に再利用され得るため、配布パターンとペイロード／設定クラスタを分離して扱います。",
        "",
        "## ファミリー挙動とC2モデル",
        "",
        (
            "AgentTeslaは主に情報窃取型マルウェアです。これらのケースで提出されたスクリプト／HTA／RARファイルは配布レイヤーです。.NETペイロードのロード後に使われる復元済みFTP／SMTP設定は、対話型の運用者コンソールではなく、窃取データの流出チャネルと解釈するのが妥当です。"
            if family.lower() == "agenttesla"
            else "RemcosRATは対話型の遠隔管理インプラントです。設定済みホスト／ポート値は、外向きのタスク指示と結果通信を運ぶと見込まれます。1つの設定内の複数ポートは代替候補として扱い、配布URLと最終C2は分離します。"
        ),
        "",
        "ケースレポートでは、観測した配布挙動、推定したファミリー能力、エンドポイントの来歴、現在の稼働状況を分離します。対象ケースはローカル実行もライブ確認もしていません。",
        "",
        "| SHA-256 | 成果物種別 | パターン | 確認済みC2／設定エンドポイント |",
        "|---|---|---|---|",
    ]
    if family.lower() == "agenttesla":
        rows[4:4] = [
            "## 証拠の来歴",
            "",
            "現在のケース表にあるFTP／SMTPエンドポイントは、外部サンドボックスの設定出力、またはRARラッパーの場合はバイト単位で同一の内側検体からの継承に由来します。提出されたスクリプトだけから復元したものではありません。オフライン解析では一部ケースから段階URLを復元しましたが、それらの段階は別途取得する必要があるため、元のコンテナから最終.NETペイロードは取得していません。",
            "",
            "`agenttesla_recover.py` はローダー由来の段階URLを記録し、範囲を限定してエンコード済み.NET候補を復元し、機密値を除去したCLR設定を抽出します。`agenttesla_payload_fetch.py` は明示的で上限付きの段階取得を提供します。新しい結果では、エンドポイントの来歴を `static_recovered_dotnet_payload`、`external_sandbox`、`inherited_external_sandbox` のいずれかで示さなければなりません。",
            "",
        ]
    for case in data["cases"]:
        c2 = "<br>".join(f"`{value}`" for value in case.get("c2", [])) or "未復元"
        rows.append(
            f"| [`{case['sha256'][:12]}…`]({links[case['sha256']]}) | `{case['artifact']}` | `{case['campaign']}` | {c2} |"
        )
    rows += [
        "",
        "ファミリー向けYARA／Sigmaの出発点は `rules/` を参照してください。ルールは仮説であり、ローカルの無害なソフトウェアとテレメトリに対する検証が必要です。",
        "",
    ]
    return "\n".join(rows)


def main() -> int:
    """レビュー済みJSONから固定レイアウト対応レポートを生成する。"""

    ap = argparse.ArgumentParser(
        description="レビュー済みケース情報から、機密値を除いた再現可能なファミリーレポートを生成します。"
    )
    ap.add_argument("--cases", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()
    data = json.loads(args.cases.read_text(encoding="utf-8"))
    args.output.mkdir(parents=True, exist_ok=True)
    canonical_context = None
    try:
        canonical_context = detect_publication_context(
            args.output, args.output.name
        )
    except PublicationError:
        if any(
            parent.name == "analysis-results"
            for parent in args.output.resolve().parents
        ):
            raise
    case_links: dict[str, str] = {}
    published_cases: list[Path] = []
    for case in data["cases"]:
        if canonical_context is None:
            dst = args.output / "cases" / case["sha256"]
        else:
            dst, resolved_context = publication_case_path(
                args.output, canonical_context.family, case["sha256"]
            )
            if resolved_context != canonical_context:
                raise PublicationError(
                    "publication context changed during generation"
                )
        dst.mkdir(parents=True, exist_ok=True)
        case_links[case["sha256"]] = Path(
            os.path.relpath(dst / "README.md", args.output)
        ).as_posix()
        (dst / "README.md").write_text(case_report(data["family"], case), encoding="utf-8")
        safe = {
            **case,
            "schema_version": 1,
            "executed_locally": False,
            "network_contacted": False,
            "credentials_published": False,
        }
        (dst / "indicators.json").write_text(json.dumps(safe, indent=2, ensure_ascii=False), encoding="utf-8")
        published_cases.append(dst)
    (args.output / "README.md").write_text(
        family_index(data, case_links), encoding="utf-8"
    )
    if canonical_context is not None:
        register_publication_cases(canonical_context, published_cases)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
