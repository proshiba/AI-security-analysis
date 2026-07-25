"""canonical IOC JSONとMarkdown描画の共有境界を検証する。"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).parents[2]
COMMON = REPOSITORY / "analysis-framework" / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from analysis_contract import seal_report, verify_report_semantics  # noqa: E402
from generate_ioc_lists import generate  # noqa: E402
from ioc_markdown import (  # noqa: E402
    canonical_ioc_view,
    render_canonical_ioc_document,
    render_submitted_iocs,
)
import publish_one_shot_collection as publisher  # noqa: E402


def canonical_document(
    digest: str,
    network: list[dict] | None = None,
) -> dict:
    """テスト用のpublisher形式iocs.jsonを返す。"""

    return {
        "schema_version": 1,
        "sha256": [digest],
        "network": network or [],
        "assessment": "静的設定証拠だけを収録",
        "sample_executed": False,
        "network_contacted": False,
    }


def create_case(repository: Path, digest: str, document: dict) -> Path:
    """generatorが列挙できる最小のcanonical caseを作る。"""

    case = (
        repository
        / "analysis-results"
        / "malware"
        / "example"
        / "versions"
        / "unknown"
        / "cases"
        / digest
    )
    case.mkdir(parents=True)
    (case / "README.md").write_text(
        "# テストケース\n\n## C2候補\n\n- `https://candidate.example/path`\n",
        encoding="utf-8",
    )
    (case / "iocs.json").write_text(
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (repository / "analysis_history.yaml").write_text("analyses: []\n", encoding="utf-8")
    return case


def test_shared_renderer_keeps_only_confirmed_static_configuration() -> None:
    """候補を昇格せず、URL秘密値を除去してrole・source・evidenceを描画する。"""

    digest = "a" * 64
    confirmed = {
        "url": "https://user:pass@c2.example/route.php?token=secret#fragment",
        "role": "beacon_or_tasking",
        "confidence": "confirmed_static_configuration",
        "source": "handler:efimer:extract",
        "evidence": {
            "kind": "deobfuscated_static_assignment",
            "source_file": "config.js",
            "token": "must-not-be-published",
        },
    }
    candidate = {
        **confirmed,
        "url": "https://candidate.example/path",
        "confidence": "candidate_static_literal",
    }
    document = canonical_document(digest, [candidate, confirmed, dict(confirmed)])

    rendered = render_canonical_ioc_document(document, expected_sha256=digest)

    assert rendered == publisher.render_iocs(digest, document["network"])
    assert "https://c2.example/route.php" in rendered
    assert "beacon_or_tasking" in rendered
    assert "confirmed_static_configuration" in rendered
    assert "handler:efimer:extract" in rendered
    assert "handler:efimer:extract; config.js" in rendered
    assert "must-not-be-published" not in rendered
    assert "candidate.example" not in rendered
    assert "user:pass@" not in rendered
    assert "token=secret" not in rendered
    assert canonical_ioc_view(document, expected_sha256=digest).entry_count == 2


def test_shared_renderer_is_deterministic_and_hash_only_compatible() -> None:
    """入力順に依存せず、network IOCがない既存publisher呼出しも維持する。"""

    digest = "b" * 64
    records = [
        {
            "host": "second.example",
            "port": 8443,
            "role": "tasking",
            "confidence": "confirmed_static_configuration",
            "source": "handler:test",
            "evidence": {"kind": "decoded_config", "index": 2},
        },
        {
            "host": "first.example",
            "port": 443,
            "role": "beacon",
            "confidence": "confirmed_static_configuration",
            "source": "handler:test",
            "evidence": {"kind": "decoded_config", "index": 1},
        },
    ]

    assert render_canonical_ioc_document(canonical_document(digest, records)) == (
        render_canonical_ioc_document(canonical_document(digest, list(reversed(records))))
    )
    assert render_submitted_iocs(digest) == publisher.render_iocs(digest)
    assert canonical_ioc_view(canonical_document(digest)).entry_count == 1


def test_generator_trusts_canonical_iocs_instead_of_candidate_text(
    tmp_path: Path,
) -> None:
    """canonical caseではREADME候補を混ぜず、publisherと同じIOC-LISTを生成する。"""

    digest = "c" * 64
    network = [
        {
            "url": "https://user:pass@confirmed.example/gate?secret=value",
            "role": "command_and_control",
            "confidence": "confirmed_static_configuration",
            "source": "handler:test",
            "evidence": {"kind": "decoded_config", "source_file": "settings.bin"},
        },
        {
            "url": "https://candidate.example/path",
            "role": "candidate",
            "confidence": "candidate_static_literal",
            "source": "handler:test",
            "evidence": {"kind": "string_scan"},
        },
    ]
    document = canonical_document(digest, network)
    case = create_case(tmp_path, digest, document)

    result = generate(tmp_path, write=True)

    content = (case / "IOC-LIST.md").read_text(encoding="utf-8")
    assert result["analyses"] == 1
    assert result["indicators"] == 2
    assert content == render_canonical_ioc_document(document, expected_sha256=digest)
    assert "https://confirmed.example/gate" in content
    assert "candidate.example" not in content
    assert "user:pass@" not in content
    assert "secret=value" not in content
    assert generate(tmp_path, check=True)["mismatches"] == []


def test_generator_reseals_tracked_ioc_list_after_write(tmp_path: Path) -> None:
    """追跡済みIOC-LISTを書き換えた場合だけartifact hashとreport sealを同期する。"""

    digest = "d" * 64
    case = create_case(tmp_path, digest, canonical_document(digest))
    stale = "古いIOC一覧\n"
    (case / "IOC-LIST.md").write_text(stale, encoding="utf-8")
    report = {
        "schema_version": 1,
        "artifact_sha256": {
            "IOC-LIST.md": hashlib.sha256(stale.encode("utf-8")).hexdigest(),
        },
    }
    seal_report(report)
    (case / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    generate(tmp_path, write=True)

    refreshed = json.loads((case / "report.json").read_text(encoding="utf-8"))
    assert refreshed["artifact_sha256"]["IOC-LIST.md"] == hashlib.sha256(
        (case / "IOC-LIST.md").read_bytes()
    ).hexdigest()
    assert verify_report_semantics(refreshed) == []


def test_canonical_renderer_rejects_case_hash_mismatch() -> None:
    """case境界とiocs.jsonの提出hashが異なる場合はfail-closedにする。"""

    with pytest.raises(ValueError, match="一致しません"):
        render_canonical_ioc_document(
            canonical_document("e" * 64),
            expected_sha256="f" * 64,
        )
