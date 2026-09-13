"""全case一括反映の文書件数とchecksum同期を検証する。"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
sys.path.insert(0, str(COMMON))

import refresh_case_inventory as inventory


def test_publication_safety_rejects_datastore_upload_receipt(tmp_path: Path) -> None:
    case = tmp_path / "analysis-results" / "case"
    case.mkdir(parents=True)
    receipt = case / "datastore-upload.json"
    receipt.write_text("{}\n", encoding="utf-8")

    result = inventory._validate_publication_safety(tmp_path)

    assert result["violations"] == ["analysis-results/case/datastore-upload.json"]
    with pytest.raises(ValueError, match="datastore upload receipt"):
        inventory.refresh(tmp_path, check=True)


def test_publication_safety_allows_private_work_receipt(tmp_path: Path) -> None:
    receipt = tmp_path / ".work" / "datastore-reports" / "datastore-upload.json"
    receipt.parent.mkdir(parents=True)
    receipt.write_text("{}\n", encoding="utf-8")

    assert inventory._validate_publication_safety(tmp_path)["violations"] == []


def _counts() -> dict[str, int]:
    return {
        "unique_case_hashes": 12,
        "malware_cases": 9,
        "unclassified_cases": 2,
        "supply_chain_payload_cases": 1,
        "confirmed_malware_versions": 3,
        "reported_malware_versions": 1,
        "unknown_malware_versions": 5,
    }


def test_sync_documented_case_counts_updates_both_readmes(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text(
        "現在は未分類検体を含む1件のSHA-256 caseを扱い、解析します。\n",
        encoding="utf-8",
    )
    results = tmp_path / "analysis-results"
    results.mkdir()
    (results / "README.md").write_text(
        """# 成果物

## 現在の収録状況

| 区分 | 件数 |
|---|---:|
| SHA-256で一意な全case | 1 |
| 未分類 | 1 |

版名は根拠がある場合だけ使用します。
未分類1件は既知ファミリへ無理に帰属させていません。
""",
        encoding="utf-8",
    )

    result = inventory.sync_documented_case_counts(tmp_path, _counts(), write=True)

    assert result["write_performed"] is True
    assert "含む12件のSHA-256 case" in (tmp_path / "README.md").read_text(encoding="utf-8")
    rendered = (results / "README.md").read_text(encoding="utf-8")
    assert "| SHA-256で一意な全case | 12 |" in rendered
    assert "| 未分類case | 2 |" in rendered
    assert "未分類2件は" in rendered
    assert inventory.sync_documented_case_counts(tmp_path, _counts())["mismatches"] == []


def test_sync_checksum_manifests_detects_and_repairs_stale_file(tmp_path: Path) -> None:
    case = tmp_path / "analysis-results" / "case"
    case.mkdir(parents=True)
    (case / "report.json").write_text("{}\n", encoding="utf-8")
    manifest = case / "manifest.sha256"
    manifest.write_text("stale\n", encoding="utf-8")

    dry_run = inventory.sync_checksum_manifests(tmp_path)
    assert dry_run["mismatches"] == ["analysis-results/case/manifest.sha256"]
    inventory.sync_checksum_manifests(tmp_path, write=True)
    assert inventory.sync_checksum_manifests(tmp_path)["mismatches"] == []
    assert "report.json" in manifest.read_text(encoding="utf-8")

def test_sync_checksum_manifests_is_portable_across_text_line_endings(
    tmp_path: Path,
) -> None:
    case = tmp_path / "analysis-results" / "case"
    case.mkdir(parents=True)
    report = case / "report.json"
    report.write_bytes(b'{\r\n  "status": "ok"\r\n}\r\n')
    binary = case / "payload.bin"
    binary.write_bytes(b"\x00payload\r\n")
    manifest = case / "manifest.sha256"
    manifest.write_text("stale\n", encoding="utf-8")

    inventory.sync_checksum_manifests(tmp_path, write=True)
    rendered = manifest.read_text(encoding="utf-8")

    portable_digest = hashlib.sha256(b'{\n  "status": "ok"\n}\n').hexdigest()
    binary_digest = hashlib.sha256(b"\x00payload\r\n").hexdigest()
    assert f"{portable_digest}  report.json" in rendered
    assert f"{binary_digest}  payload.bin" in rendered

    report.write_bytes(b'{\n  "status": "ok"\n}\n')
    assert inventory.sync_checksum_manifests(tmp_path)["mismatches"] == []


def test_streaming_checksum_normalizes_crlf_across_chunk_boundary(
    tmp_path: Path,
) -> None:
    target = tmp_path / "report.txt"
    target.write_bytes(b"ab\r\ncd\r")

    digest = inventory._streaming_sha256(
        target,
        normalize_crlf=True,
        chunk_bytes=3,
    )

    assert digest == hashlib.sha256(b"ab\ncd\r").hexdigest()


def _stub_plan() -> dict:
    return {
        "errors": [],
        "cases": [],
        "counts": _counts(),
        "catalog": {"path": "analysis-results/catalog/cases.json", "document": {}},
    }


def _install_plan_counter(monkeypatch, *, metadata_written: bool) -> list[int]:
    """レイアウト計画の構築回数を数え、他の重い段階は無害化する。"""
    calls = [0]

    def counting_plan(_root):
        calls[0] += 1
        return _stub_plan()

    monkeypatch.setattr(inventory, "build_layout_plan", counting_plan)
    monkeypatch.setattr(inventory, "preflight_catalog_sync", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        inventory,
        "sync_case_identity_metadata",
        lambda root, *, write=False, plan=None: {
            "updated_cases": [],
            "write_performed": bool(write and metadata_written),
        },
    )
    monkeypatch.setattr(
        inventory,
        "sync_catalog",
        lambda root, *, write=False, plan=None, approved_case_removals=frozenset(),
        bootstrap_missing_catalog=False: {
            "added_cases": [],
            "updated_cases": [],
            "removed_case_count": 0,
            "write_performed": False,
        },
    )
    monkeypatch.setattr(
        inventory,
        "sync_documented_case_counts",
        lambda root, counts, *, write=False: {"mismatches": [], "write_performed": False},
    )
    for name in ("generate_ioc_lists", "generate_code_similarity", "generate_logic_similarity"):
        monkeypatch.setattr(
            inventory, name,
            lambda root, *a, write=False, check=False, **kw: {
                "mismatches": [], "write_performed": False
            },
        )
    monkeypatch.setattr(
        inventory, "sync_checksum_manifests",
        lambda root, *, write=False: {"manifests": 0, "mismatches": [], "write_performed": False},
    )
    monkeypatch.setattr(
        inventory, "_run_ui_command",
        lambda root, script, *, check: {
            "script": script, "returncode": 0, "check_failed": False, "stderr": ""
        },
    )
    return calls


def test_check_builds_layout_plan_once(monkeypatch, tmp_path: Path) -> None:
    """書き込まないパスではツリーが変わらないので計画は1回で足りる。"""
    calls = _install_plan_counter(monkeypatch, metadata_written=False)
    inventory.refresh(tmp_path, check=True)
    assert calls[0] == 1


def test_write_rebuilds_plan_only_when_metadata_changed(monkeypatch, tmp_path: Path) -> None:
    """write後checkを再帰実行し、metadata変更時だけouter planを作り直す。"""
    calls = _install_plan_counter(monkeypatch, metadata_written=True)
    result = inventory.refresh(tmp_path, write=True)
    assert calls[0] == 3
    assert result["verification"]["mode"] == "check"

    calls = _install_plan_counter(monkeypatch, metadata_written=False)
    result = inventory.refresh(tmp_path, write=True)
    assert calls[0] == 2
    assert result["verification"]["check_failed"] is False


def test_write_preflight_failure_happens_before_metadata_write(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """削除承認不一致なら最初のmetadata writeより前に停止する。"""

    _install_plan_counter(monkeypatch, metadata_written=False)
    events = []

    def reject_preflight(*_args, **_kwargs):
        events.append("preflight")
        raise inventory.CatalogSyncError("approval mismatch")

    def unexpected_metadata(*_args, **_kwargs):
        events.append("metadata")
        pytest.fail("承認不一致後にmetadata writeへ進んではならない")

    monkeypatch.setattr(inventory, "preflight_catalog_sync", reject_preflight)
    monkeypatch.setattr(inventory, "sync_case_identity_metadata", unexpected_metadata)

    with pytest.raises(inventory.CatalogSyncError, match="approval mismatch"):
        inventory.refresh(tmp_path, write=True)
    assert events == ["preflight"]


def test_refresh_bootstrap_requires_write_and_rejects_deletion_approval(
    tmp_path: Path,
) -> None:
    """refresh API/CLIのbootstrapをwrite専用かつ削除承認と排他的にする。"""

    with pytest.raises(ValueError, match="requires write mode"):
        inventory.refresh(tmp_path, bootstrap_missing_catalog=True)
    with pytest.raises(inventory.CatalogSyncError, match="cannot be combined"):
        inventory.refresh(
            tmp_path,
            write=True,
            approved_case_removals=frozenset({"a" * 64}),
            bootstrap_missing_catalog=True,
        )
    with pytest.raises(ValueError, match="requires --write"):
        inventory.main(["--bootstrap-missing-catalog"])
    with pytest.raises(ValueError, match="requires --write"):
        inventory.main(["--allow-removed-case-stdin"])
    with pytest.raises(inventory.CatalogSyncError, match="cannot be combined"):
        inventory.main(
            [
                "--write",
                "--bootstrap-missing-catalog",
                "--allow-removed-case-stdin",
            ]
        )


def test_refresh_cli_passes_stdin_approval_without_argv_digest(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    approved = frozenset({"a" * 64})
    captured = {}
    monkeypatch.setattr(
        inventory,
        "read_approved_case_removals_from_stdin",
        lambda: approved,
    )

    def refresh(repository, **kwargs):
        captured.update(repository=repository, **kwargs)
        return {"check_failed": False}

    monkeypatch.setattr(inventory, "refresh", refresh)

    assert inventory.main(
        [
            "--repository",
            str(tmp_path),
            "--write",
            "--allow-removed-case-stdin",
        ]
    ) == 0
    assert captured == {
        "repository": tmp_path,
        "write": True,
        "check": False,
        "approved_case_removals": approved,
        "bootstrap_missing_catalog": False,
    }


def test_refresh_cli_passes_explicit_catalog_bootstrap(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured = {}

    def refresh(repository, **kwargs):
        captured.update(repository=repository, **kwargs)
        return {"check_failed": False}

    monkeypatch.setattr(inventory, "refresh", refresh)

    assert inventory.main(
        [
            "--repository",
            str(tmp_path),
            "--write",
            "--bootstrap-missing-catalog",
        ]
    ) == 0
    assert captured == {
        "repository": tmp_path,
        "write": True,
        "check": False,
        "approved_case_removals": frozenset(),
        "bootstrap_missing_catalog": True,
    }


def test_write_repreflights_rebuilt_plan_and_then_recursively_checks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """metadata更新後のplanを再承認検証してからcatalogを書き、checkを再帰実行する。"""

    _install_plan_counter(monkeypatch, metadata_written=False)
    approved = frozenset({"a" * 64})
    events = []
    metadata_calls = 0

    def preflight(_root, **kwargs):
        events.append(
            (
                "preflight",
                kwargs["approved_case_removals"],
                kwargs["bootstrap_missing_catalog"],
            )
        )

    def metadata(_root, *, write=False, plan=None):
        nonlocal metadata_calls
        metadata_calls += 1
        events.append(("metadata", write))
        return {
            "updated_cases": [],
            "write_performed": bool(write and metadata_calls == 1),
        }

    def sync_catalog(
        _root,
        *,
        write=False,
        plan=None,
        approved_case_removals=frozenset(),
        bootstrap_missing_catalog=False,
    ):
        events.append(
            (
                "catalog",
                write,
                approved_case_removals,
                bootstrap_missing_catalog,
            )
        )
        return {
            "added_cases": [],
            "updated_cases": [],
            "removed_case_count": int(write),
            "write_performed": write,
        }

    monkeypatch.setattr(inventory, "preflight_catalog_sync", preflight)
    monkeypatch.setattr(inventory, "sync_case_identity_metadata", metadata)
    monkeypatch.setattr(inventory, "sync_catalog", sync_catalog)

    result = inventory.refresh(
        tmp_path,
        write=True,
        approved_case_removals=approved,
    )

    assert events[:4] == [
        ("preflight", approved, False),
        ("metadata", True),
        ("preflight", approved, False),
        ("catalog", True, approved, False),
    ]
    assert ("catalog", False, frozenset(), False) in events
    assert result["verification"]["mode"] == "check"
