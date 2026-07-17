"""Tests for the bounded, static-only deep triage orchestrator."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import sys

import pyzipper
import pytest

REPOSITORY = Path(__file__).parents[2]
COMMON = REPOSITORY / "analysis-framework" / "common"
for entry in (REPOSITORY, COMMON):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

import deep_static_triage as triage  # noqa: E402


def _digest(data: bytes) -> str:
    """Return a fixture SHA-256 value."""

    return hashlib.sha256(data).hexdigest()


def _aes_zip(name: str, data: bytes) -> bytes:
    """Build a MalwareBazaar-style encrypted fixture archive."""

    stream = io.BytesIO()
    with pyzipper.AESZipFile(
        stream,
        "w",
        compression=pyzipper.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as archive:
        archive.setpassword(b"infected")
        archive.setencryption(pyzipper.WZ_AES, nbits=256)
        archive.writestr(name, data)
    return stream.getvalue()


def test_load_and_expand_inventory_with_case_override(tmp_path: Path) -> None:
    """Expand group hashes and apply explicit per-hash override fields."""

    first = "1" * 64
    second = "2" * 64
    child = "3" * 64
    inventory = tmp_path / "inventory.yaml"
    inventory.write_text(
        "\n".join(
            [
                "groups:",
                "  - id: native-protectors",
                "    family: ValleyRAT",
                "    category: virtualization",
                "    priority: high",
                "    blockers: [opaque_predicates]",
                f"    hashes: [{first}]",
                "cases:",
                f"  - sha256: {first}",
                "    priority: critical",
                "    blockers: [control_flow_flattening]",
                f"    expected_children: [{child}]",
                f"    raw_code_layers: {{{child}: 64}}",
                f"  - sha256: {second}",
                "    family: RemcosRAT",
                "    container_probe: true",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    document = triage.load_inventory(inventory)
    cases = triage.expand_inventory(document)
    assert [item["sha256"] for item in cases] == [first, second]
    assert cases[0]["group_id"] == "native-protectors"
    assert cases[0]["priority"] == "critical"
    assert cases[0]["blockers"] == ["control_flow_flattening"]
    assert cases[0]["expected_children"] == [child]
    assert cases[0]["raw_code_layers"] == {child: 64}
    assert cases[1]["family"] == "RemcosRAT"
    assert cases[1]["container_probe"] is True
    with pytest.raises(ValueError):
        triage.expand_inventory({"groups": "invalid"})
    with pytest.raises(ValueError):
        triage.expand_inventory(
            {"cases": [{"sha256": "4" * 64, "container_probe": "yes"}]}
        )


def test_reviewed_container_probe_and_tool_paths_are_forwarded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pass explicit static-tool settings only for a reviewed root carrier."""
    data = b"fixture"
    digest = _digest(data)
    source = tmp_path / digest
    source.write_bytes(data)
    observed: dict[str, object] = {}

    def fake_unpack(blob: bytes, name: str, **kwargs):
        observed.update(kwargs)
        return {"format": "data", "name": name}, []

    monkeypatch.setattr(triage, "unpack_bytes", fake_unpack)
    result = triage.analyze_case(
        {
            "sha256": digest,
            "family": "Fixture",
            "container_probe": True,
        },
        [{"path": source, "source_kind": "raw_file"}],
        sevenzip=tmp_path / "7z.exe",
        archive_password="infected",
    )
    assert result["status"] == "analyzed"
    assert observed == {
        "sevenzip": tmp_path / "7z.exe",
        "force_container_probe": True,
        "archive_password": "infected",
    }


def test_index_local_samples_recognizes_raw_and_aes_zip(tmp_path: Path) -> None:
    """Index hash-labelled binaries and ZIPs while ignoring report files."""

    raw_hash = "a" * 64
    zip_hash = "b" * 64
    (tmp_path / raw_hash).write_bytes(b"raw")
    (tmp_path / f"{zip_hash}.zip").write_bytes(b"zip")
    (tmp_path / f"{raw_hash}.json").write_text("{}", encoding="utf-8")
    (tmp_path / "not-a-hash.exe").write_bytes(b"x")
    index = triage.index_local_samples([tmp_path, tmp_path / "missing"])
    assert set(index) == {raw_hash, zip_hash}
    assert index[raw_hash][0]["source_kind"] == "raw_file"
    assert index[zip_hash][0]["source_kind"] == "aes_zip"


def test_scan_protector_markers_supports_ascii_wide_and_bounds() -> None:
    """Detect required ASCII and UTF-16LE marker families in bounded windows."""

    wide_vmprotect = "VMProtect".encode("utf-16-le")
    data = (
        b"Themida WinLicense KoiVM ConfuserEx Enigma .NET Reactor "
        + wide_vmprotect
        + b" UPX! SmartAssembly nsPack"
    )
    markers = triage.scan_protector_markers(data)
    assert set(markers) == {
        "KoiVM",
        "ConfuserEx",
        "Themida",
        "WinLicense",
        "VMProtect",
        "Enigma",
        ".NET Reactor",
        "SmartAssembly",
        "nsPack",
        "UPX",
    }
    with pytest.raises(ValueError):
        triage.scan_protector_markers(data, max_scan_bytes=0)
    assert triage.scan_protector_markers(b"random upx coincidence") == []
    assert (
        triage._contextual_markers(
            ["UPX"], {"pe": {"packer_markers": [], "sections": []}}, "pe"
        )
        == []
    )
    assert triage._contextual_markers(
        ["UPX"], {"pe": {"packer_markers": ["UPX!"], "sections": []}}, "pe"
    ) == []
    assert triage._contextual_markers(
        ["UPX"],
        {
            "pe": {
                "packer_markers": ["UPX!"],
                "sections": [],
                "classification": "packed_or_protected",
            }
        },
        "pe",
    ) == ["UPX"]


def test_analyze_case_recurses_in_memory_and_strips_private_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Route PE and explicitly declared raw code without persisting child bytes."""

    root_data = b"MZ" + b"Themida" + b"\x00" * 24
    child_data = b"\x90\xc3 KoiVM"
    root_hash = _digest(root_data)
    child_hash = _digest(child_data)
    root_path = tmp_path / root_hash
    root_path.write_bytes(root_data)
    calls: list[tuple[str, int | None]] = []
    unpack_names: list[str] = []

    def fake_unpack(data: bytes, name: str):
        """Return one recovered raw-code layer for the root fixture."""

        unpack_names.append(name)
        if data == root_data:
            return (
                {
                    "format": "pe",
                    "name": name,
                    "path": r"C:\private\sample.exe",
                    "nested": {"blocks": [{"address": "0x1"}]},
                    "executed": False,
                },
                [("decoded-loader", child_data)],
            )
        return {"format": "data", "name": name, "executed": False}, []

    def fake_pe(data: bytes, **kwargs):
        """Record the bounded PE control-flow invocation."""

        calls.append(("pe", kwargs["max_blocks"]))
        return {
            "status": "analyzed",
            "blocks": [{"address": "0x10"}],
            "local_path": r"C:\private\cfg.json",
            "techniques": {"control_flow_flattening": {"status": "suspected"}},
        }

    def fake_raw(data: bytes, *, bits: int, **kwargs):
        """Record explicit raw-code routing and its declared architecture."""

        calls.append(("raw", bits))
        return {"status": "analyzed", "blocks": [{"address": "0"}], "techniques": {}}

    monkeypatch.setattr(triage, "unpack_bytes", fake_unpack)
    monkeypatch.setattr(triage, "analyze_pe_control_flow", fake_pe)
    monkeypatch.setattr(triage, "analyze_code_region", fake_raw)
    case = {
        "sha256": root_hash,
        "family": "Fixture",
        "category": "cff",
        "priority": "high",
        "blockers": ["control_flow_flattening"],
        "expected_children": [child_hash],
        "raw_code_layers": {child_hash: 64},
    }
    result = triage.analyze_case(
        case,
        [{"path": root_path, "source_kind": "raw_file"}],
        max_depth=2,
        max_nodes=3,
        max_blocks=17,
    )
    assert result["status"] == "analyzed"
    assert [item[0] for item in calls] == ["pe", "raw"]
    assert calls[0] == ("pe", 17) and calls[1] == ("raw", 64)
    assert len(result["nodes"]) == 2
    assert result["expected_children"]["all_observed"] is True
    assert result["expected_children"]["all_analyzed"] is True
    assert unpack_names[0].endswith(".exe")
    assert unpack_names[1].endswith(".bin")
    rendered = json.dumps(result)
    assert "private" not in rendered.lower()
    assert '"blocks"' not in rendered
    assert result["raw_artifacts_written"] is False
    assert list(tmp_path.iterdir()) == [root_path]


def test_analyze_case_reads_aes_zip_and_enforces_depth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Authenticate a MalwareBazaar archive and stop recovered traversal at depth zero."""

    data = b"fixture"
    child = b"child"
    digest = _digest(data)
    archive_path = tmp_path / f"{digest}.zip"
    archive_path.write_bytes(_aes_zip("fixture.bin", data))
    monkeypatch.setattr(
        triage,
        "unpack_bytes",
        lambda blob, name: ({"format": "data"}, [("child", child)]),
    )
    case = {"sha256": digest, "family": "Fixture"}
    result = triage.analyze_case(
        case,
        [{"path": archive_path, "source_kind": "aes_zip"}],
        max_depth=0,
    )
    assert result["source_kind"] == "aes_zip"
    assert result["nodes"][0]["children"][0]["analysis"] == "depth_limit"
    assert result["budget_limited"] is True

    total_limited = triage.analyze_case(
        case,
        [{"path": archive_path, "source_kind": "aes_zip"}],
        max_depth=1,
        max_total_layer_bytes=len(data) + len(child) - 1,
    )
    assert (
        total_limited["nodes"][0]["children"][0]["analysis"]
        == "total_byte_limit"
    )

    unpack_calls = 0

    def forbidden_unpack(blob: bytes, name: str):
        """Fail if a root rejected by the scheduled-byte budget is unpacked."""

        nonlocal unpack_calls
        unpack_calls += 1
        raise AssertionError("over-budget root must not be unpacked")

    monkeypatch.setattr(triage, "unpack_bytes", forbidden_unpack)
    root_limited = triage.analyze_case(
        case,
        [{"path": archive_path, "source_kind": "aes_zip"}],
        max_total_layer_bytes=len(data) - 1,
    )
    assert unpack_calls == 0
    assert root_limited["status"] == "partial"
    assert root_limited["budget_limited"] is True
    assert root_limited["nodes"] == []
    assert root_limited["budget_stop"] == {
        "reason": "root_total_byte_limit",
        "root_size": len(data),
        "root_was_unpacked": False,
    }
    accounting = root_limited["budgets"]["max_total_layer_bytes_accounting"]
    assert accounting["is_peak_process_memory_limit"] is False
    assert accounting["includes_unpacker_internal_temporary_allocations"] is False
    assert root_limited["budget_usage"]["scheduled_layer_bytes"] == 0


def test_run_render_write_parser_and_main(tmp_path: Path) -> None:
    """Cover batch summary, Markdown, output restrictions, parser, and CLI entry point."""

    digest = "d" * 64
    document = {
        "groups": [
            {
                "id": "missing",
                "family": "Fixture",
                "category": "static",
                "priority": "low",
                "blockers": [],
                "hashes": [digest],
            }
        ]
    }
    report = triage.run_inventory(document, [tmp_path / "samples"])
    assert report["summary"]["total"] == 1
    assert report["summary"]["not_found"] == 1
    assert report["safety"] == {
        "executed": False,
        "emulated": False,
        "network_contacted": False,
        "raw_artifacts_written": False,
        "persistent_outputs": ["json", "markdown"],
    }
    markdown = triage.render_markdown(report)
    assert "# 深層静的トリアージ" in markdown and digest in markdown
    assert "## 概要" in markdown
    assert "| 総ケース数 | 1 |" in markdown
    assert "## ケース詳細" in markdown
    assert "- 解析上限到達: いいえ" in markdown
    assert "`Fixture`" in markdown
    assert "`not_found`" in markdown
    assert "This report was produced" not in markdown
    output = tmp_path / "report"
    json_path, markdown_path = triage.write_public_report(report, output)
    assert {path.name for path in output.iterdir()} == {
        "deep-static-triage.json",
        "deep-static-triage.md",
    }
    assert json.loads(json_path.read_text(encoding="utf-8"))["summary"]["total"] == 1
    assert markdown_path.read_text(encoding="utf-8").startswith("# 深層静的トリアージ")

    args = triage.build_parser().parse_args(
        [
            "--inventory",
            "inventory.yaml",
            "--root",
            "samples",
            "--output-dir",
            "reports",
        ]
    )
    assert args.max_depth == triage.DEFAULT_MAX_DEPTH

    empty_inventory = tmp_path / "empty.yaml"
    empty_inventory.write_text("groups: []\ncases: []\n", encoding="utf-8")
    cli_output = tmp_path / "cli-output"
    assert (
        triage.main(
            [
                "--inventory",
                str(empty_inventory),
                "--root",
                str(tmp_path),
                "--output-dir",
                str(cli_output),
            ]
        )
        == 0
    )
    assert (cli_output / "deep-static-triage.json").is_file()


def test_public_sanitizer_preserves_urls_and_removes_secret_values(
    tmp_path: Path,
) -> None:
    """Keep HTTPS evidence while removing credentials, keys, and local paths."""

    url = "https://example.test/config.enc"
    secret_values = [
        "pw-value", "token-value", "secret-value", "cred-value",
        "rc4-value", "aes-value", "private-value", "api-value",
    ]
    report = {
        "summary": {},
        "cases": [],
        "evidence": {
            "url": url,
            "password": secret_values[0],
            "auth_token": secret_values[1],
            "client_secret": secret_values[2],
            "credentials": secret_values[3],
            "rc4_key": secret_values[4],
            "aes_key": secret_values[5],
            "private_key": secret_values[6],
            "api_key": secret_values[7],
            "public_key": "publishable-public-key",
            "token": "0x06000001",
            "local_note": r"C:\private\sample.bin",
        },
    }
    json_path, _ = triage.write_public_report(report, tmp_path)
    clean_text = json_path.read_text(encoding="utf-8")
    clean = json.loads(clean_text)
    assert clean["evidence"]["url"] == url
    assert clean["evidence"]["public_key"] == "publishable-public-key"
    assert clean["evidence"]["token"] == "0x06000001"
    assert clean["evidence"]["local_note"] == "[local-path-omitted]"
    assert not any(value in clean_text for value in secret_values)


def test_public_report_normalizes_stub_confounders_and_managed_routing(
    tmp_path: Path,
) -> None:
    """Require structural UPX evidence and expose native/managed routing states."""

    report = {
        "summary": {},
        "cases": [
            {
                "status": "analyzed",
                "case": {"sha256": "a" * 64, "family": "Fixture"},
                "expected_children": {"missing": []},
                "nodes": [
                    {
                        "sha256": "b" * 64,
                        "format": "pe",
                        "markers": ["UPX", "Themida"],
                        "unpack": {
                            "pe": {
                                "packer_markers": ["UPX!", "Themida"],
                                "classification": "not_packed",
                                "sections": [{"name": ".text"}],
                                "managed_il_triage": {
                                    "techniques": {
                                        "resource_obfuscation": {"status": "suspected"}
                                    }
                                },
                            }
                        },
                        "control_flow": {
                            "static_context": {"packer_markers": ["UPX!"]},
                            "techniques": {
                                "control_flow_flattening": {
                                    "status": "suspected",
                                    "evidence": [],
                                },
                                "indirect_branch_obfuscation": {
                                    "status": "suspected",
                                    "evidence": [],
                                },
                            }
                        },
                    }
                ],
            },
            {
                "status": "analyzed",
                "case": {"sha256": "c" * 64, "family": "Fixture"},
                "expected_children": {"missing": []},
                "nodes": [
                    {
                        "sha256": "d" * 64,
                        "format": "pe",
                        "markers": ["Enigma", "Themida"],
                        "unpack": {
                            "pe": {"classification": "packed_or_protected"}
                        },
                        "control_flow": {
                            "static_context": {},
                            "techniques": {
                                "control_flow_flattening": {
                                    "status": "suspected", "evidence": []
                                },
                                "indirect_branch_obfuscation": {
                                    "status": "suspected", "evidence": []
                                },
                            },
                        },
                    }
                ],
            }
        ],
    }
    json_path, markdown_path = triage.write_public_report(report, tmp_path)
    clean = json.loads(json_path.read_text(encoding="utf-8"))
    node = clean["cases"][0]["nodes"][0]
    assert node["markers"] == ["Themida"]
    assert node["unpack"]["pe"]["packer_markers"] == ["Themida"]
    assert node["control_flow"]["static_context"]["packer_markers"] == []
    assessment = node["control_flow"]["techniques"]["control_flow_flattening"]
    assert assessment["status"] == "suspected"
    assert node["control_flow"]["techniques"]["indirect_branch_obfuscation"]["status"] == "suspected"
    positive = clean["cases"][1]["nodes"][0]["control_flow"]["techniques"]
    assert positive["control_flow_flattening"]["status"] == "confounded"
    assert positive["indirect_branch_obfuscation"]["status"] == "confounded"
    markdown = markdown_path.read_text(encoding="utf-8")
    assert "control_flow_flattening:confounded" in markdown
    assert "resource_obfuscation" in markdown
    assert "control_flow_flattening:suspected" in markdown
