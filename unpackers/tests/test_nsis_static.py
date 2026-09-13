from __future__ import annotations

import zlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from unpackers import static_unpacker as unpacker
from unpackers.nsis_static import (
    NsisMember,
    nsis_selection_public,
    parse_nsis_launch_graph,
    parse_nsis_listing,
    parse_sevenzip_version,
    select_nsis_members,
)


def _slt(
    source_size: int, records: list[dict[str, str]], archive_type: str = "Nsis"
) -> str:
    lines = [
        "7-Zip 26.02 (x64)",
        "",
        "Path = input.exe",
        f"Type = {archive_type}",
        f"Physical Size = {source_size}",
        "Method = Deflate",
        "SubType = NSIS-3 Unicode",
        "",
        "----------",
    ]
    for record in records:
        lines.extend(f"{key} = {value}" for key, value in record.items())
        lines.append("")
    return "\n".join(lines)


def test_parse_sevenzip_version_requires_recognized_modern_banner() -> None:
    assert parse_sevenzip_version("7-Zip 26.02 (x64)") == ("26.02", True)
    assert parse_sevenzip_version("7-Zip 23.01 (x64)") == ("23.01", False)
    assert parse_sevenzip_version("unknown tool") == (None, False)


def test_parse_nsis_listing_preserves_duplicates_and_drive_mapping() -> None:
    listing = parse_nsis_listing(
        _slt(
            100,
            [
                {"Path": "$PLUGINSDIR\\$R6", "Size": "3", "CRC": "352441C2"},
                {"Path": "$PLUGINSDIR\\$R6", "Size": "4"},
                {"Path": "C:\\Program Files\\App\\stage.ps1", "Size": ""},
            ],
        ),
        0,
        100,
    )
    assert listing.status == "listed"
    assert listing.complete is True
    assert [member.output_name for member in listing.members] == [
        "$PLUGINSDIR/$R6",
        "$PLUGINSDIR/$R6_1",
        "C_/Program Files/App/stage.ps1",
    ]
    assert listing.unknown_size_count == 1
    assert listing.crc_unavailable_count == 2


@pytest.mark.parametrize(
    ("archive_type", "source_size", "path", "encrypted", "status"),
    [
        ("PE", 100, "stage.exe", "-", "not_nsis_archive"),
        ("Nsis", 99, "stage.exe", "-", "physical_size_mismatch"),
        ("Nsis", 100, "../stage.exe", "-", "unsafe_or_truncated_inventory"),
        ("Nsis", 100, "stage?.exe", "-", "unsafe_or_truncated_inventory"),
        ("Nsis", 100, "stage.exe", "+", "encrypted_archive"),
    ],
)
def test_parse_nsis_listing_fails_closed(
    archive_type: str,
    source_size: int,
    path: str,
    encrypted: str,
    status: str,
) -> None:
    listing = parse_nsis_listing(
        _slt(
            source_size,
            [{"Path": path, "Size": "4", "Encrypted": encrypted}],
            archive_type,
        ),
        0,
        100,
    )
    assert listing.status == status
    assert listing.complete is False


def test_nsis_selection_keeps_duplicate_archive_name_as_one_group() -> None:
    listing = parse_nsis_listing(
        _slt(
            100,
            [
                {"Path": "[NSIS].nsi", "Size": "20"},
                {"Path": "$PLUGINSDIR\\$R6", "Size": "30"},
                {"Path": "$PLUGINSDIR\\$R6", "Size": "40"},
                {"Path": "documentation.txt", "Size": "10"},
            ],
        ),
        0,
        100,
    )
    selection = select_nsis_members(
        listing,
        max_members=3,
        max_member_size=100,
        max_total_size=100,
    )
    assert [member.output_name for member in selection.members] == [
        "[NSIS].nsi",
        "$PLUGINSDIR/$R6",
        "$PLUGINSDIR/$R6_1",
    ]
    assert selection.complete_archive is False
    assert nsis_selection_public(selection)["enabled"] is True


def test_parse_nsis_launch_graph_records_placement_and_launch_order() -> None:
    graph = parse_nsis_launch_graph(
        b"""; NSIS script NSIS-3 Unicode
SetOutPath $INSTDIR
File helper.exe
StrCpy $R0 $INSTDIR\\helper.exe
Exec \"$R0 --quiet\"
nsExec::ExecToStack \"powershell -File $TEMP\\stage.ps1\"
"""
    )
    assert graph["status"] == "parsed"
    assert graph["placement_count"] == 1
    assert graph["launch_count"] == 2
    assert graph["dynamic_launch_count"] == 2
    assert [action["kind"] for action in graph["actions"]] == [
        "directory",
        "placement",
        "launch",
        "launch",
    ]


def _mock_nsis_tool(
    monkeypatch: pytest.MonkeyPatch,
    *,
    source: bytes,
    script: bytes,
    payload: bytes,
    payload_packed_size: int | None = None,
    test_returncode: int = 0,
    unexpected_output: bool = False,
) -> None:
    records = []
    for name, blob in (("[NSIS].nsi", script), ("payload.exe", payload)):
        packed_size = (
            payload_packed_size
            if name == "payload.exe" and payload_packed_size is not None
            else max(1, len(blob))
        )
        records.append(
            {
                "Path": name,
                "Size": str(len(blob)),
                "Packed Size": str(packed_size),
                "CRC": f"{zlib.crc32(blob) & 0xFFFFFFFF:08X}",
                "Encrypted": "-",
            }
        )
    listing = _slt(len(source), records)

    monkeypatch.setattr(
        unpacker,
        "_static_tool_identity",
        lambda _path: {"sha256": "a" * 64, "size": 1234},
    )

    def fake_run(command: list[str], **_kwargs):
        operation = command[1]
        if operation == "i":
            return SimpleNamespace(
                returncode=0, stdout="7-Zip 26.02 (x64)\n", stderr=""
            )
        if operation == "l":
            return SimpleNamespace(returncode=0, stdout=listing, stderr="")
        if operation == "t":
            return SimpleNamespace(
                returncode=test_returncode,
                stdout=f"Files: 2\nSize: {len(script) + len(payload)}\n",
                stderr="",
            )
        assert operation == "x"
        output = Path(next(value[2:] for value in command if value.startswith("-o")))
        output.mkdir(parents=True)
        (output / "[NSIS].nsi").write_bytes(script)
        (output / "payload.exe").write_bytes(payload)
        if unexpected_output:
            (output / "unexpected.bin").write_bytes(b"x")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(unpacker, "_run_static_tool_process", fake_run)


def test_nsis_static_extract_seals_tool_source_inventory_crc_and_graph(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = b"MZ-static-nsis-fixture"
    script = (
        b"; NSIS script NSIS-3\nSetOutPath $INSTDIR\n"
        b"File payload.exe\nExec $INSTDIR\\payload.exe\n"
    )
    payload = b"MZpayload"
    _mock_nsis_tool(
        monkeypatch,
        source=source,
        script=script,
        payload=payload,
    )
    report, artifacts = unpacker.nsis_static_extract(
        source,
        tmp_path / "7z.exe",
        max_members=8,
        max_member_size=1024,
        max_total_size=4096,
    )
    assert report["status"] == "extracted"
    assert report["archive_test_complete"] is True
    assert report["extraction_complete"] is True
    assert report["full_archive_extraction_complete"] is True
    assert report["tool"]["version"] == "26.02"
    assert report["tool"]["identity_unchanged"] is True
    assert report["crc_validation"] == {
        "available_count": 2,
        "verified_count": 2,
        "unavailable_count": 0,
        "complete": True,
    }
    assert report["launch_graph"]["launch_count"] == 1
    assert [kind for kind, _ in artifacts] == [
        "nsis-install-script.nsi",
        "nsis-member-001-pe.exe",
    ]


def test_nsis_static_extract_rejects_failed_archive_test(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, script, payload = b"MZfixture", b"; NSIS script NSIS-3\n", b"MZpayload"
    _mock_nsis_tool(
        monkeypatch,
        source=source,
        script=script,
        payload=payload,
        test_returncode=2,
    )
    report, artifacts = unpacker.nsis_static_extract(source, tmp_path / "7z.exe")
    assert report["status"] == "archive_test_failed"
    assert report["extraction_complete"] is False
    assert artifacts == []


def test_nsis_static_extract_rejects_tool_identity_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, script, payload = b"MZfixture", b"; NSIS script NSIS-3\n", b"MZpayload"
    _mock_nsis_tool(
        monkeypatch,
        source=source,
        script=script,
        payload=payload,
    )
    identities = iter(
        (
            {"sha256": "a" * 64, "size": 1234},
            {"sha256": "b" * 64, "size": 1234},
        )
    )
    monkeypatch.setattr(unpacker, "_static_tool_identity", lambda _path: next(identities))

    report, artifacts = unpacker.nsis_static_extract(source, tmp_path / "7z.exe")

    assert report["status"] == "tool_integrity_failed"
    assert report["tool"]["identity_unchanged"] is False
    assert artifacts == []


def test_nsis_static_extract_omits_only_ratio_blocked_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = b"MZfixture"
    script = b"; NSIS script NSIS-3\nFile payload.exe\n"
    payload = b"MZ" + b"P" * 200
    _mock_nsis_tool(
        monkeypatch,
        source=source,
        script=script,
        payload=payload,
        payload_packed_size=1,
    )

    report, artifacts = unpacker.nsis_static_extract(
        source,
        tmp_path / "7z.exe",
        max_compression_ratio=100,
    )

    assert report["status"] == "selectively_extracted"
    assert report["extraction_complete"] is False
    assert report["full_archive_extraction_complete"] is False
    assert report["ratio_validation"]["blocked_member_count"] == 1
    assert report["retained_members"] == 1
    assert report["route_only_reasons"][0] == "nsis_ratio_blocked_members_omitted"
    assert [kind for kind, _ in artifacts] == ["nsis-install-script.nsi"]


def test_nsis_static_extract_rejects_unexpected_tool_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, script, payload = b"MZfixture", b"; NSIS script NSIS-3\n", b"MZpayload"
    _mock_nsis_tool(
        monkeypatch,
        source=source,
        script=script,
        payload=payload,
        unexpected_output=True,
    )
    report, artifacts = unpacker.nsis_static_extract(source, tmp_path / "7z.exe")
    assert report["status"] == "unsafe_tool_output"
    assert report["extraction_complete"] is False
    assert artifacts == []


@pytest.mark.parametrize("reparse", [False, True])
def test_collect_nsis_outputs_rejects_hardlink_or_reparse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reparse: bool
) -> None:
    output = tmp_path / "output"
    output.mkdir()
    payload = output / "payload.exe"
    payload.write_bytes(b"MZpayload")
    member = NsisMember(
        archive_name="payload.exe",
        normalized_name="payload.exe",
        output_name="payload.exe",
        size=len(b"MZpayload"),
        packed_size=len(b"MZpayload"),
        crc32=None,
        encrypted=False,
        attributes="A",
    )
    if reparse:
        monkeypatch.setattr(unpacker, "_has_reparse_attribute", lambda _info: True)
        expected_reason = "output_reparse_forbidden"
    else:
        monkeypatch.setattr(unpacker, "_has_single_link", lambda *_args: False)
        expected_reason = "output_file_invalid"

    with pytest.raises(unpacker.StaticToolExecutionError, match=expected_reason):
        unpacker._collect_nsis_outputs(
            output,
            (member,),
            maximum_member_size=1024,
            maximum_total_size=2048,
        )
