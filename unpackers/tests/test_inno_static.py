"""Inno Setup静的inventory・選択・外部parser境界の試験。"""

from __future__ import annotations

import io
import struct
import zipfile
import zlib
from pathlib import Path

import pytest

from unpackers import static_unpacker
from unpackers.inno_static import (
    MAX_INNO_RESOURCE_TABLE_ENTRIES,
    MAX_INNO_SIGNAL_VALUES,
    InnoListing,
    InnoMember,
    assess_inno_candidate,
    inno_candidate_public,
    parse_innounp_listing,
    parse_install_script,
    recover_segmented_zip,
    select_inno_members,
)


def listing_text(rows: tuple[tuple[str, bytes], ...]) -> str:
    """locale固定optionで得られる最小のinnounp一覧を構築する。"""

    rendered = [
        "*innounp* - the Inno Setup Unpacker, version 2.71.1 (2026-08-29)",
        "",
        "Inno Setup archive:           input.exe",
        "Inno Setup version detected:  6.7.0 (Unicode)",
        "",
        "Size        Date/Time            Filename",
        "-------------------------------------------------",
    ]
    rendered.extend(
        f"{len(blob):10d}  2026-09-11 00:00     {name}" for name, blob in rows
    )
    rendered.append("-------------------------------------------------")
    return "\n".join(rendered)


def synthetic_inno_pe() -> bytes:
    """revision 2 loader tableをRCDATA/11111に持つ最小PEを作る。"""

    data = bytearray(0x1000)
    pe_offset = 0x80
    optional_offset = pe_offset + 24
    optional_size = 0xE0
    section_offset = optional_offset + optional_size
    resource_offset = 0x200
    loader_offset = 0x300
    data_offset = 0x900
    information_offset = 0xA00
    executable_offset = 0xB00

    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset : pe_offset + 4] = b"PE\0\0"
    struct.pack_into("<H", data, pe_offset + 4, 0x14C)
    struct.pack_into("<H", data, pe_offset + 6, 1)
    struct.pack_into("<H", data, pe_offset + 20, optional_size)
    struct.pack_into("<H", data, optional_offset, 0x10B)
    struct.pack_into("<I", data, optional_offset + 92, 16)
    struct.pack_into("<II", data, optional_offset + 112, 0x1000, 0x200)
    data[section_offset : section_offset + 8] = b".rsrc\0\0\0"
    struct.pack_into("<IIII", data, section_offset + 8, 0xE00, 0x1000, 0xE00, 0x200)

    struct.pack_into("<HH", data, resource_offset + 12, 0, 1)
    struct.pack_into("<II", data, resource_offset + 16, 10, 0x80000020)
    struct.pack_into("<HH", data, resource_offset + 0x20 + 12, 0, 1)
    struct.pack_into("<II", data, resource_offset + 0x20 + 16, 11111, 0x80000040)
    struct.pack_into("<HH", data, resource_offset + 0x40 + 12, 0, 1)
    struct.pack_into("<II", data, resource_offset + 0x40 + 16, 1033, 0x60)
    struct.pack_into(
        "<IIII",
        data,
        resource_offset + 0x60,
        0x1100,
        64,
        0,
        0,
    )

    loader_without_crc = struct.pack(
        "<12sIQQIIQQI",
        b"rDlPtS\xcd\xe6\xd7{\x0b*",
        2,
        len(data),
        executable_offset,
        0x2000,
        0,
        information_offset,
        data_offset,
        0,
    )
    data[loader_offset : loader_offset + 60] = loader_without_crc
    struct.pack_into(
        "<I", data, loader_offset + 60, zlib.crc32(loader_without_crc) & 0xFFFFFFFF
    )
    data[data_offset : data_offset + 4] = b"zlb\x1a"
    data[information_offset : information_offset + 30] = (
        b"Inno Setup Setup Data (6.7.0)\0"
    )
    return bytes(data)


def synthetic_legacy_inno_pe() -> bytes:
    """resourceを使わない4.1.6系の固定pointer構造を作る。"""

    data = bytearray(synthetic_inno_pe())
    struct.pack_into("<II", data, 0x108, 0, 0)
    data[0x30:0x34] = b"Inno"
    struct.pack_into("<II", data, 0x34, 0x300, ~0x300 & 0xFFFFFFFF)
    data[0x300:0x340] = b"\0" * 64
    loader_without_crc = struct.pack(
        "<12sIIIIII",
        b"rDlPtS07\x87eVx",
        len(data),
        0xB00,
        0x2000,
        0,
        0xA00,
        0x900,
    )
    data[0x300 : 0x300 + len(loader_without_crc)] = loader_without_crc
    struct.pack_into(
        "<I",
        data,
        0x300 + len(loader_without_crc),
        zlib.crc32(loader_without_crc) & 0xFFFFFFFF,
    )
    return bytes(data)


def test_candidate_requires_signal_and_validated_loader_structure() -> None:
    """7-ZipのInno識別をresource・CRC・offsetで再検証する。"""

    data = synthetic_inno_pe()
    assessment = assess_inno_candidate(
        data,
        archive_types=["PE", "Inno Setup"],
    )
    assert assessment.status == "candidate"
    assert assessment.candidate is True
    assert assessment.source_signals == ("sevenzip_inno_archive_type",)
    assert assessment.pe_structure_valid is True
    assert assessment.loader_location == "pe_rcdata_11111"
    assert assessment.loader_revision == 2
    assert assessment.loader_crc_verified is True
    assert assessment.setup_header_boundary_verified is True

    public = inno_candidate_public(assessment)
    assert public["candidate"] is True
    assert public["terminal_promotion_eligible"] is False
    assert public["sample_executed"] is False
    assert public["network_contacted"] is False
    assert not any("offset" in key for key in public)

    unprompted = assess_inno_candidate(data)
    assert unprompted.status == "not_signaled"
    assert unprompted.candidate is False


def test_candidate_validates_legacy_fixed_pointer_without_resource() -> None:
    """旧形式は0x30 pointer complementとtable CRCの双方を要求する。"""

    assessment = assess_inno_candidate(
        synthetic_legacy_inno_pe(),
        packer_markers=["Inno Setup"],
    )
    assert assessment.candidate is True
    assert assessment.loader_location == "legacy_fixed_pointer"
    assert assessment.loader_revision == 0
    assert assessment.loader_crc_verified is True


def test_candidate_rejects_fake_marker_and_corrupt_structure() -> None:
    """表示文字列単独、CRC破損、再CRC後の範囲外offsetを全て拒否する。"""

    fake_marker = bytearray(synthetic_inno_pe())
    fake_marker[0x300:0x340] = b"Inno Setup".ljust(64, b"\0")
    marker_assessment = assess_inno_candidate(
        bytes(fake_marker), packer_markers=["Inno Setup"]
    )
    assert marker_assessment.status == "signal_without_validated_structure"
    assert marker_assessment.candidate is False

    corrupt_crc = bytearray(synthetic_inno_pe())
    corrupt_crc[0x33C] ^= 0x01
    crc_assessment = assess_inno_candidate(bytes(corrupt_crc), archive_types=["Inno"])
    assert crc_assessment.candidate is False
    assert crc_assessment.reason == "loader_table_or_offsets_invalid"

    invalid_offset = bytearray(synthetic_inno_pe())
    struct.pack_into("<Q", invalid_offset, 0x328, len(invalid_offset) + 1)
    struct.pack_into(
        "<I",
        invalid_offset,
        0x33C,
        zlib.crc32(invalid_offset[0x300:0x33C]) & 0xFFFFFFFF,
    )
    offset_assessment = assess_inno_candidate(
        bytes(invalid_offset), archive_types=["Inno"]
    )
    assert offset_assessment.candidate is False
    assert offset_assessment.reason == "loader_table_or_offsets_invalid"


def test_candidate_limits_fail_closed_at_n_plus_one() -> None:
    """signal件数、入力size、resource entry件数はN+1で閉じる。"""

    data = synthetic_inno_pe()
    too_many_signals = assess_inno_candidate(
        data,
        archive_types=["Inno"] * (MAX_INNO_SIGNAL_VALUES + 1),
    )
    assert too_many_signals.status == "signal_limit_or_shape_blocked"
    assert too_many_signals.reason == "signal_count_limit"

    oversized = assess_inno_candidate(
        data,
        archive_types=["Inno"],
        max_input_size=len(data) - 1,
    )
    assert oversized.status == "input_size_blocked"
    assert oversized.candidate is False

    too_many_resources = bytearray(data)
    struct.pack_into(
        "<HH",
        too_many_resources,
        0x200 + 12,
        0,
        MAX_INNO_RESOURCE_TABLE_ENTRIES + 1,
    )
    resource_assessment = assess_inno_candidate(
        bytes(too_many_resources), archive_types=["Inno"]
    )
    assert resource_assessment.candidate is False
    assert resource_assessment.reason == "resource_entry_count_limit"


def test_listing_rejects_traversal_without_partial_trust() -> None:
    """1件でも曖昧なpathがあればinventory全体を不完全として閉じる。"""

    parsed = parse_innounp_listing(
        listing_text(((r"{app}\good.exe", b"MZgood"), (r"{app}\..\bad", b"bad"))),
        0,
    )
    assert parsed.status == "unsafe_or_truncated_inventory"
    assert parsed.complete is False
    assert parsed.invalid_member_count == 1


@pytest.mark.parametrize("archive_name", ("-psecret", "@response.txt"))
def test_listing_rejects_option_and_response_file_member_names(
    archive_name: str,
) -> None:
    """innounpのmask引数になり得るprefixをinventory段階で拒否する。"""

    parsed = parse_innounp_listing(listing_text(((archive_name, b"MZ"),)), 0)

    assert parsed.status == "unsafe_or_truncated_inventory"
    assert parsed.complete is False
    assert parsed.invalid_member_count == 1


@pytest.mark.parametrize(
    "mutate",
    (
        lambda text: text.replace(
            "-------------------------------------------------\n",
            "-------------------------------------------------\nrecognition failed for this row\n",
            1,
        ),
        lambda text: text.rsplit("\n", 1)[0],
        lambda text: text.replace("Size        Date/Time            Filename\n", ""),
    ),
)
def test_listing_requires_recognized_rows_and_complete_table_framing(mutate) -> None:
    """未認識row、footer欠落、header欠落を完全inventoryへ昇格しない。"""

    parsed = parse_innounp_listing(
        mutate(listing_text(((r"{app}\good.exe", b"MZgood"),))),
        0,
    )

    assert parsed.status == "unsafe_or_truncated_inventory"
    assert parsed.complete is False


def test_listing_accepts_supported_complete_table_contract() -> None:
    """既存のinnounp table形式はheader・両separator確認後に受理する。"""

    parsed = parse_innounp_listing(
        listing_text(((r"{app}\good.exe", b"MZgood"),)),
        0,
    )

    assert parsed.status == "listed"
    assert parsed.complete is True
    assert [member.normalized_name for member in parsed.members] == ["{app}/good.exe"]


def test_install_script_extracts_encryption_and_launch_graph() -> None:
    """Run/UninstallRunだけを静的launch edgeとして採用する。"""

    facts = parse_install_script(
        b"""; Created by "innounp" version 2.71.1
; Inno Setup Version: 6.7.0 (Unicode)
[Setup]
; Encryption=yes
[Files]
Filename: "{app}\\not-a-run.exe";
[Run]
Filename: "{app}\\host.exe"; Parameters: "-x"
Filename: "{code:ResolveTarget}";
[UninstallRun]
Filename: "{app}\\cleanup.exe";
"""
    )
    assert facts.encrypted is True
    assert facts.decompiler_provenance is True
    assert facts.launch_targets == ("{app}/host.exe", "{app}/cleanup.exe")
    assert facts.dynamic_launch_target_count == 1


def test_selection_prefers_launch_siblings_and_omits_dependency_noise() -> None:
    """filename固定値を使わず、launch graphと構造でmemberを選ぶ。"""

    members = tuple(
        InnoMember(name, name.replace("\\", "/"), size)
        for name, size in (
            (r"{app}\host.exe", 10),
            (r"{app}\side.dll", 20),
            (r"{app}\config.dat", 30),
            (r"{app}\node_modules\library.js", 40),
            (r"{app}\image.png", 50),
            ("install_script.iss", 60),
        )
    )
    listing = InnoListing("listed", "2.71.1", "6.7.0", members, 0, 0, True)
    facts = parse_install_script(
        b'; Created by "innounp" version 2.71.1\n'
        b"; Inno Setup Version: 6.7.0\n"
        b'[Run]\nFilename: "{app}\\host.exe";\n'
    )
    selection = select_inno_members(
        listing,
        facts,
        max_members=4,
        max_member_size=1024,
        max_total_size=4096,
    )
    names = {item.normalized_name for item in selection.members}
    assert "{app}/host.exe" in names
    assert "{app}/side.dll" in names
    assert "{app}/config.dat" in names
    assert "install_script.iss" in names
    assert "{app}/node_modules/library.js" not in names
    assert "{app}/image.png" not in names
    assert selection.complete_archive is False
    assert selection.limit_reasons == ("low_value_members_omitted",)


def test_selection_keeps_sideload_dll_before_other_sibling_executable() -> None:
    """容量競合時は起動hostと同居DLLを別の同居EXEより先に保持する。"""

    members = tuple(
        InnoMember(name, name.replace("\\", "/"), size)
        for name, size in (
            (r"{app}\host.exe", 10),
            (r"{app}\side.dll", 70),
            (r"{app}\another.exe", 70),
            ("install_script.iss", 10),
        )
    )
    listing = InnoListing("listed", "2.71.1", "6.7.0", members, 0, 0, True)
    facts = parse_install_script(
        b'; Created by "innounp" version 2.71.1\n'
        b"; Inno Setup Version: 6.7.0\n"
        b'[Run]\nFilename: "{app}\\host.exe";\n'
    )
    selection = select_inno_members(
        listing,
        facts,
        max_members=8,
        max_member_size=100,
        max_total_size=100,
    )
    names = {item.normalized_name for item in selection.members}
    assert names == {"{app}/host.exe", "{app}/side.dll", "install_script.iss"}
    assert selection.limit_reasons == ("total_size_limit",)


@pytest.mark.parametrize(
    (
        "encrypted",
        "archive_password",
        "expected_status",
        "expected_calls",
        "expected_unlock_attempted",
    ),
    (
        (False, "outer-password", "artifacts_recovered", 3, False),
        (True, "", "encrypted_payload_blocked", 2, False),
        (True, "payload-password", "encrypted_payload_blocked", 2, False),
        (True, "wrong-password", "encrypted_payload_blocked", 2, False),
    ),
)
def test_inno_static_extract_is_fail_closed_and_snapshot_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    encrypted: bool,
    archive_password: str,
    expected_status: str,
    expected_calls: int,
    expected_unlock_attempted: bool,
) -> None:
    """一覧・script・選択抽出の順を守り、暗号化時はpayloadを読まない。"""

    script = (
        b'; Created by "innounp" version 2.71.1\n'
        b"; Inno Setup Version: 6.7.0 (Unicode)\n"
        b'[Setup]\n; Encryption=yes\n[Run]\nFilename: "{app}\\host.exe";\n'
        if encrypted
        else b'; Created by "innounp" version 2.71.1\n'
        b"; Inno Setup Version: 6.7.0 (Unicode)\n"
        b'[Setup]\n[Run]\nFilename: "{app}\\host.exe";\n'
    )
    rows = (
        (r"{app}\host.exe", b"MZhost"),
        (r"{app}\side.dll", b"MZside"),
        (r"{app}\splash.png", b"PNG"),
        ("install_script.iss", script),
    )
    payload_by_name = {name: blob for name, blob in rows}
    calls: list[list[str]] = []

    def fake_identity(_path: Path) -> dict[str, object]:
        return {"sha256": "a" * 64, "size": 1234}

    def fake_run(
        command: list[str],
        **_kwargs: object,
    ) -> static_unpacker.StaticToolCompleted:
        calls.append(command)
        if "-v" in command:
            return static_unpacker.StaticToolCompleted(0, listing_text(rows), "")
        output_argument = next(value for value in command if value.startswith("-d"))
        output = Path(output_argument[2:])
        output.mkdir(parents=True)
        source_index = next(
            index
            for index, value in enumerate(command)
            if Path(value).name.startswith("input") and Path(value).suffix == ".exe"
        )
        for member_name in command[source_index + 1 :]:
            path = output.joinpath(*member_name.replace("\\", "/").split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload_by_name[member_name])
        return static_unpacker.StaticToolCompleted(0, "", "")

    monkeypatch.setattr(static_unpacker, "_static_tool_identity", fake_identity)
    monkeypatch.setattr(static_unpacker, "_run_static_tool_process", fake_run)
    report, artifacts = static_unpacker.inno_static_extract(
        b"MZfixture Inno Setup",
        tmp_path / "innounp.exe",
        "fixture.exe",
        archive_password,
        max_members=16,
        max_member_size=1024,
        max_total_size=4096,
    )
    assert report["status"] == expected_status
    assert report["inventory_complete"] is True
    assert report["tool"]["identity_unchanged"] is True
    assert report["archive_unlock_attempted"] is expected_unlock_attempted
    assert len(calls) == expected_calls
    if archive_password:
        assert archive_password not in repr(report)
        assert all(archive_password not in value for command in calls for value in command)
    if expected_status == "encrypted_payload_blocked":
        assert report["extraction_complete"] is False
        assert [kind for kind, _ in artifacts] == ["inno-install-script.iss"]
        assert "inno_encrypted_archive_unlock_not_supported" in report["route_only_reasons"]
    else:
        assert report["extraction_complete"] is True
        assert len(artifacts) == 4


def test_cli_accepts_explicit_innounp_path_and_safe_stdin_flag(tmp_path: Path) -> None:
    """外部toolは明示指定時だけ有効になる。"""

    parser = static_unpacker.build_parser()
    args = parser.parse_args(
        [
            "--input",
            str(tmp_path / "input.exe"),
            "--output",
            str(tmp_path / "report.json"),
            "--innounp",
            str(tmp_path / "innounp.exe"),
            "--inno-password-stdin",
        ]
    )
    assert args.innounp == tmp_path / "innounp.exe"
    assert args.inno_password_stdin is True
    options = {
        option
        for action in parser._actions
        for option in action.option_strings
    }
    assert "--archive-password" not in options
    assert "--inno-password" not in options


def test_segmented_zip_reassembly_requires_complete_contiguous_crc_valid_zip() -> None:
    """名前やhashではなくlisting順とZIP内部整合性だけで分割を結合する。"""

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("payload.bin", bytes(range(256)) * 8)
        archive.writestr("loader.exe", b"MZ" + bytes(range(256)) * 16)
    complete = output.getvalue()
    split = len(complete) // 2
    payloads = (
        (InnoMember("first.part", "{app}/first.part", split), complete[:split]),
        (
            InnoMember(
                "second.part",
                "{app}/second.part",
                len(complete) - split,
            ),
            complete[split:],
        ),
    )
    recovered = recover_segmented_zip(
        payloads,
        max_members=8,
        max_member_size=8192,
        max_total_size=16384,
    )
    assert recovered.status == "recovered"
    assert recovered.blob == complete
    assert recovered.archive_member_count == 2
    assert recovered.crc_verified is True

    corrupted = bytearray(payloads[0][1])
    corrupted[-1] ^= 0xFF
    rejected = recover_segmented_zip(
        ((payloads[0][0], bytes(corrupted)), payloads[1]),
        max_members=8,
        max_member_size=8192,
        max_total_size=16384,
    )
    assert rejected.status == "not_found"
    assert rejected.blob is None
