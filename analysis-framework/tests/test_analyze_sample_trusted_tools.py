"""analyze_sampleの外部静的tool pathとidentity安全境界を検証する。"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import analyze_sample as analyzer  # noqa: E402


def test_static_tool_identity_uses_name_size_and_sha256_only(tmp_path: Path) -> None:
    """契約identityへ絶対pathやtool内容を公開しない。"""

    tool = tmp_path / ("upx.exe" if os.name == "nt" else "upx")
    payload = b"pinned synthetic static tool"
    tool.write_bytes(payload)

    normalized = analyzer._normalize_tool_path(tool, "UPX")
    identity = analyzer._tool_identity(normalized)

    assert normalized == tool.resolve()
    assert identity == {
        "name": tool.name,
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }
    assert str(tool.parent) not in repr(identity)


def test_static_tool_path_rejects_hardlink(tmp_path: Path) -> None:
    """operator tool binaryが複数pathで変更可能なhardlinkを拒否する。"""

    tool = tmp_path / "upx.exe"
    alias = tmp_path / "upx-alias.exe"
    tool.write_bytes(b"fixture")
    try:
        os.link(tool, alias)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"このfilesystemではhardlinkを作成できません: {exc}")

    with pytest.raises(ValueError, match="単一link"):
        analyzer._normalize_tool_path(tool, "UPX")


def test_static_tool_path_rejects_reparse_or_symlink(tmp_path: Path) -> None:
    """tool pathのsymlink／reparse経由を拒否する。"""

    tool = tmp_path / "real-upx.exe"
    alias = tmp_path / "linked-upx.exe"
    tool.write_bytes(b"fixture")
    try:
        os.symlink(tool, alias)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"この環境ではsymlinkを作成できません: {exc}")

    with pytest.raises((OSError, RuntimeError, ValueError)):
        analyzer._normalize_tool_path(alias, "UPX")


def test_static_tool_path_rejects_oversized_binary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """tool binaryにも明示的なsize上限を適用する。"""

    tool = tmp_path / "upx.exe"
    tool.write_bytes(b"oversized")
    monkeypatch.setattr(analyzer, "MAX_STATIC_TOOL_BINARY_BYTES", 4)

    with pytest.raises(ValueError, match="通常file"):
        analyzer._normalize_tool_path(tool, "UPX")


def test_batch_summary_preserves_sealed_static_tool_identity(tmp_path: Path) -> None:
    """長時間jobのsummaryがtool名だけへ縮退せずroot契約と一致する。"""

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"static assessment fixture")
    tool = tmp_path / "sevenzip.exe"
    payload = b"synthetic pinned sevenzip"
    tool.write_bytes(payload)

    summary = analyzer.run_batch(
        [sample],
        tmp_path / "output",
        registry=analyzer.DEFAULT_REGISTRY,
        archive_mode="raw",
        assessment_only=True,
        sevenzip=tool,
    )

    expected = {
        "upx": None,
        "sevenzip": {
            "name": tool.name,
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        },
        "diec": None,
        "innounp": None,
    }
    assert summary["analysis_contract"]["settings"]["static_tools"] == expected
    assert summary["settings"]["static_tools"] == expected


def test_one_shot_innounp_is_sealed_and_forwarded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """明示innounpを契約へ封印し、共有unpackerへ同じ絶対pathで渡す。"""

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"one-shot forwarding fixture")
    tool = tmp_path / "innounp.exe"
    tool_payload = b"synthetic pinned innounp"
    tool.write_bytes(tool_payload)
    inno_password = "inner-password"

    summary = analyzer.run_batch(
        [sample],
        tmp_path / "assessment-output",
        registry=analyzer.DEFAULT_REGISTRY,
        archive_mode="raw",
        assessment_only=True,
        innounp=tool,
        inno_password=inno_password,
    )
    identity = summary["analysis_contract"]["settings"]["static_tools"]["innounp"]
    assert identity == {
        "name": tool.name,
        "size": len(tool_payload),
        "sha256": hashlib.sha256(tool_payload).hexdigest(),
    }
    settings = summary["analysis_contract"]["settings"]
    assert settings["archive_password_configured"] is True
    assert "archive_password_fingerprint" not in settings
    assert settings["inno_password_configured"] is True
    assert "inno_password_fingerprint" not in settings
    assert hashlib.sha256(inno_password.encode("utf-8")).hexdigest() not in repr(summary)
    assert inno_password not in repr(summary)

    calls: list[dict[str, object]] = []

    def fake_unpacker(_data: bytes, _name: str, **kwargs: object):
        calls.append(kwargs)
        return {"status": "fixture"}, []

    monkeypatch.setattr(analyzer, "unpack_bytes", fake_unpacker)
    unit = analyzer.InputUnit(
        source_name=sample.name,
        data=sample.read_bytes(),
        input_kind="raw",
        outer_sha256=hashlib.sha256(sample.read_bytes()).hexdigest(),
        outer_size=sample.stat().st_size,
    )
    analyzer.recover_static_layers(
        unit,
        innounp=tool.resolve(),
        archive_password="outer-password",
        inno_password=inno_password,
    )
    assert calls[0]["innounp"] == tool.resolve()
    assert calls[0]["archive_password"] == "outer-password"
    assert calls[0]["inno_password"] == inno_password


def test_archive_password_has_no_public_digest_and_disables_resume(
    tmp_path: Path,
) -> None:
    """外装credentialは公開派生値を残さず、同値でもcase再利用を行わない。"""

    sample = tmp_path / "archive-password-resume.bin"
    sample.write_bytes(b"credential-bound resume fixture")
    output = tmp_path / "archive-password-resume-output"
    password = "low-entropy-private-password"
    password_digest = hashlib.sha256(password.encode("utf-8")).hexdigest()

    first = analyzer.run_batch(
        [sample],
        output,
        registry=analyzer.DEFAULT_REGISTRY,
        password=password,
        archive_mode="raw",
        assessment_only=True,
    )
    settings = first["analysis_contract"]["settings"]
    assert settings["archive_password_configured"] is True
    assert "archive_password_fingerprint" not in settings
    assert password not in repr(first)
    assert password_digest not in repr(first)

    rerun = analyzer.run_batch(
        [sample],
        output,
        registry=analyzer.DEFAULT_REGISTRY,
        password=password,
        archive_mode="raw",
        assessment_only=True,
        resume=True,
    )
    assert rerun["counts"]["resumed"] == 0
    assert rerun["counts"]["analyzed"] == 1


def test_inno_password_has_no_public_digest_and_disables_direct_root_resume(
    tmp_path: Path,
) -> None:
    """Inno credential設定時も秘密比較を行わずroot caseを必ず再解析する。"""

    sample = tmp_path / "inno-password-resume.bin"
    sample.write_bytes(b"inno credential-bound resume fixture")
    output = tmp_path / "inno-password-resume-output"
    password = "low-entropy-inno-password"
    password_digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
    common = {
        "registry": analyzer.DEFAULT_REGISTRY,
        "password": "",
        "inno_password": password,
        "archive_mode": "raw",
        "assessment_only": True,
    }

    first = analyzer.run_batch([sample], output, **common)
    settings = first["analysis_contract"]["settings"]
    assert settings["inno_password_configured"] is True
    assert "inno_password_fingerprint" not in settings
    assert password not in repr(first)
    assert password_digest not in repr(first)

    rerun = analyzer.run_batch([sample], output, resume=True, **common)
    assert rerun["counts"]["resumed"] == 0
    assert rerun["counts"]["analyzed"] == 1


def test_empty_archive_password_keeps_verified_resume(
    tmp_path: Path,
) -> None:
    """credentialを使わない実行では既存の厳格resumeを維持する。"""

    sample = tmp_path / "uncredentialed-resume.bin"
    sample.write_bytes(b"uncredentialed resume fixture")
    output = tmp_path / "uncredentialed-resume-output"
    common = {
        "registry": analyzer.DEFAULT_REGISTRY,
        "password": "",
        "archive_mode": "raw",
        "assessment_only": True,
    }

    first = analyzer.run_batch([sample], output, **common)
    assert first["analysis_contract"]["settings"]["archive_password_configured"] is False
    rerun = analyzer.run_batch([sample], output, resume=True, **common)
    assert rerun["counts"]["resumed"] == 1
    assert rerun["counts"]["analyzed"] == 1


def test_one_shot_parser_accepts_innounp_without_enabling_it_by_default(
    tmp_path: Path,
) -> None:
    """CLIは明示pathを受け取り、未指定時は従来どおり無効にする。"""

    parser = analyzer.build_parser()
    defaults = parser.parse_args(
        ["--input", str(tmp_path / "sample.bin"), "--output", str(tmp_path / "out")]
    )
    explicit = parser.parse_args(
        [
            "--input",
            str(tmp_path / "sample.bin"),
            "--output",
            str(tmp_path / "out"),
            "--innounp",
            str(tmp_path / "innounp.exe"),
            "--inno-password-stdin",
        ]
    )
    assert defaults.innounp is None
    assert defaults.inno_password_stdin is False
    assert explicit.innounp == tmp_path / "innounp.exe"
    assert explicit.inno_password_stdin is True
    options = {
        option
        for action in parser._actions
        for option in action.option_strings
    }
    assert "--password" not in options
    assert "--inno-password" not in options
