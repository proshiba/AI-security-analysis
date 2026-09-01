"""RedC2 npm package静的解析器の安全境界とloader判定を検証する。"""

from __future__ import annotations

import gzip
import importlib.util
import json
import struct
import sys
import tarfile
import zipfile
from io import BytesIO
from pathlib import Path

import pytest

FRAMEWORK = Path(__file__).parents[1]
COMMON = FRAMEWORK / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from analysis_contract import handler_result_quality  # noqa: E402
from handler_catalog import (  # noqa: E402
    HandlerNoEvidenceError,
    discover_handlers,
    execute_handler,
    load_handler,
    preflight_handler_for_assessment,
)


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ANALYZER = load_module(FRAMEWORK / "malware" / "redc2" / "analyze_package_set.py", "redc2_analyzer")
DETECTOR = load_module(FRAMEWORK / "malware" / "redc2" / "detect.py", "redc2_detector")


def make_elf(*, redc2: bool = False, extra: bytes = b"") -> bytes:
    evidence = b""
    if redc2:
        evidence = b"\0".join(
            (
                *ANALYZER.PROTOCOL_MARKERS,
                *ANALYZER.TLS_API_MARKERS,
                b"Other input runs as shell.",
                b"SOCKS5 proxy started",
            )
        )
    body = evidence + extra
    total_size = 64 + 56 + len(body)
    ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident,
        3,
        62,
        1,
        0x400078,
        64,
        0,
        0,
        64,
        56,
        1,
        0,
        0,
        0,
    )
    program_header = struct.pack(
        "<IIQQQQQQ",
        1,
        5,
        0,
        0x400000,
        0x400000,
        total_size,
        total_size,
        0x1000,
    )
    return header + program_header + body


def make_tar(
    *,
    chmod: bool = True,
    mode: int = 0o644,
    unsafe_name: str | None = None,
    payload: bytes | None = None,
    package_name: str = "fixture",
    package_scripts: dict[str, str] | None = None,
    package_exports: object | None = None,
    loader_extra: bytes = b"",
) -> bytes:
    payload = payload if payload is not None else make_elf()
    expected = ANALYZER.sha256_bytes(payload)
    loader = (
        "import cp from 'node:child_process'; import fs from 'node:fs';\n(async () => {\n"
        + f"const expectedHash = '{expected}';\n"
        + ("fs.chmodSync(binaryPath, 0o755);\n" if chmod else "")
        + "cp.spawn(binaryPath, [], {detached: true, shell: false, stdio: 'pipe'});\n})();"
    ).encode() + loader_extra
    metadata = {"name": package_name, "version": "1.0.0", "type": "module"}
    if package_scripts is not None:
        metadata["scripts"] = package_scripts
    if package_exports is not None:
        metadata["exports"] = package_exports
    files = {
        "package/package.json": json.dumps(metadata).encode(),
        "package/dist/index.mjs": loader,
        unsafe_name or "package/dist/internal/calc.bin": payload,
    }
    stream = BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = mode if content is payload else 0o644
            archive.addfile(info, BytesIO(content))
    return stream.getvalue()


def test_loader_viability_accounts_for_chmod_and_mode() -> None:
    assert ANALYZER.analyze_package("a.tgz", make_tar(chmod=True))["loader"]["normal_install_execution_viable"] is True
    assert (
        ANALYZER.analyze_package("b.tgz", make_tar(chmod=False))["loader"]["normal_install_execution_viable"] is False
    )
    assert (
        ANALYZER.analyze_package("c.tgz", make_tar(chmod=False, mode=0o755))["loader"][
            "normal_install_execution_viable"
        ]
        is True
    )


def test_tar_path_traversal_is_rejected() -> None:
    with pytest.raises(ANALYZER.ArchiveValidationError, match="unsafe archive member path"):
        ANALYZER.analyze_package("unsafe.tgz", make_tar(unsafe_name="../calc.bin"))


def test_tar_header_checksum_corruption_is_rejected() -> None:
    """gzip自体が正常でも、tar header改変をmemberとして解析しない。"""

    raw = bytearray(gzip.decompress(make_tar()))
    raw[0] ^= 1
    corrupted = gzip.compress(bytes(raw), mtime=0)
    with pytest.raises(ANALYZER.ArchiveValidationError, match="checksum"):
        ANALYZER.analyze_package("corrupted.tgz", corrupted)


def test_detector_requires_header_protocol_api_and_capability_correlations() -> None:
    assert DETECTOR.detect(make_elf(redc2=True), Path("fixture"))["matched"] is True
    stuffed = make_elf(extra=b"\0".join(ANALYZER.PROTOCOL_MARKERS))
    detection = DETECTOR.detect(stuffed, Path("stuffed"))
    assert detection["matched"] is False
    assert detection["observations"]["valid_elf_header"] is True
    assert detection["observations"]["tls_api_cluster_complete"] is False
    assert DETECTOR.detect(b"\x7fELFREDSHELL", Path("weak"))["matched"] is False


def _handler_spec():
    values = [
        item
        for item in discover_handlers()
        if item.family == "redc2" and item.relative_path == "analysis-framework/malware/redc2/extract_config.py"
    ]
    assert len(values) == 1
    return values[0]


def test_automatic_handler_contract_and_format_preflight() -> None:
    """RedC2 facadeは復元済み2形式だけを許可し、副作用をpreflightで拒否しない。"""

    spec = _handler_spec()
    assert spec.automatic is True
    assert spec.input_formats == ("data", "elf")
    assert spec.input_contract_source == "module_declaration"
    assert spec.minimum_evidence_score == 20_000
    for actual_format in spec.input_formats:
        preflight = preflight_handler_for_assessment(
            spec,
            actual_format=actual_format,
            input_size=4096,
        )
        assert preflight["eligible"] is True
        assert preflight["blockers"] == []
        assert preflight["sample_execution_allowed"] is False
        assert preflight["network_allowed"] is False
        assert preflight["filesystem_write_allowed"] is False
    incompatible = preflight_handler_for_assessment(
        spec,
        actual_format="pe",
        input_size=4096,
    )
    assert incompatible["eligible"] is False
    assert "incompatible_input_format:pe" in incompatible["blockers"]


def test_handler_analyzes_tarball_and_package_set_without_execution() -> None:
    """合成RedC2 packageをone-shotとpackage-set CLIの両入口で静的解析する。"""

    handler, invocation = load_handler(_handler_spec())
    assert invocation == "bytes"
    package = make_tar(payload=make_elf(redc2=True))
    direct = handler(package)
    assert direct["matched"] is True
    assert direct["family"] == "redc2"
    assert direct["source"]["kind"] == "npm_tarball"
    assert direct["package_count"] == 1
    for marker in ANALYZER.PROTOCOL_MARKERS:
        assert f"protocol_marker:{marker.decode('ascii')}" in direct["matched_patterns"]
    assert "static_correlation:openssl_tls_io_api_cluster" in direct["matched_patterns"]
    assert direct["config"]["static_config_recovered"] is False
    assert direct["network_candidates"] == []
    assert direct["safety"]["sample_executed"] is False
    assert direct["safety"]["node_imported"] is False
    assert direct["safety"]["network_contacted"] is False
    quality = handler_result_quality(direct, minimum_score=_handler_spec().minimum_evidence_score)
    assert quality["tier_name"] == "structural_corroboration"
    assert quality["sufficient"] is True

    outer = BytesIO()
    with zipfile.ZipFile(outer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("package-a.tgz", package)
        archive.writestr("package-b.tgz", package)
    package_set = ANALYZER.analyze_outer_zip_bytes(outer.getvalue())
    assert package_set["analysis_type"] == "non_executing_static_npm_package_set"
    assert package_set["package_count"] == 2
    assert package_set["unique_payload_count"] == 1
    assert list(package_set["payload_occurrences"].values()) == [2]
    assert package_set["safety"]["sample_executed"] is False
    assert package_set["safety"]["network_contacted"] is False


def test_handler_suppresses_partial_markers_and_unrelated_formats() -> None:
    """一般ELF、部分marker、benign npm package、PEをRedC2へ昇格しない。"""

    handler, _invocation = load_handler(_handler_spec())
    for data in (
        make_elf(),
        make_elf(extra=b"REDSHELL"),
        make_tar(payload=make_elf()),
        b"MZ" + b"\0" * 256,
    ):
        with pytest.raises(HandlerNoEvidenceError):
            handler(data)


def test_handler_rejects_valid_minimal_elf_with_only_four_stuffed_markers() -> None:
    """妥当ELF headerへ4 markerだけを詰めても、自動handlerを一致させない。"""

    handler, _invocation = load_handler(_handler_spec())
    stuffed = make_elf(extra=b"\0".join(ANALYZER.PROTOCOL_MARKERS))
    proof = handler.__globals__["payload_evidence"](stuffed)
    assert proof["valid_elf_header"] is True
    assert proof["protocol_marker_cluster_complete"] is True
    assert proof["tls_api_cluster_complete"] is False
    assert proof["matched"] is False
    with pytest.raises(HandlerNoEvidenceError):
        handler(stuffed)


def test_reviewed_exact_hash_mapping_recovers_static_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """review済みhashから固定endpointを引ける場合だけconfig品質要件を充足する。"""

    handler, _invocation = load_handler(_handler_spec())
    payload = make_elf(redc2=True)
    digest = ANALYZER.sha256_bytes(payload)
    evidence_globals = handler.__globals__["payload_evidence"].__globals__
    monkeypatch.setitem(
        evidence_globals["REVIEWED_STATIC_CONFIG_BY_SHA256"],
        digest,
        {"host": "192.0.2.10", "port": 8792, "transport": "TLS"},
    )
    result = handler(payload)
    assert result["config"] == {
        "recovery_status": "reviewed_exact_payload_hash_mapping",
        "static_config_recovered": True,
        "endpoint_count": 1,
    }
    assert result["network_candidates"] == [
        {
            "host": "192.0.2.10",
            "port": 8792,
            "transport": "TLS",
            "role": "c2_candidate",
            "confidence": "reviewed_exact_payload_hash_mapping",
        }
    ]


def test_handler_fails_closed_for_corrupt_and_oversized_candidates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """強い候補markerを持つ破損ELF、破損gzip、hard limit超過を解析成功にしない。"""

    handler, _invocation = load_handler(_handler_spec())
    with pytest.raises(HandlerNoEvidenceError):
        handler(b"\x7fELF" + b"".join(ANALYZER.PROTOCOL_MARKERS))
    with pytest.raises(ANALYZER.ArchiveValidationError):
        handler(b"\x1f\x8bcorrupt-redc2-package")
    monkeypatch.setitem(handler.__globals__, "MAX_TOTAL", 128)
    with pytest.raises(ValueError, match="入力size"):
        handler(b"A" * 129)


def test_handler_public_result_omits_package_secrets_and_raw_payload() -> None:
    """package metadata、loader文字列、URL資格情報、ELF bytesを公開結果へ出さない。"""

    secret = "operator-password-do-not-publish"
    payload = make_elf(
        redc2=True,
        extra=f"https://user:{secret}@example.invalid/private?token={secret}".encode(),
    )
    package = make_tar(
        payload=payload,
        package_name=secret,
        package_scripts={"postinstall": f"echo {secret}"},
        loader_extra=f"\nconst password = '{secret}';".encode(),
    )
    execution = execute_handler(_handler_spec(), package, "private-package.tgz")
    rendered = json.dumps(execution, ensure_ascii=False)
    result = execution["result"]
    assert secret not in rendered
    assert "user:" not in rendered
    assert result["safety"]["secret_material_published"] is False
    assert result["safety"]["raw_payload_exported"] is False
    assert execution["verified_binary_outputs"] == []
    assert execution["executed_sample"] is False
    assert execution["network_contacted"] is False


def test_package_set_cli_result_is_always_a_safe_public_summary() -> None:
    """CLI既定JSONへpackage metadata、member名、URL、query、自由文字列を出さない。"""

    secret = "cli-secret-do-not-publish"
    payload = make_elf(
        redc2=True,
        extra=f"https://user:{secret}@example.invalid/private?token={secret}#fragment".encode(),
    )
    package = make_tar(
        payload=payload,
        unsafe_name=f"package/dist/{secret}.bin",
        package_name=secret,
        package_scripts={"postinstall": f"echo {secret}"},
        package_exports={".": f"./{secret}.mjs"},
        loader_extra=f"\nconst credential = '{secret}';".encode(),
    )
    outer = BytesIO()
    with zipfile.ZipFile(outer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(f"{secret}.tgz", package)
    result = ANALYZER.analyze_outer_zip_bytes(outer.getvalue())
    rendered = json.dumps(result, ensure_ascii=False)
    assert secret not in rendered
    assert "user:" not in rendered
    assert "?token=" not in rendered
    assert "#fragment" not in rendered
    assert '"package_name"' not in rendered
    assert '"scripts"' not in rendered
    assert '"exports"' not in rendered
    assert '"static_urls"' not in rendered
    assert result["packages"][0]["package_metadata_exported"] is False
    assert result["packages"][0]["member_names_exported"] is False
    assert result["packages"][0]["source_strings_exported"] is False
    assert result["safety"]["secret_material_published"] is False


def test_package_set_cli_failure_is_fixed_public_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """失敗時もarchive名、絶対path、例外本文、tracebackを公開しない。"""

    secret = "cli-failure-secret-do-not-publish"
    package_stream = BytesIO()
    with tarfile.open(fileobj=package_stream, mode="w:gz") as package_archive:
        malformed_metadata = b"{not-valid-json"
        info = tarfile.TarInfo("package/package.json")
        info.size = len(malformed_metadata)
        package_archive.addfile(info, BytesIO(malformed_metadata))

    input_path = tmp_path / f"{secret}-input.zip"
    output_path = tmp_path / f"{secret}-output.json"
    with zipfile.ZipFile(input_path, mode="w", compression=zipfile.ZIP_DEFLATED) as outer_archive:
        outer_archive.writestr(f"{secret}.tgz", package_stream.getvalue())

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "analyze_package_set.py",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
        ],
    )
    assert ANALYZER.main() == 2
    captured = capsys.readouterr()

    assert captured.out == ""
    assert captured.err.count("\n") == 1
    assert secret not in captured.err
    assert str(tmp_path) not in captured.err
    assert "Traceback" not in captured.err
    assert "ArchiveValidationError" not in captured.err
    assert json.loads(captured.err) == {
        "schema_version": 1,
        "analysis_type": "non_executing_static_npm_package_set",
        "status": "failed",
        "error": {
            "code": ANALYZER.PUBLIC_CLI_FAILURE_CODE,
            "message": ANALYZER.PUBLIC_CLI_FAILURE_MESSAGE,
        },
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "secret_material_published": False,
        },
    }
    assert not output_path.exists()


def test_package_set_cli_analysis_failure_removes_existing_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """解析失敗時は以前の成功成果物を残さず固定失敗JSONだけを返す。"""

    input_path = tmp_path / "private-input.zip"
    output_path = tmp_path / "private-output.json"
    output_path.write_text('{"stale":true}\n', encoding="utf-8")

    def fail_analysis(_path: Path, _password: str) -> dict[str, object]:
        raise RuntimeError(f"secret failure at {input_path}")

    monkeypatch.setattr(ANALYZER, "analyze_outer_zip", fail_analysis)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "analyze_package_set.py",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
        ],
    )

    assert ANALYZER.main() == 2
    captured = capsys.readouterr()

    assert captured.out == ""
    assert json.loads(captured.err) == ANALYZER._public_cli_failure()
    assert str(input_path) not in captured.err
    assert str(output_path) not in captured.err
    assert not output_path.exists()


def test_package_set_cli_write_failure_leaves_no_partial_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """一時fileへの書込が途中で失敗しても既存・部分成果物を公開しない。"""

    input_path = tmp_path / "private-input.zip"
    output_path = tmp_path / "private-output.json"
    output_path.write_text('{"stale":true}\n', encoding="utf-8")
    temporary_paths: list[Path] = []

    monkeypatch.setattr(ANALYZER, "analyze_outer_zip", lambda *_args: {"status": "complete"})

    def partially_write_then_fail(path: Path, _value: object) -> None:
        temporary_paths.append(path)
        path.write_text("{", encoding="utf-8")
        raise OSError(f"secret write failure at {output_path}")

    monkeypatch.setattr(ANALYZER, "write_json", partially_write_then_fail)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "analyze_package_set.py",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
        ],
    )

    assert ANALYZER.main() == 2
    captured = capsys.readouterr()

    assert captured.out == ""
    assert json.loads(captured.err) == ANALYZER._public_cli_failure()
    assert str(output_path) not in captured.err
    assert temporary_paths and temporary_paths[0] != output_path
    assert all(not path.exists() for path in temporary_paths)
    assert not output_path.exists()
