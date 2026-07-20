from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]


def load(relative: str, name: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_reviewed_controller_cipher_decodes_exactly() -> None:
    module = load("analysis-framework/malware/phorpiex_spam/extract_config.py", "phorpiex_spam_config")
    assert module.decode_not_xor(module.ENCRYPTED_CONTROLLER).decode() == module.CONTROLLER_URL


def test_http_and_smtp_detectors_require_compound_evidence() -> None:
    module = load("analysis-framework/malware/phorpiex_spam/network_detector.py", "phorpiex_spam_detector")
    assert module.inspect_http(b"GET /n.txt HTTP/1.0\r\n\r\n", "178.16.55.240")["matched"]
    smtp = b"Subject: I RECORDED YOU!\r\n\r\nPay 1QKNMjsLUuaS4hVDMzy4cWBhuaqz58xxCc"
    assert module.inspect_smtp(smtp)["matched"]
    assert not module.inspect_smtp(b"Subject: I RECORDED YOU!\r\n\r\nbenign")["matched"]


def test_extractor_rejects_unreviewed_hash() -> None:
    module = load("analysis-framework/malware/phorpiex_spam/extract_config.py", "phorpiex_spam_unknown")
    with pytest.raises(ValueError, match="SHA-256"):
        module.extract_config(b"synthetic")
