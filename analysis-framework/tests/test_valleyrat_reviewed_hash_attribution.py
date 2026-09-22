"""ValleyRATレビュー済みhashのfamily帰属境界を検証する。"""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

import pytest

from classifiers import classify_sample

MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "malware" / "valleyrat" / "detect.py"
)
SPEC = importlib.util.spec_from_file_location(
    "valleyrat_reviewed_hash_attribution_detect",
    MODULE_PATH,
)
assert SPEC and SPEC.loader
DETECT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DETECT)


class _FixedDigest:
    """実検体byteを保持せずregistry hash分岐だけを再現する。"""

    def __init__(self, digest: str) -> None:
        self._digest = digest

    def hexdigest(self) -> str:
        return self._digest


@pytest.mark.parametrize(
    "confirmation_record",
    (
        {"final_rat_confirmed": False},
        {},
        {"final_rat_confirmed": True},
    ),
    ids=("explicit-false", "missing", "explicit-true"),
)
def test_reviewed_hash_is_always_handler_route_only(
    monkeypatch: pytest.MonkeyPatch,
    confirmation_record: dict[str, bool],
) -> None:
    """過去レビュー状態に関係なく現在のbytesから終端構造を再検証する。"""

    data = b"MZ reviewed attribution fixture:" + repr(confirmation_record).encode()
    digest = hashlib.sha256(data).hexdigest()
    campaign_type = "signed_proxy_sideload"
    monkeypatch.setitem(DETECT.KNOWN_CAMPAIGNS, digest, campaign_type)
    monkeypatch.setitem(
        DETECT.REVIEWED_SAMPLES,
        digest,
        {"campaign": campaign_type, **confirmation_record},
    )

    result = DETECT.detect(data, Path("reviewed-fixture.exe"))
    campaign = result["campaigns"][0]
    normalized = classify_sample.normalize_detection_result(result)

    assert result["matched"] is True
    assert campaign["campaign_type"] == campaign_type
    assert "known inner SHA-256" in campaign["reasons"]
    assert result["supports_family_attribution"] is False
    assert campaign["supports_family_attribution"] is False
    assert campaign["attribution_scope"] == "reviewed_component_handler_route"
    assert campaign["terminal_family_confirmed"] is False
    assert (
        result["observations"]["reviewed_routing_semantics"]
        ["terminal_family_confirmed"]
        is False
    )
    assert (
        result["observations"]["reviewed_routing_semantics"]
        ["prior_review_recorded_terminal"]
        is (confirmation_record.get("final_rat_confirmed") is True)
    )
    assert classify_sample.detection_supports_family_attribution(normalized) is False


def test_every_reviewed_registry_hash_follows_confirmation_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """現行registry全件で明示true以外がroute-onlyになることを検証する。"""

    route_only_count = 0
    for digest, reviewed in DETECT.REVIEWED_SAMPLES.items():
        monkeypatch.setattr(
            DETECT.hashlib,
            "sha256",
            lambda _data, value=digest: _FixedDigest(value),
        )
        result = DETECT.detect(b"MZ registry-policy fixture", Path("fixture.exe"))
        campaign = result["campaigns"][0]
        assert campaign["campaign_type"] == reviewed["campaign"]
        route_only_count += 1
        assert result["supports_family_attribution"] is False
        assert campaign["supports_family_attribution"] is False
        assert campaign["terminal_family_confirmed"] is False

    assert route_only_count > 0
    assert route_only_count == len(DETECT.REVIEWED_SAMPLES)


def test_protected_inno_route_is_exact_hash_only_and_not_family_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """汎用native候補よりreview済み経路を優先し、未知hashへ拡張しない。"""

    reviewed_data = b"MZ synthetic reviewed Inno Setup fixture"
    unknown_data = b"MZ synthetic unknown Inno Setup fixture"
    reviewed_digest = hashlib.sha256(reviewed_data).hexdigest()
    monkeypatch.setitem(DETECT.KNOWN_CAMPAIGNS, reviewed_digest, "protected_installer_bundle")
    monkeypatch.setitem(
        DETECT.REVIEWED_SAMPLES,
        reviewed_digest,
        {"campaign": "protected_installer_bundle", "final_rat_confirmed": False},
    )
    monkeypatch.setattr(DETECT, "_terminal_configuration_detection", lambda *_: None)
    monkeypatch.setattr(DETECT, "_appdomainmanager_loader_shape", lambda *_: {"matched": False})
    monkeypatch.setattr(
        DETECT,
        "_native_loader_detection",
        lambda *_: {
            "matched": True,
            "supports_family_attribution": False,
            "campaigns": [{"campaign_type": "native_loader_candidate"}],
        },
    )
    monkeypatch.setattr(DETECT, "analyze_signed_proxy_sideload", lambda *_: {})

    reviewed = DETECT.detect(reviewed_data, Path("reviewed.exe"))
    unknown = DETECT.detect(unknown_data, Path("unknown.exe"))
    assert reviewed["campaigns"][0]["campaign_type"] == "protected_installer_bundle"
    assert reviewed["supports_family_attribution"] is False
    assert reviewed["campaigns"][0]["terminal_family_confirmed"] is False
    assert unknown["campaigns"][0]["campaign_type"] != "protected_installer_bundle"
