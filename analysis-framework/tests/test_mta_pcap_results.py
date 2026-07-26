from __future__ import annotations

import json
import re
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[2]
RESULT_ROOT = (
    REPOSITORY
    / "analysis-results"
    / "network-traffic"
    / "malware-traffic-analysis-net"
    / "2026-07-26"
)
RULE_PATH = (
    REPOSITORY
    / "analysis-framework"
    / "network-rules"
    / "snort3"
    / "mta-20260726-candidates.rules"
)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_capture_manifest_has_exactly_50_dated_pcaps() -> None:
    manifest = load_json(RESULT_ROOT / "manifest.json")
    assert manifest["capture_count"] == 50
    assert len(manifest["items"]) == 50
    assert manifest["items"][0]["published_date"] == "2026-06-01"
    assert manifest["items"][-1]["published_date"] == "2025-02-13"
    for item in manifest["items"]:
        assert re.fullmatch(r"20\d{2}-\d{2}-\d{2}", item["published_date"])
        assert item["capture_start"]
        assert item["capture_end"]
        assert re.fullmatch(r"[0-9a-f]{64}", item["pcap_sha256"])
        assert int(item["packet_count"]) > 0


def test_every_capture_has_safe_public_observations() -> None:
    capture_dirs = sorted((RESULT_ROOT / "captures").iterdir())
    assert len(capture_dirs) == 50
    for capture_dir in capture_dirs:
        observations = load_json(capture_dir / "protocol-observations.json")
        safety = observations["safety"]
        assert safety["pcap_replayed"] is False
        assert safety["sample_executed"] is False
        assert safety["exported_object_executed"] is False
        assert safety["network_name_resolution_enabled"] is False
        assert safety["live_c2_contacted"] is False
        assert (capture_dir / "README.md").is_file()
        assert (capture_dir / "sample-links.json").is_file()


def test_ftp_sensitive_arguments_are_not_published() -> None:
    for path in (RESULT_ROOT / "captures").glob("*/protocol-observations.json"):
        observations = load_json(path)
        for record in observations["ftp"]["records"]:
            command = record.get("command")
            argument = record.get("argument")
            if command in {"USER", "PASS", "ACCT", "STOR"} and argument:
                assert isinstance(argument, dict)
                assert argument["redacted"] is True
                assert re.fullmatch(r"[0-9a-f]{64}", argument["sha256"])


def test_curated_snort_candidates_have_evidence_and_unique_sids() -> None:
    evidence = load_json(RESULT_ROOT / "signature-evidence.json")
    assert evidence["candidate_count"] == 11
    assert len(evidence["rules"]) == 11
    assert all(item["capture_count"] > 0 for item in evidence["rules"])
    assert all(not item["cross_family_capture_matches"] for item in evidence["rules"])
    assert all(item["validation"]["status"] == "candidate" for item in evidence["rules"])

    rules_text = RULE_PATH.read_text(encoding="utf-8")
    rules = [line for line in rules_text.splitlines() if line.startswith("alert ")]
    assert len(rules) == 11
    sids = [int(re.search(r"sid:(\d+);", rule).group(1)) for rule in rules]
    assert len(sids) == len(set(sids))
    assert all(all(option in rule for option in ("msg:", "flow:", "sid:", "rev:")) for rule in rules)
    assert not re.search(r'pcre:"[^"]+",fast_pattern', rules_text)


def test_background_traffic_candidates_were_rejected() -> None:
    rejected = load_json(RESULT_ROOT / "rejected-signature-candidates.json")
    assert rejected["rejected_count"] == 9
    rules_text = RULE_PATH.read_text(encoding="utf-8").lower()
    banned = (
        "windowsupdate",
        "c.pki.goog",
        "ipinfo.io",
        "acroipm2.adobe.com",
        "filestreamingservice",
        "|05 00 00 03 10 00 00 00|",
    )
    assert not any(value in rules_text for value in banned)


def test_feature_lifecycle_preserves_currentness_limits() -> None:
    lifecycle = load_json(RESULT_ROOT / "feature-lifecycle.json")
    assert lifecycle["feature_count"] == len(lifecycle["features"])
    assert lifecycle["feature_count"] > 0
    for feature in lifecycle["features"]:
        assert feature["first_observed"] <= feature["last_observed"]
        assert feature["age_days"] >= 0
        assert feature["status"] in {
            "recently_observed",
            "revalidation_recommended",
            "historical_revalidation_required",
            "legacy_observation",
        }
        assert "断定しない" in feature["current_use_status"]

def test_pcap_tools_are_reusable_and_do_not_embed_local_user_paths() -> None:
    tool_names = (
        "mta_pcap_inventory.py",
        "mta_pcap_downloader.py",
        "mta_pcap_analyzer.py",
    )
    common = REPOSITORY / "analysis-framework" / "common"
    for name in tool_names:
        source = (common / name).read_text(encoding="utf-8")
        assert "C:\\Users\\Administrator" not in source
        assert "/50]" not in source
        compile(source, str(common / name), "exec")

    analyzer = (common / "mta_pcap_analyzer.py").read_text(encoding="utf-8")
    for command in ("USER", "PASS", "ACCT", "STOR", "RETR"):
        assert f'"{command}"' in analyzer
