"""スティーラー系抽出器のC2証拠境界を検証する。"""

from __future__ import annotations

from extractors.formbook import extract as extract_formbook
from extractors.lummastealer import extract as extract_lumma
from extractors.remusstealer import extract as extract_remus


def test_candidate_literal_is_not_promoted_to_confirmed_c2() -> None:
    for extractor in (extract_formbook, extract_lumma, extract_remus):
        result = extractor(b"https://example.test/api/upload", "fixture.bin")
        protocol = result["config"]["protocol_analysis"]
        assert protocol["candidate_infrastructure"] == [
            "https://example.test/api/upload"
        ]
        assert protocol["confirmed_c2"] == []
        assert protocol["terminal_protocol_recovered"] is False
        expected = (
            "passive_only"
            if extractor is extract_formbook
            else "guarded_active_reviewed_profile_only"
        )
        assert protocol["active_probe_policy"] == expected


def test_family_guidance_keeps_distinct_wire_profiles() -> None:
    formbook = extract_formbook(b"FormBook", "fixture.bin")["config"][
        "protocol_analysis"
    ]
    lumma = extract_lumma(b"LummaC2", "fixture.bin")["config"][
        "protocol_analysis"
    ]
    remus = extract_remus(b"RemusStealer", "fixture.bin")["config"][
        "protocol_analysis"
    ]
    assert formbook["profile_candidates"] == [
        "FormBook-4.1-or-XLoader-RC4-HTTP"
    ]
    assert "Lumma-v6-uid-cid" in lumma["profile_candidates"]
    assert remus["profile_candidates"] == [
        "Remus-access-token-step-multipart-HTTP"
    ]
