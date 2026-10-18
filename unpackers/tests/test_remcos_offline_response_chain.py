from __future__ import annotations

from types import SimpleNamespace

import pyzipper

from unpackers import remcos_offline_response_chain as chain


def test_offline_chain_routes_saved_response_through_all_static_stages(
    monkeypatch,
) -> None:
    child = b"$child=1"
    stage = b"native-stage"
    monkeypatch.setattr(
        chain,
        "recover_reviewed_cyclic_xor_context",
        lambda _parent: SimpleNamespace(
            report={
                "status": "context_recovered",
                "remote_payload_transform": {"status": "recovered"},
            },
            key=b"key",
            function_name="Unwrap",
        ),
    )
    monkeypatch.setattr(
        chain,
        "recover_remote_payload_from_transform",
        lambda _response, _transform: ({"status": "payload_recovered"}, child),
    )
    monkeypatch.setattr(
        chain,
        "recover_inherited_cyclic_xor_loader",
        lambda _parent, _child, *, response_data: (
            {
                "candidate_set_complete": True,
                "candidate_set_truncated": False,
                "response_recovery": {
                    "native_span_stage": {"status": "stage_recovered"}
                },
            },
            [("remcos-native-stage-03.bin", stage)],
        ),
    )
    monkeypatch.setattr(
        chain,
        "recover_remcos_native_constants",
        lambda _stage: (
            {"status": "constants_recovered"},
            [("remcos-native-constant-001.txt", b"one.invalid/path")],
        ),
    )

    report, artifacts = chain.analyze_remcos_offline_response_chain(
        b"parent", b"saved-response"
    )

    assert report["status"] == "constants_recovered"
    assert report["safety"]["network_contacted"] is False
    assert artifacts == [
        ("remote-child.ps1", child),
        ("remcos-native-stage-03.bin", stage),
        ("remcos-native-constant-001.txt", b"one.invalid/path"),
    ]


def test_cli_writes_only_json_and_aes_archive(tmp_path, monkeypatch) -> None:
    parent = tmp_path / "parent.ps1"
    response = tmp_path / "response.bin"
    report_path = tmp_path / "report.json"
    archive_path = tmp_path / "artifacts.zip"
    parent.write_bytes(b"parent")
    response.write_bytes(b"response")
    monkeypatch.setattr(
        chain,
        "analyze_remcos_offline_response_chain",
        lambda _parent, _response: (
            {"status": "stage_recovered"},
            [("stage.bin", b"fixture")],
        ),
    )

    result = chain.main(
        [
            "--parent",
            str(parent),
            "--response",
            str(response),
            "--report",
            str(report_path),
            "--artifact-zip",
            str(archive_path),
        ]
    )

    assert result == 0
    assert report_path.is_file()
    with pyzipper.AESZipFile(archive_path) as archive:
        archive.setpassword(b"infected")
        names = archive.namelist()
        assert len(names) == 1
        assert archive.read(names[0]) == b"fixture"


def test_poly_only_output_is_selected_as_partial_stage(monkeypatch) -> None:
    prefix = b"poly-only"
    monkeypatch.setattr(
        chain,
        "recover_reviewed_cyclic_xor_context",
        lambda _parent: SimpleNamespace(
            report={
                "status": "context_recovered",
                "remote_payload_transform": {"status": "recovered"},
            },
            key=b"key",
            function_name="Unwrap",
        ),
    )
    monkeypatch.setattr(
        chain,
        "recover_remote_payload_from_transform",
        lambda _response, _transform: ({"status": "payload_recovered"}, b"child"),
    )
    monkeypatch.setattr(
        chain,
        "recover_inherited_cyclic_xor_loader",
        lambda _parent, _child, *, response_data: (
            {
                "candidate_set_complete": True,
                "candidate_set_truncated": False,
                "response_recovery": {
                    "native_span_stage": {"status": "xor_profile_not_unique"},
                    "polymorphic_xor_loader": {"status": "shellcode_recovered"},
                },
            },
            [("remcos-polymorphic-xor-shellcode.bin", prefix)],
        ),
    )
    monkeypatch.setattr(
        chain,
        "recover_remcos_native_constants",
        lambda _stage: ({"status": "decrypt_helper_not_unique"}, []),
    )

    report, _artifacts = chain.analyze_remcos_offline_response_chain(
        b"parent", b"saved-response"
    )

    assert report["status"] == "stage_recovered"
    assert report["logical_stage"]["selection_reason"] == "polymorphic_prefix_only"
    assert report["logical_stage"]["size"] == len(prefix)
