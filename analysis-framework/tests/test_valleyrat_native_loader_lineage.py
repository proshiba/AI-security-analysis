"""native loader静的lineageのfail-closed契約を検証する。"""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from extractors.valleyrat import native_loader_lineage as lineage  # noqa: E402


def _terminal_proof(**updates: object) -> lineage.TerminalComponentProof:
    values: dict[str, object] = {
        "family": "valleyrat",
        "static_config_recovered": True,
        "terminal_family_confirmed": True,
        "supports_family_attribution": True,
        "terminal_network_lineage_proven": True,
        "terminal_protocol_lineage_proven": True,
        "endpoint_count": 2,
        "candidate_only": False,
    }
    values.update(updates)
    return lineage.TerminalComponentProof(**values)  # type: ignore[arg-type]


def _wide_pipe_probe(*, protocol_complete: bool = True) -> dict[str, object]:
    required = {
        "single_validated_winsock_descriptor": True,
        "external_root_launcher": True,
        "configuration_source_to_parser": True,
        "parser_field_schema_complete": True,
        "launcher_parser_before_worker": True,
        "runtime_endpoint_globals_referenced": True,
        "worker_transport_vtable_dispatch": True,
        "tcp_connect_send_receive_chain": True,
        "same_socket_field_connect_send_receive": True,
        "winos_framing_and_xor": protocol_complete,
        "bootstrap_command_04": True,
        "winos_receive_dispatcher": True,
        "received_stage_memory_and_registry_path": True,
    }
    return {
        "matched": True,
        "family": "valleyrat",
        "supports_family_attribution": True,
        "terminal_family_confirmed": True,
        "static_config_recovered": True,
        "config": {"endpoint_count": 2},
        "evidence": {
            "wide_pipe_config": {
                "lineage": {
                    "analysis_complete": True,
                    "terminal_network_lineage_proven": True,
                    "required_groups": required,
                    "protocol": {
                        "transport": "tcp",
                        "frame_prefix_size": 4,
                        "header_size": 10,
                        "payload_transform": "header_derived_xor",
                    },
                }
            }
        },
    }


def _bundle(records: list[tuple[bytes, bytes]]) -> bytes:
    body = bytearray()
    body.extend(len(records).to_bytes(4, "little"))
    for name, payload in records:
        body.extend(len(name).to_bytes(4, "little"))
        body.extend(name)
        body.extend(len(payload).to_bytes(4, "little"))
        body.extend(payload)
    return bytes(body) + len(body).to_bytes(4, "little") + b"KBND"


def test_kbnd_records_require_exact_footer_and_bounded_ascii_names() -> None:
    """footer長とrecord境界が完全一致する場合だけbundleを受理する。"""

    encoded = bytes(range(64))
    data = _bundle([(b"component-one", encoded), (b"component-two", b"opaque")])

    records = lineage._bundle_records(data, 0)

    assert records is not None
    assert [item.encoded for item in records] == [encoded, b"opaque"]
    assert lineage._bundle_records(data[:-8] + (1).to_bytes(4, "little") + b"KBND", 0) is None
    assert lineage._bundle_records(_bundle([(b"../escape", b"payload")]), 0) is not None
    assert lineage._bundle_records(_bundle([(b"bad\0name", b"payload")]), 0) is None


@pytest.mark.parametrize(
    ("updates"),
    [
        {"family": "unknown"},
        {"static_config_recovered": False},
        {"terminal_family_confirmed": False},
        {"supports_family_attribution": False},
        {"terminal_network_lineage_proven": False},
        {"terminal_protocol_lineage_proven": False},
        {"endpoint_count": 0},
        {"candidate_only": True},
    ],
)
def test_terminal_gate_rejects_every_incomplete_proof(updates: dict[str, object]) -> None:
    """候補、設定欠落、network欠落、protocol欠落を個別に拒否する。"""

    assert lineage._strict_terminal(_terminal_proof(**updates)) is False


def test_terminal_gate_rejects_runtime_type_spoofing() -> None:
    """type annotationを無視した不正family値でも例外を出さず拒否する。"""

    assert lineage._strict_terminal(_terminal_proof(family=None)) is False
    assert lineage._strict_terminal({"terminal_family_confirmed": True}) is False


def _resource_trace(*, process_path_matches: bool = True) -> lineage._Trace:
    module = lineage._Value("argument", 0)
    resource_type = lineage._Value("argument", 1)
    resource_name = lineage._Value("argument", 2)
    path = lineage._Value("pointer", "stack", 64)
    other_path = lineage._Value("pointer", "stack", 96)

    def call(
        name: str,
        index: int,
        arguments: tuple[lineage._Value | None, ...],
    ) -> lineage._ApiCall:
        return lineage._ApiCall(
            name,
            0x1000 + index,
            index,
            arguments,
            lineage._Value("return", 0x1000 + index),
        )

    find = call("findresourcew", 1, (module, resource_name, resource_type, None))
    load = call("loadresource", 2, (module, find.result, None, None))
    lock = call("lockresource", 3, (load.result, None, None, None))
    size = call("sizeofresource", 4, (module, find.result, None, None))
    create = call("createfilew", 5, (path, None, None, None))
    write = call("writefile", 6, (create.result, lock.result, size.result, None))
    process = call(
        "createprocessw",
        7,
        (path if process_path_matches else other_path, None, None, None),
    )
    return lineage._Trace(calls=[find, load, lock, size, create, write, process])


def test_resource_callback_requires_locked_bytes_size_and_same_process_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """API列ではなくhandle・buffer・size・pathの同値性を要求する。"""

    context = SimpleNamespace()
    function = lineage._Function(0x1000, 0x1100, ())
    monkeypatch.setattr(lineage, "_trace_function", lambda *_args, **_kwargs: _resource_trace())

    assert lineage._resource_callback_proven(context, function) is True

    monkeypatch.setattr(
        lineage,
        "_trace_function",
        lambda *_args, **_kwargs: _resource_trace(process_path_matches=False),
    )
    assert lineage._resource_callback_proven(context, function) is False


@pytest.mark.parametrize("argument_index", [0, 1, 2])
def test_resource_callback_rejects_write_lineage_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    argument_index: int,
) -> None:
    """WriteFileのhandle、buffer、sizeのどれかが異なれば拒否する。"""

    trace = _resource_trace()
    write = trace.calls[-2]
    arguments = list(write.arguments)
    arguments[argument_index] = lineage._Value("constant", 0x55)
    trace.calls[-2] = replace(write, arguments=tuple(arguments))
    monkeypatch.setattr(lineage, "_trace_function", lambda *_args, **_kwargs: trace)

    assert (
        lineage._resource_callback_proven(
            SimpleNamespace(),
            lineage._Function(0x1000, 0x1100, ()),
        )
        is False
    )


def _install_stage_fixture(
    monkeypatch: pytest.MonkeyPatch,
    executed: tuple[bytes, ...],
) -> None:
    root_context = object()
    monkeypatch.setattr(
        lineage,
        "_load_context",
        lambda data: root_context if data == b"MZ root" else None,
    )
    monkeypatch.setattr(lineage, "_structural_cluster", lambda _context: "generic_loader_candidate")
    stage = lineage._Stage(
        kind="fixture_stage",
        executed_components=executed,
        recovered_component_count=len(executed),
        observation={
            "status": "validated_fixture_loader_lineage",
            "resource_names_included": False,
            "output_paths_included": False,
            "raw_payload_included": False,
        },
    )
    monkeypatch.setattr(
        lineage,
        "_direct_resource_stage",
        lambda context: stage if context is root_context else None,
    )
    monkeypatch.setattr(lineage, "_kbnd_stage", lambda _context: None)


def test_complete_loader_and_terminal_proof_is_promoted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """全loader辺と終端config/network/protocol証明が揃う場合だけ確定する。"""

    terminal = b"MZ terminal component"
    _install_stage_fixture(monkeypatch, (terminal,))

    result = lineage.analyze_native_loader_lineage(
        b"MZ root",
        terminal_proofs={terminal: _terminal_proof()},
    )

    assert result is not None
    assert result.terminal_component == terminal
    assert result.recovered_components == ()
    assert result.observation["supports_family_attribution"] is True
    assert result.observation["terminal_family_confirmed"] is True
    assert result.observation["terminal_network_lineage_proven"] is True
    assert result.observation["lineage_depth"] == 1
    assert result.observation["terminal"]["endpoint_values_included"] is False


def test_default_validator_reuses_strict_production_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """stub validator未注入でも既存strict probeから終端証明を構築する。"""

    terminal = b"MZ terminal component"
    _install_stage_fixture(monkeypatch, (terminal,))
    monkeypatch.setattr(
        lineage,
        "probe_wide_pipe_config",
        lambda data: _wide_pipe_probe() if data == terminal else {"matched": False},
    )
    monkeypatch.setattr(
        lineage,
        "probe_run_dll_native_core_config",
        lambda _data: {"matched": False},
    )

    result = lineage.analyze_native_loader_lineage(b"MZ root")

    assert result is not None
    assert result.terminal_component == terminal
    assert result.observation["terminal_family_confirmed"] is True
    assert result.observation["terminal_network_lineage_proven"] is True
    assert result.observation["terminal_protocol_lineage_proven"] is True


def test_default_validator_rejects_incomplete_protocol_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """config/network markerがあってもprotocol group欠落ならroute-onlyへ閉じる。"""

    terminal = b"MZ terminal component"
    _install_stage_fixture(monkeypatch, (terminal,))
    monkeypatch.setattr(
        lineage,
        "probe_wide_pipe_config",
        lambda data: (
            _wide_pipe_probe(protocol_complete=False)
            if data == terminal
            else {"matched": False}
        ),
    )
    monkeypatch.setattr(
        lineage,
        "probe_run_dll_native_core_config",
        lambda _data: {"matched": False},
    )

    result = lineage.analyze_native_loader_lineage(b"MZ root")

    assert result is not None
    assert result.terminal_component is None
    assert result.recovered_components == (terminal,)
    assert result.observation["follow_on_candidate_set_complete"] is True
    assert result.observation["supports_family_attribution"] is False
    assert result.observation["terminal_protocol_lineage_proven"] is False


def test_candidate_terminal_never_promotes_and_keeps_loader_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """config候補だけなら復元loader証拠を保持してfamily確定しない。"""

    candidate = b"MZ candidate component"
    _install_stage_fixture(monkeypatch, (candidate,))

    result = lineage.analyze_native_loader_lineage(
        b"MZ root",
        terminal_proofs={
            candidate: _terminal_proof(
                terminal_network_lineage_proven=False,
                candidate_only=True,
            )
        },
    )

    assert result is not None
    assert result.terminal_component is None
    assert result.recovered_components == (candidate,)
    assert result.observation["supports_family_attribution"] is False
    assert result.observation["terminal_family_confirmed"] is False
    assert result.observation["stages"][0]["status"] == "validated_fixture_loader_lineage"
    assert "valleyrat_terminal_component_unproven" in result.observation["missing_proof_codes"]


def test_multiple_terminal_paths_are_ambiguous(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """複数の異なる終端へ到達するloaderを暗黙に統合しない。"""

    _install_stage_fixture(monkeypatch, (b"MZ terminal one", b"MZ terminal two"))

    result = lineage.analyze_native_loader_lineage(
        b"MZ root",
        terminal_proofs={
            b"MZ terminal one": _terminal_proof(),
            b"MZ terminal two": _terminal_proof(),
        },
    )

    assert result is not None
    assert result.terminal_component is None
    assert result.recovered_components == (
        b"MZ terminal one",
        b"MZ terminal two",
    )
    assert result.observation["follow_on_candidate_set_complete"] is True
    assert result.observation["terminal_family_confirmed"] is False
    assert "multiple_terminal_component_paths_ambiguous" in result.observation["missing_proof_codes"]


def test_follow_on_limit_discards_partial_component_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """follow-on上限を超えた場合はprefixだけを後段へ渡さない。"""

    first = b"MZ first route-only component"
    second = b"MZ second route-only component"
    _install_stage_fixture(monkeypatch, (first, second))
    monkeypatch.setattr(lineage, "MAXIMUM_FOLLOW_ON_COMPONENTS", 1)

    result = lineage.analyze_native_loader_lineage(
        b"MZ root",
        terminal_proofs={},
    )

    assert result is not None
    assert result.terminal_component is None
    assert result.recovered_components == ()
    assert result.observation["follow_on_candidate_set_complete"] is False
    assert result.observation["follow_on_components_truncated"] is True
    assert result.observation["follow_on_component_count"] == 0


def test_loader_structure_without_transform_is_route_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """import構造だけのclusterはfamilyやC2設定を確定しない。"""

    context = object()
    monkeypatch.setattr(lineage, "_load_context", lambda _data: context)
    monkeypatch.setattr(lineage, "_structural_cluster", lambda _context: "route_only_candidate")
    monkeypatch.setattr(lineage, "_direct_resource_stage", lambda _context: None)
    monkeypatch.setattr(lineage, "_kbnd_stage", lambda _context: None)

    result = lineage.analyze_native_loader_lineage(b"MZ fixture")

    assert result is not None
    assert result.observation["terminal_family_confirmed"] is False
    assert result.observation["terminal"]["endpoint_count"] == 0
    assert "native_loader_transform_lineage_unproven" in result.observation["missing_proof_codes"]
    assert result.observation["hash_or_filename_rule_used"] is False
    assert result.observation["external_label_used"] is False
