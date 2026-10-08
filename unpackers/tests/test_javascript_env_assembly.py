"""Environment分割型JScript loaderの非実行復元テスト。"""

from __future__ import annotations

import base64

import pytest

from unpackers import javascript_env_assembly as loader
from unpackers import static_unpacker


def _utf16_code_units(value: str) -> str:
    raw = value.encode("utf-16le")
    return "".join(
        chr(int.from_bytes(raw[index : index + 2], "little"))
        for index in range(0, len(raw), 2)
    )


def _pollute(value: str, separator: str) -> str:
    return separator.join(value) + separator


def _script(
    payload: bytes,
    *,
    include_command: bool = True,
    encoded_override: str | None = None,
) -> bytes:
    separator = "A📒B"
    encoded = encoded_override or base64.b64encode(payload).decode("ascii")
    polluted_units = _utf16_code_units(_pollute(encoded, separator))
    split_at = next(
        index
        for index in range(1, len(polluted_units))
        if 0xD800 <= ord(polluted_units[index - 1]) <= 0xDBFF
        and 0xDC00 <= ord(polluted_units[index]) <= 0xDFFF
    )
    first, second = polluted_units[:split_at], polluted_units[split_at:]
    prefix = (
        "powershell -windowstyle hidden -command "
        "[System.Reflection.Assembly]::Load([Convert]::FromBase64String("
    )
    suffix = "));[Fixture.Entry]::Start('QQ==','','Qg==');"
    command_lines = ""
    if include_command:
        command_lines = f'''var command = "{_pollute(prefix, separator)}" + expression + "{_pollute(suffix, separator)}";
command = command.split("{separator}").join("");
'''
    text = f'''var shell = new ActiveXObject("WScript.Shell");
var environment = shell.Environment("User");
var payload = "{first}";
payload += "{second}";
payload = payload.split("{separator}").join("");
var chunkSize = 30000;
var expression = "";
for (var index = 0; index < payload.length; index += chunkSize) {{
  var key = "P" + index;
  environment.Item(key) = payload.substr(index, chunkSize);
  expression = expression + "$env:" + key + "+";
}}
{command_lines}
var startup = service.Get("Win32_ProcessStartup").SpawnInstance_();
var process = service.Get("Win32_Process");
process.Create(command, null, startup, null);
'''
    return b"\xff\xfe" + text.encode("utf-16le", errors="surrogatepass")


def test_recovers_split_surrogate_base64_pe_without_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"MZ" + bytes(range(256)) * 4
    monkeypatch.setattr(loader, "_valid_pe", lambda value: value == payload)
    report, artifacts = loader.recover_javascript_env_assembly(_script(payload))
    assert report["status"] == "managed_assembly_recovered"
    assert report["decoded_sha256"] == loader._sha256(payload)
    assert report["literal_segments"] == 2
    assert report["environment"]["chunk_count"] == 1
    assert report["invocation"]["static_method"] == "Start"
    assert report["invocation"]["argument_count"] == 3
    assert report["invocation"]["arguments"][0]["decoded_sha256"] == loader._sha256(
        b"A"
    )
    assert report["evidence_boundary"] == {
        "supports_family_attribution": False,
        "supports_c2_confirmation": False,
        "loader_arguments_decrypted": False,
        "payload_acquisition_url_recovered": False,
    }
    assert report["executed"] is False
    assert report["network_contacted"] is False
    assert artifacts == [("javascript-env-assembly-pe", payload)]


def test_rejects_valid_base64_pe_without_assembly_load_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"MZ" + b"P" * 1022
    monkeypatch.setattr(loader, "_valid_pe", lambda value: value == payload)
    report, artifacts = loader.recover_javascript_env_assembly(
        _script(payload, include_command=False)
    )
    assert report["status"] == "pattern_not_found"
    assert report["decoded_pe_candidate_count"] == 1
    assert report["accepted_candidate_count"] == 0
    assert artifacts == []


def test_rejects_unrelated_environment_write_without_payload_lineage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"MZ" + b"E" * 1022
    monkeypatch.setattr(loader, "_valid_pe", lambda value: value == payload)
    script = _script(payload).decode("utf-16le", errors="surrogatepass")
    script = script.replace(
        "environment.Item(key) = payload.substr(index, chunkSize);",
        "var unused = payload.substr(index, chunkSize);\n"
        '  environment.Item(key) = "decoy";',
    )

    report, artifacts = loader.recover_javascript_env_assembly(
        script.encode("utf-16le", errors="surrogatepass")
    )

    assert report["status"] == "pattern_not_found"
    assert report["decoded_pe_candidate_count"] == 1
    assert artifacts == []


def test_rejects_command_not_passed_to_win32_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"MZ" + b"C" * 1022
    monkeypatch.setattr(loader, "_valid_pe", lambda value: value == payload)
    script = _script(payload).decode("utf-16le", errors="surrogatepass")
    script = script.replace(
        "process.Create(command, null, startup, null);",
        'process.Create("benign", null, startup, null);',
    )

    report, artifacts = loader.recover_javascript_env_assembly(
        script.encode("utf-16le", errors="surrogatepass")
    )

    assert report["status"] == "pattern_not_found"
    assert report["decoded_pe_candidate_count"] == 1
    assert artifacts == []


def test_rejects_duplicate_split_recipe_as_ambiguous(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """同じ有効候補を二重列挙した場合も一意とみなさない。"""

    payload = b"MZ" + b"A" * 1022
    monkeypatch.setattr(loader, "_valid_pe", lambda value: value == payload)
    script = _script(payload).decode("utf-16le", errors="surrogatepass")
    split_recipe = 'payload = payload.split("A📒B").join("");'
    script = script.replace(split_recipe, f"{split_recipe}\n{split_recipe}")

    report, artifacts = loader.recover_javascript_env_assembly(
        script.encode("utf-16le", errors="surrogatepass")
    )

    assert report["status"] == "ambiguous_candidates"
    assert report["decoded_pe_candidate_count"] == 2
    assert report["accepted_candidate_count"] == 2
    assert artifacts == []


def test_rejects_noncanonical_base64_before_pe_acceptance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """未使用bitが非zeroのBase64は同じbytesへ復号できても拒否する。"""

    payload = b"MZ" + b"N" * 1022
    canonical = base64.b64encode(payload).decode("ascii")
    assert canonical.endswith("==")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    unused_bits_set = alphabet[alphabet.index(canonical[-3]) + 1]
    noncanonical = canonical[:-3] + unused_bits_set + "=="
    assert base64.b64decode(noncanonical, validate=True) == payload
    monkeypatch.setattr(loader, "_valid_pe", lambda value: value == payload)

    report, artifacts = loader.recover_javascript_env_assembly(
        _script(payload, encoded_override=noncanonical)
    )

    assert report["status"] == "pattern_not_found"
    assert report["decoded_pe_candidate_count"] == 0
    assert report["accepted_candidate_count"] == 0
    assert artifacts == []


@pytest.mark.parametrize(
    ("limit_name", "limit_value", "chunk_size"),
    [
        ("MAX_LITERAL_SEGMENTS", 1, None),
        ("MAX_JOINED_CHARACTERS", 32, None),
        ("MAX_ENVIRONMENT_CHUNKS", 4, 100),
    ],
)
def test_rejects_literal_join_and_environment_chunk_limit_overruns(
    monkeypatch: pytest.MonkeyPatch,
    limit_name: str,
    limit_value: int,
    chunk_size: int | None,
) -> None:
    """各上限を超えた部分結果は後段へ渡さない。"""

    payload = b"MZ" + b"L" * 1022
    monkeypatch.setattr(loader, "_valid_pe", lambda value: value == payload)
    monkeypatch.setattr(loader, limit_name, limit_value)
    script = _script(payload)
    if chunk_size is not None:
        text = script.decode("utf-16le", errors="surrogatepass")
        text = text.replace("var chunkSize = 30000;", f"var chunkSize = {chunk_size};")
        script = text.encode("utf-16le", errors="surrogatepass")

    report, artifacts = loader.recover_javascript_env_assembly(script)

    assert report["status"] == "pattern_not_found"
    assert report["accepted_candidate_count"] == 0
    assert artifacts == []


def test_static_unpacker_routes_recovered_assembly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"MZ" + b"R" * 1022
    monkeypatch.setattr(loader, "_valid_pe", lambda value: value == payload)
    report, artifacts = static_unpacker.unpack_bytes(_script(payload), "fixture.js")
    assert report["javascript_env_assembly"]["status"] == "managed_assembly_recovered"
    assert ("javascript-env-assembly-pe", payload) in artifacts
    assert report["executed"] is False
    assert report["network_contacted"] is False


def test_rejects_non_utf16_and_oversized_inputs() -> None:
    report, artifacts = loader.recover_javascript_env_assembly(b"var x = 1;")
    assert report["status"] == "utf16le_bom_not_found"
    assert artifacts == []
    report, artifacts = loader.recover_javascript_env_assembly(
        b"\xff\xfe" + b"A" * loader.MAX_SCRIPT_SIZE
    )
    assert report["status"] == "size_blocked"
    assert artifacts == []


def test_type_contract_is_fail_closed() -> None:
    with pytest.raises(TypeError, match="data must be bytes"):
        loader.recover_javascript_env_assembly("not bytes")  # type: ignore[arg-type]
