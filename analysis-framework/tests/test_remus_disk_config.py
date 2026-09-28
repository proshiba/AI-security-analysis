"""検体を含めず、RET/NOPの無害PEと暗号数式でon-disk抽出境界を試験する。"""

from __future__ import annotations
import ast
import hashlib
import json
from pathlib import Path
import struct
import sys

import pytest

REPOSITORY = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(REPOSITORY),
    str(REPOSITORY / "analysis-framework"),
    str(REPOSITORY / "analysis-framework" / "common"),
    str(Path(__file__).parent),
]
import remus_disk_config as disk  # noqa: E402

RVAS = {
    "copy": 0x1000,
    "initializer": 0x1300,
    "stream": 0x1800,
    "caller": 0x2100,
    "http": 0x2200,
    "transport": 0x4000,
    "selector": 0x5000,
    "assign": 0x6000,
}
KEY = hashlib.sha256(b"harmless-fixture-key").digest()
NONCE = b"test1234"
URIS = ("http://first.example:8080/a", "https://second.example/b", "http://third.example:9090/c")


def _pe(text, rdata, data):
    headers = bytearray(0x200)
    headers[:2] = b"MZ"
    struct.pack_into("<I", headers, 0x3C, 0x80)
    headers[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", headers, 0x84, 0x8664, 3, 0, 0, 0, 0xF0, 0x22)
    optional = 0x98
    struct.pack_into("<H", headers, optional, 0x20B)
    struct.pack_into("<I", headers, optional + 16, 0x1000)
    struct.pack_into("<Q", headers, optional + 24, 0x140000000)
    struct.pack_into("<II", headers, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", headers, optional + 56, 0xC000, 0x200)
    struct.pack_into("<I", headers, optional + 108, 16)
    raw = bytearray()
    for i, (name, rva, flags, content) in enumerate(
        (
            (b".text", 0x1000, 0x60000020, text),
            (b".rdata", 0x9000, 0x40000040, rdata),
            (b".data", 0xB000, 0xC0000040, data),
        )
    ):
        size = (len(content) + 511) & ~511
        struct.pack_into(
            "<8sIIIIIIHHI",
            headers,
            optional + 0xF0 + 40 * i,
            name,
            len(content),
            rva,
            size,
            0x200 + len(raw),
            0,
            0,
            0,
            0,
            flags,
        )
        raw += content + b"\0" * (size - len(content))
    return bytes(headers + raw)


def _fixture(
    *,
    key=KEY,
    nonce=NONCE,
    mask=0x6D,
    xor_base=0x11111111,
    xor_multiplier=0x22222222,
    key_rva=0x9100,
    nonce_rva=0x9120,
    cipher_rva=0x9130,
    state_rva=0xB100,
    url_rva=0xB180,
    selector_rva=0xB010,
    uris=URIS,
):
    text = bytearray(b"\x90" * 0x7000)
    rdata = bytearray(0x1000)
    writable = bytearray(0x1000)

    def put(rva, value):
        text[rva - 0x1000 : rva - 0x1000 + len(value)] = value

    def rip(rva, opcode, target):
        put(rva, opcode + struct.pack("<i", target - (rva + len(opcode) + 4)))

    def call(rva, target):
        put(rva, b"\xe8" + struct.pack("<i", target - (rva + 5)))

    for kind, size in disk.PROFILE_SIZES.items():
        put(RVAS[kind] + size - 1, b"\xc3")
    put(RVAS["initializer"] + 0x10, b"\x01\xd8")
    put(RVAS["stream"] + 0x20, b"\x31\xd1\x05\x11\x22\x33\x44")
    put(RVAS["stream"] + 0x30, b"\x83\xc1\x01")
    call(RVAS["stream"] + 0x40, RVAS["copy"])
    start = RVAS["caller"]
    put(start, b"\x48\x83\xec\x28")
    rip(start + 4, b"\x48\x8d\x0d", state_rva)
    rip(start + 11, b"\x48\x8d\x15", key_rva)
    rip(start + 18, b"\x4c\x8d\x05", nonce_rva)
    put(start + 25, b"\x45\x31\xc9")
    call(start + 28, RVAS["initializer"])
    put(start + 33, b"\xb0\x01\x48\x83\xc4\x28\xc3")
    s = RVAS["selector"]
    put(s + 0x11, b"\x80\xe2" + bytes([mask ^ 255]))
    put(s + 0x18, b"\x04" + bytes([mask]))
    rip(s + 0xBF, b"\x0f\xb6\x05", selector_rva)
    put(s + 0xC6, b"\x83\xf0" + bytes([mask]) + b"\xc1\xe0\x06")
    rip(s + 0xCC, b"\x48\x8d\x15", cipher_rva)
    put(s + 0xD3, b"\x48\x01\xc2")
    rip(s + 0xD6, b"\x48\x8d\x0d", state_rva)
    put(s + 0xDD, b"\x4c\x8d\x84\x24\x10\x01\x00\x00")
    call(s + 0xE5, RVAS["stream"])
    put(s + 0xFC, b"\xb8" + struct.pack("<I", xor_base))
    put(s + 0x125, b"\x69\xc9" + struct.pack("<I", xor_multiplier))
    rip(s + 0x183, b"\x48\x8d\x0d", url_rva)
    call(s + 0x19A, RVAS["assign"])
    rip(s + 0x1EB, b"\x48\x8d\x15", 0x9400)
    rip(s + 0x39F, b"\x48\x8d\x0d", 0x9500)
    call(s + 0x43A, RVAS["http"])
    rip(s + 0x52B, b"\x48\x8d\x05", url_rva)
    rip(s + 0x5D7, b"\x48\x8d\x05", url_rva)
    t = RVAS["transport"]
    call(t + 0x5A, s)
    call(t + 0xE6, s)
    rip(t + 0x81, b"\x48\x8d\x3d", url_rva)
    call(t + 0x2F6, RVAS["http"])
    put(t + 0xCE, b"\x24" + bytes([((mask & 254) * 2) & 255]))
    put(t + 0xD2, b"\xb0" + bytes([(~mask) & 127]))
    put(t + 0xD6, b"\x24" + bytes([mask]))
    put(t + 0xD8, b"\x80\xc1" + bytes([mask]))
    put(t + 0xDB, b"\x80\xe1" + bytes([mask ^ 255]))
    writable[selector_rva - 0xB000] = mask
    struct.pack_into("<Q", writable, 0x20, 0x140000000 + RVAS["http"] + 0x100)
    rdata[key_rva - 0x9000 : key_rva - 0x9000 + 32] = key
    rdata[nonce_rva - 0x9000 : nonce_rva - 0x9000 + 8] = nonce
    plain = b"".join((u.encode("ascii") + b"\0").ljust(64, b"\0") for u in uris)
    xor_key = struct.pack("<I", xor_base ^ xor_multiplier)
    intermediate = bytes(v ^ xor_key[i % 4] for i, v in enumerate(plain))
    rdata[cipher_rva - 0x9000 : cipher_rva - 0x9000 + 192] = disk._chacha_slots(intermediate, key, nonce)
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_call",
            "params": [{"to": "0x" + "1" * 40, "data": "0x11223344"}, "latest"],
        },
        separators=(",", ":"),
    ).encode()
    assert len(body) == 136
    body = body + b"\0"
    rdata[0x400 : 0x400 + 137] = bytes(v ^ (((i + 1) * 0x2C) & 255) for i, v in enumerate(body))
    wide = ("https://rpc.example.net/o" + "\0").encode("utf-16le").ljust(52, b"\0")
    encrypted = b"".join(
        struct.pack("<H", v ^ (((i + 1) * 0xCF71) & 65535)) for i, v in enumerate(struct.unpack("<26H", wide))
    )
    assert encrypted[-4:] == struct.pack("<I", 0x117A4266)
    rdata[0x500:0x530] = encrypted[:48]
    return _pe(bytes(text), bytes(rdata), bytes(writable))


@pytest.fixture(autouse=True)
def _allow_only_harmless_fixture_shape(monkeypatch):
    data = _fixture()
    image = disk._pe_sections(data)
    profiles = {k: disk._profile_digest(data, image, RVAS[k], k)[0] for k in disk.PROFILE_SIZES}
    profiles["dispatch_data"] = disk._dispatch_digest(data, image, 0xB010)
    monkeypatch.setattr(disk, "VERIFIED_CODE_PROFILE", profiles)


def test_synthetic_recovery_and_role_boundaries():
    result = disk.extract_remus_disk_config(_fixture())
    assert [e["uri"] for e in result["config"]["endpoints"]] == list(URIS)
    assert [e["counter"] for e in result["config"]["endpoints"]] == [0, 1, 2]
    assert result["config"]["resolver"]["role"] == "blockchain_c2_resolver_not_c2"
    assert result["config"]["resolver"]["final_c2_recovered"] is False
    assert result["family_attribution_confirmed"] is False
    assert result["c2_liveness_confirmed"] is False
    assert result["safety"]["sample_executed"] is False


def test_normal_extractor_integrates_disk_config_without_family_or_live_promotion(monkeypatch):
    from extractors.remusstealer import extractor

    module = extractor._load_common_module("remus_disk_config")
    monkeypatch.setattr(module, "VERIFIED_CODE_PROFILE", disk.VERIFIED_CODE_PROFILE)
    result = extractor.extract(_fixture(), "harmless-native.bin")
    config = result["config"]
    assert config["static_config_recovered"] is True
    assert config["family_attribution_confirmed"] is False
    assert result["supports_family_attribution"] is False
    assert result["terminal_family_confirmed"] is False
    assert result["attribution_scope"] == "component_handler_route"
    assert config["c2_liveness_confirmed"] is False
    assert config["urls"] == list(URIS)
    assert config["endpoints"] == ["first.example:8080", "second.example:443", "third.example:9090"]
    assert "rpc.example.net" not in " ".join(config["endpoints"])
    assert config["resolvers"][0]["role"] == "blockchain_c2_resolver_not_c2"
    assert config["protocol_analysis"]["confirmed_c2"] == []
    assert config["protocol_analysis"]["terminal_protocol_recovered"] is False
    assert config["protocol_analysis"]["active_profile_generation"]["status"] == "blocked"
    assert result["executed"] is False and result["network_contacted"] is False


def test_normal_extractor_keeps_nonmatching_input_conservative():
    from extractors.remusstealer import extractor

    result = extractor.extract(b"harmless document with https://www.example.org/", "plain.txt")
    assert result["config"]["static_config_recovered"] is False
    assert "disk_config_analysis" not in result["config"]


def test_normal_extractor_does_not_silently_drop_timeout(monkeypatch):
    from extractors.remusstealer import extractor

    module = extractor._load_common_module("remus_disk_config")
    monkeypatch.setattr(extractor, "_terminal_memory_report", lambda _: None)

    def timeout(_):
        raise module.RemusDiskConfigLimitError("wall_seconds", 9.0, 8.0)

    monkeypatch.setattr(module, "extract_remus_disk_config", timeout)
    with pytest.raises(module.RemusDiskConfigLimitError):
        extractor.extract(_fixture(), "harmless-native.bin")


def test_changed_key_nonce_xor_mask_and_relocated_data():
    result = disk.extract_remus_disk_config(
        _fixture(
            key=hashlib.sha256(b"new-key").digest(),
            nonce=b"changed!",
            mask=0x35,
            xor_base=0x12345678,
            xor_multiplier=0x87654321,
            key_rva=0x9600,
            nonce_rva=0x9620,
            cipher_rva=0x9630,
            state_rva=0xB300,
            url_rva=0xB380,
            selector_rva=0xB080,
        )
    )
    assert [e["uri"] for e in result["config"]["endpoints"]] == list(URIS)
    assert result["config"]["evidence"]["selector_xor_mask"] == 0x35
    assert result["config"]["evidence"]["cipher_rva"] == 0x9630


def test_overlay_is_ignored():
    assert disk.extract_remus_disk_config(_fixture() + b"not-a-payload" * 100)["status"] == "extracted"


@pytest.mark.parametrize(
    "rva,before,after",
    [
        (0x1310, b"\x01\xd8", b"\x29\xd8"),
        (0x1820, b"\x31\xd1", b"\x09\xd1"),
        (0x1822, b"\x05\x11\x22\x33\x44", b"\x05\x11\x22\x33\x45"),
        (0x1830, b"\x83\xc1\x01", b"\x83\xc1\x02"),
        (0x1000, b"\x90", b"\xcc"),
        (0x5000, b"\x90", b"\xcc"),
        (0x6000, b"\x90", b"\xcc"),
        (0x2200, b"\x90", b"\xcc"),
    ],
)
def test_arithmetic_callee_and_sink_mutations_fail_closed(rva, before, after):
    data = bytearray(_fixture())
    image = disk._pe_sections(bytes(data))
    offset = image.get_offset_from_rva(rva)
    assert bytes(data[offset : offset + len(before)]) == before
    data[offset : offset + len(after)] = after
    with pytest.raises(disk.RemusDiskConfigError):
        disk.extract_remus_disk_config(bytes(data))


def test_dispatch_pointer_mutation_is_not_hidden_by_code_normalization():
    data = bytearray(_fixture())
    image = disk._pe_sections(bytes(data))
    offset = image.get_offset_from_rva(0xB020)
    data[offset] ^= 1
    with pytest.raises(disk.RemusDiskConfigError):
        disk.extract_remus_disk_config(bytes(data))


def test_changed_core_call_target_requires_verified_callee_shape():
    data = bytearray(_fixture())
    image = disk._pe_sections(bytes(data))
    rva = 0x1840
    struct.pack_into("<i", data, image.get_offset_from_rva(rva) + 1, 0x6000 - (rva + 5))
    with pytest.raises(disk.RemusDiskConfigError):
        disk.extract_remus_disk_config(bytes(data))


def test_rotation_mutation_is_rejected_even_with_variable_parameter():
    data = bytearray(_fixture())
    image = disk._pe_sections(bytes(data))
    offset = image.get_offset_from_rva(0x40D3)
    data[offset] ^= 1
    with pytest.raises(disk.RemusDiskConfigError):
        disk.extract_remus_disk_config(bytes(data))


def test_initial_selector_nonzero_is_not_misinterpreted_as_counter_zero():
    data = bytearray(_fixture())
    image = disk._pe_sections(bytes(data))
    offset = image.get_offset_from_rva(0xB010)
    data[offset] ^= 1
    with pytest.raises(disk.RemusDiskConfigError):
        disk.extract_remus_disk_config(bytes(data))


def test_credentials_are_rejected_and_query_fragment_are_removed():
    with pytest.raises(disk.RemusDiskConfigError):
        disk.extract_remus_disk_config(_fixture(uris=("http://user:pass@first.example/a", *URIS[1:])))
    result = disk.extract_remus_disk_config(_fixture(uris=("http://first.example/a?secret=value#private", *URIS[1:])))
    assert result["config"]["endpoints"][0]["uri"] == "http://first.example/a"
    assert "secret=value" not in json.dumps(result)


def test_raw_crypto_values_are_not_in_report():
    report = json.dumps(disk.extract_remus_disk_config(_fixture()))
    assert KEY.hex() not in report and NONCE.hex() not in report


def test_non_pe_and_input_limit_are_rejected(monkeypatch):
    with pytest.raises(disk.RemusDiskConfigError):
        disk.extract_remus_disk_config(b"harmless text")
    monkeypatch.setattr(disk, "MAX_INPUT_BYTES", 128)
    with pytest.raises(disk.RemusDiskConfigError):
        disk.extract_remus_disk_config(_fixture())


def test_timeout_is_explicit_not_silent_nonmatch(monkeypatch):
    data = _fixture()
    calls = iter([0.0, 9.0, 9.0])
    monkeypatch.setattr(disk.time, "monotonic", lambda: next(calls))
    with pytest.raises(disk.RemusDiskConfigLimitError) as error:
        disk.extract_remus_disk_config(data)
    assert error.value.constraint == "wall_seconds"


def _reviewed_shape(source, key):
    """危険なコードを実行せず、AST上の局所許可だけを確認する。"""
    import handler_catalog as catalog

    tree = ast.parse(source)
    scope = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == key[1][10:])
    call = next(
        node for node in ast.walk(scope) if isinstance(node, ast.Call) and catalog._ast_call_name(node.func) == key[2]
    )
    return catalog._reviewed_source_call_shape_allowed(
        call, key[2], tree, scope, catalog._import_aliases(tree), key=key
    )


@pytest.mark.parametrize(
    "mode,read_expression,extra_binding,expected",
    [
        ("capstone.CS_MODE_64", "_read(data, image, rva, size, executable=True)", "", True),
        ("capstone.CS_MODE_32", "_read(data, image, rva, size, executable=True)", "", False),
        ("mode", "_read(data, image, rva, size, executable=True)", "", False),
        ("capstone.CS_MODE_64", "data", "", False),
        ("capstone.CS_MODE_64", "_read(data, image, rva, size, executable=False)", "", False),
        ("capstone.CS_MODE_64", "_read(data, image, rva, size, executable=True)", "    machine = data\n", False),
        ("capstone.CS_MODE_64", "_read(data, image, rva, size, executable=True)", "    data = b'changed'\n", False),
        ("capstone.CS_MODE_64", "_read(data, image, rva, size, executable=True)", "    capstone.Cs = data\n", False),
    ],
)
def test_capstone_review_requires_fixed_mode_and_bounded_origin(mode, read_expression, extra_binding, expected):
    key = ("analysis-framework/common/remus_disk_config.py", "reachable:_instructions", "machine.disasm")
    source = (
        "import capstone\n"
        "def _instructions(data, image, rva, size):\n"
        f"    raw = {read_expression}\n"
        f"    machine = capstone.Cs(capstone.CS_ARCH_X86, {mode})\n"
        f"{extra_binding}"
        "    return list(machine.disasm(raw, rva))\n"
    )
    assert _reviewed_shape(source, key) is expected


@pytest.mark.parametrize(
    "loader,argument,extra_binding,expected",
    [
        ("'remus_disk_config'", "data", "", True),
        ("'remus_memory_config'", "data", "", False),
        ("data", "data", "", False),
        ("'remus_disk_config'", "b'other'", "", False),
        ("'remus_disk_config'", "data", "    module = data\n", False),
        ("'remus_disk_config'", "data", "    data = b'other'\n", False),
    ],
)
def test_disk_review_requires_exact_loader_and_input(loader, argument, extra_binding, expected):
    key = (
        "extractors/remusstealer/extractor.py",
        "reachable:_terminal_disk_report",
        "module.extract_remus_disk_config",
    )
    source = (
        "def _terminal_disk_report(data):\n"
        f"    module = _load_common_module({loader})\n"
        f"{extra_binding}"
        f"    return module.extract_remus_disk_config({argument})\n"
    )
    assert _reviewed_shape(source, key) is expected


@pytest.mark.parametrize("context", ["_candidate", "extract_remus_disk_config"])
@pytest.mark.parametrize(
    "argument,extra_binding,expected",
    [("", "", True), ("1", "", False), ("", "    time.monotonic = data\n", False)],
)
def test_monotonic_review_rejects_arguments_and_rebinding(context, argument, extra_binding, expected):
    key = ("analysis-framework/common/remus_disk_config.py", "reachable:" + context, "time.monotonic")
    source = f"import time\ndef {context}(data):\n{extra_binding}    return time.monotonic({argument})\n"
    assert _reviewed_shape(source, key) is expected


def test_reviewed_calls_are_not_broadly_allowed():
    import handler_catalog as catalog

    keys = [
        ("analysis-framework/common/remus_disk_config.py", "reachable:_instructions", "machine.disasm"),
        ("analysis-framework/common/remus_disk_config.py", "reachable:_candidate", "time.monotonic"),
        ("analysis-framework/common/remus_disk_config.py", "reachable:extract_remus_disk_config", "time.monotonic"),
        ("extractors/remusstealer/extractor.py", "reachable:_terminal_disk_report", "module.extract_remus_disk_config"),
    ]
    for key in keys:
        assert key in catalog._REVIEWED_SOURCE_CALLS
        assert ("extractors/other/extractor.py", *key[1:]) not in catalog._REVIEWED_SOURCE_CALLS
        assert (key[0], "reachable:other_function", key[2]) not in catalog._REVIEWED_SOURCE_CALLS
        assert key[2] not in catalog._APPROVED_EXTERNAL_CALLS


def test_ordinary_preflight_accepts_scoped_static_dependencies():
    import handler_catalog as catalog

    catalog.clear_handler_caches()
    spec = next(item for item in catalog.discover_handlers() if item.family == "remusstealer" and item.automatic)
    try:
        result = catalog.preflight_handler_for_assessment(spec, actual_format="pe", input_size=1024)
    finally:
        catalog.clear_handler_caches()
    assert result["eligible"], result["blockers"]
    assert result["sample_execution_allowed"] is False
    assert result["network_allowed"] is False
    assert result["filesystem_write_allowed"] is False


def test_ordinary_supervised_handler_rejects_unmatched_harmless_fixture():
    import handler_catalog as catalog

    spec = next(item for item in catalog.discover_handlers() if item.family == "remusstealer" and item.automatic)
    bounded = catalog.execute_handler_bounded_for_assessment(
        spec, b"MZ\0harmless fixture", "harmless.bin", actual_format="pe"
    )
    assert bounded["status"] == "completed", bounded["preflight"]["blockers"]
    result = bounded["execution"]["result"]
    assert result["config"]["static_config_recovered"] is False
    assert result["config"].get("candidate_infrastructure", False) is False
    assert bounded["execution"]["executed_sample"] is False
    assert bounded["execution"]["network_contacted"] is False


@pytest.mark.parametrize(
    "offset,format_code,value",
    [
        (0x84, "H", 0x14C),
        (0x98, "H", 0x10B),
        (0x98 + 16, "I", 0xC010),
        (0x98 + 16, "I", 0x9100),
        (0x98 + 56, "I", 0x2000000),
        (0x98 + 60, "I", 0xFFFFFFFF),
        (0x98 + 0xF0 + 40 + 12, "I", 0x1100),
        (0x98 + 0xF0 + 40 + 20, "I", 0x300),
        (0x98 + 0xF0 + 40 + 20, "I", 0x100),
        (0x98 + 0xF0 + 40 + 20, "I", 0xFFFFFFFF),
    ],
)
def test_pe_machine_entry_header_and_section_mutations_are_rejected(offset, format_code, value):
    data = bytearray(_fixture())
    struct.pack_into("<" + format_code, data, offset, value)
    with pytest.raises(disk.RemusDiskConfigError):
        disk._pe_sections(bytes(data))


def test_raw_read_and_section_limits_are_not_weakening(monkeypatch):
    data = _fixture()
    image = disk._pe_sections(data)
    for rva, size, executable in [(0x8FFF, 2, False), (0x20000, 1, False), (0xB010, 1, True), (0x1000, 0, True)]:
        with pytest.raises(disk.RemusDiskConfigError):
            disk._read(data, image, rva, size, executable=executable)
    monkeypatch.setattr(disk, "MAX_CODE_BYTES", 8)
    with pytest.raises(disk.RemusDiskConfigError):
        disk._pe_sections(data)


def test_validated_detector_routes_without_confirming_family():
    from malware.remusstealer.detect import detect
    from classifiers.classify_sample import detection_supports_family_attribution

    result = detect(_fixture(), Path("harmless-native.bin"))
    assert result["matched"] is True
    assert result["supports_family_attribution"] is False
    assert detection_supports_family_attribution(result) is False
    assert result["campaigns"][0]["attribution_scope"] == "handler_route_only"
    assert result["observations"]["c2_setting_slot_count"] == 3
    assert result["observations"]["family_attribution_confirmed"] is False
    assert result["observations"]["resolver_final_c2_recovered"] is False


def test_detector_rejects_shape_mutation_and_plain_uris():
    from malware.remusstealer.detect import detect

    data = bytearray(_fixture())
    image = disk._pe_sections(bytes(data))
    data[image.get_offset_from_rva(RVAS["http"])] ^= 1
    assert detect(bytes(data), Path("harmless-mutated.bin"))["matched"] is False
    data = _pe(b"\xc3" + b"https://first.example/a", b"RemusStealer", b"not-code-profile")
    assert detect(data, Path("harmless-strings.bin"))["matched"] is False


def test_detector_keeps_timeout_as_visible_unmatched_limit(monkeypatch):
    from malware.remusstealer.detect import detect

    def timeout(_):
        raise disk.RemusDiskConfigLimitError("wall_seconds", 9.0, 8.0)

    monkeypatch.setattr(disk, "extract_remus_disk_config", timeout)
    result = detect(_fixture(), Path("harmless-native.bin"))
    assert result["matched"] is False
    assert result["observations"]["static_route_status"] == "limit_exceeded"
    assert result["supports_family_attribution"] is False


def test_classifier_keeps_route_only_as_unknown_but_schedules_verification():
    from classifiers import classify_sample
    from malware.remusstealer.detect import detect

    data = _fixture()
    digest = hashlib.sha256(data).hexdigest()
    evaluation = {
        "malware_type": "remusstealer",
        "detector": "malware/remusstealer/detect.py",
        "known_outer_sha256": False,
        "known_inner_sha256": False,
        "known_routing_sha256": False,
        "detector_matched": True,
        "applicable": True,
        "automatic_route_eligible": True,
        "supports_family_attribution": False,
        "error": None,
        "detection": detect(data, Path("harmless-native.bin")),
    }
    classification = classify_sample._classify_evaluations(
        Path("harmless-native.bin"),
        {"sha256": digest, "size": len(data), "detector_errors": {}, "evaluations": [evaluation]},
        None,
    )
    routing = classify_sample.build_family_routing_candidates(
        [{"layer": {"sha256": digest, "depth": 0}, "classification": classification}],
        family_coverage=[
            {
                "family": "remusstealer",
                "status": "automatic_handler_available",
                "detector_registered": True,
                "automatic_handlers": ["remusstealer.extract"],
                "manual_or_unsupported_handlers": [],
            }
        ],
    )
    assert classification["malware_type"] == "unknown"
    assert routing["selected_families"] == []
    assert routing["verification_only_families"] == ["remusstealer"]
    assert routing["candidates"][0]["routing_eligibility"]["family_attribution"] is False
    assert routing["candidates"][0]["routing_eligibility"]["candidate_verification"] is True
