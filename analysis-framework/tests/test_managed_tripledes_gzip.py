"""無害なPEと非実行CIL modelによる、16/24-byte静的resource復元試験。"""

import base64
import gzip
import struct
from copy import deepcopy
from types import SimpleNamespace

import pytest
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from unpackers import managed_tripledes_gzip as recovery


def _payload():
    image = bytearray(0x400)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", image, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
    struct.pack_into("<H", image, 0x98, 0x20B)
    struct.pack_into("<I", image, 0x98 + 16, 0x1000)
    struct.pack_into("<Q", image, 0x98 + 24, 0x400000)
    struct.pack_into("<II", image, 0x98 + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, 0x98 + 56, 0x2000, 0x200)
    struct.pack_into("<I", image, 0x98 + 108, 16)
    struct.pack_into("<II", image, 0x98 + 112 + 14 * 8, 0x1100, 0x48)
    section = 0x98 + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    image[0x200] = 0xC3
    struct.pack_into("<IHHIII", image, 0x300, 0x48, 2, 5, 0x1180, 32, 1)
    image[0x380:0x384] = b"BSJB"
    # fileを実行・CLR loadできるようにする試験ではない。PE/CLR境界だけを検証する。
    return bytes(image)


def _fixture(key_size=24, name="harmless.resource", local_base=0, crypto_stream=False, clear=None):
    key, iv = bytes(range(1, key_size + 1)), b"12345678"
    payload = _payload()
    if clear is None:
        clear = struct.pack("<i", len(payload)) + gzip.compress(payload, mtime=0)
    pad = 8 - len(clear) % 8
    effective_key = key + key[:8] if len(key) == 16 else key
    encryptor = Cipher(TripleDES(effective_key), modes.CBC(iv)).encryptor()
    encrypted = encryptor.update(clear + bytes([pad]) * pad) + encryptor.finalize()
    il = []

    def add(opcode, operand="None", ref=None, string=None, parameter_count=None):
        item = {
            "offset": len(il),
            "opcode": opcode,
            "operand": str(operand),
            "resolved_token": ref,
            "parameter_count": parameter_count,
        }
        if string is not None:
            item["string"] = string
        il.append(item)

    def load(n):
        add("ldloc.s", f"local(0x{n + local_base:04x})")

    def store(n):
        add("stloc.s", f"local(0x{n + local_base:04x})")

    def number(n):
        add("ldc.i4", n)

    def call(ref, opcode="callvirt", argc=None):
        add(opcode, ref=ref, parameter_count=argc)

    add("ldstr", string=name)
    call("System.Reflection.Assembly::GetManifestResourceStream")
    store(5)
    load(5)
    call("System.IO.Stream::get_Length")
    add("conv.ovf.i")
    add("newarr", ref="System.Byte")
    store(0)
    load(5)
    load(0)
    number(0)
    load(0)
    add("ldlen")
    add("conv.i4")
    call("System.IO.Stream::Read")
    add("pop")
    for value, variable in [(key, 1), (iv, 2)]:
        add("ldstr", string=base64.b64encode(value).decode())
        call("System.Convert::FromBase64String", "call")
        store(variable)
    call("System.Security.Cryptography.TripleDES::Create", "call")
    store(6)
    for variable, setting in [(1, "Key"), (2, "IV")]:
        load(6)
        load(variable)
        call("System.Security.Cryptography.SymmetricAlgorithm::set_" + setting)
    for value, setting in [(1, "Mode"), (2, "Padding")]:
        load(6)
        number(value)
        call("System.Security.Cryptography.SymmetricAlgorithm::set_" + setting)
    load(6)
    call("System.Security.Cryptography.SymmetricAlgorithm::CreateDecryptor")
    store(7)
    if crypto_stream:
        load(0)
        call("System.IO.MemoryStream::.ctor", "newobj", 1)
        store(13)
        load(13)
        load(7)
        number(0)
        call("System.Security.Cryptography.CryptoStream::.ctor", "newobj", 3)
        store(14)
        call("System.IO.MemoryStream::.ctor", "newobj", 0)
        store(15)
        load(14)
        load(15)
        call("System.IO.Stream::CopyTo", argc=1)
        load(15)
        call("System.IO.MemoryStream::ToArray")
        store(3)
    else:
        load(7)
        load(0)
        number(0)
        load(0)
        add("ldlen")
        add("conv.i4")
        call("System.Security.Cryptography.ICryptoTransform::TransformFinalBlock")
        store(3)
    load(3)
    number(4)
    load(3)
    add("ldlen")
    add("conv.i4")
    number(4)
    add("sub")
    call("System.IO.MemoryStream::.ctor", "newobj", 3)
    store(8)
    load(8)
    number(0)
    call("System.IO.Compression.GZipStream::.ctor", "newobj", 2)
    store(9)
    call("System.IO.MemoryStream::.ctor", "newobj", 0)
    store(10)
    number(4096)
    add("newarr", ref="System.Byte")
    store(11)
    jump_at = len(il)
    add("br.s", "pending")
    write_at = len(il)
    load(10)
    load(11)
    number(0)
    load(12)
    call("System.IO.Stream::Write")
    read_at = len(il)
    load(9)
    load(11)
    number(0)
    load(11)
    add("ldlen")
    add("conv.i4")
    call("System.IO.Stream::Read")
    add("dup")
    store(12)
    number(0)
    add("bgt.s", write_at)
    il[jump_at]["operand"] = str(read_at)
    load(10)
    call("System.IO.MemoryStream::ToArray")
    store(4)
    load(4)
    call("System.Reflection.Assembly::Load", "call")
    add("pop")
    add("ret")
    return (
        payload,
        encrypted,
        {"token": 0x06000001, "rva": 0x2000, "instructions": il},
        name,
    )


@pytest.mark.parametrize("key_size", [16, 24])
@pytest.mark.parametrize("name", ["harmless.resource", "renamed.payload.blob"])
@pytest.mark.parametrize("local_base", [0, 80])
@pytest.mark.parametrize("crypto_stream", [False, True])
def test_recovers_both_key_sizes_by_local_dataflow(key_size, name, local_base, crypto_stream):
    payload, encrypted, method, resource = _fixture(key_size, name, local_base, crypto_stream)
    report, artifacts = recovery.recover_model(b"harmless-parent", [method], {resource: encrypted})
    assert report["status"] == "recovered", report
    assert artifacts == [("managed-tripledes-gzip-pe", payload)]
    assert report["key_size"] == key_size
    assert report["transform_kind"] == ("CryptoStream_Read_CopyTo" if crypto_stream else "TransformFinalBlock")
    assert report["normal_cfg_dominance_verified"] is True
    assert report["sample_executed"] is False and report["clr_loaded"] is False
    assert report["family_attribution_allowed"] is False
    assert report["c2_confirmation_allowed"] is False
    assert report["terminal_promotion_eligible"] is False
    assert "key" not in report and "iv" not in report


@pytest.mark.parametrize(
    "mutation",
    ["unknown_key", "wrong_mode", "no_sink", "alias", "array_mutation", "skip_recipe"],
)
def test_rejects_unproven_or_skippable_dataflow(mutation):
    _, encrypted, method, resource = _fixture()
    il = method["instructions"]
    if mutation == "unknown_key":
        next(i for i in il if i.get("resolved_token") == "System.Convert::FromBase64String")["resolved_token"] = (
            "Untrusted::DynamicKey"
        )
    elif mutation == "wrong_mode":
        at = next(
            n
            for n, i in enumerate(il)
            if i.get("resolved_token") == "System.Security.Cryptography.SymmetricAlgorithm::set_Mode"
        )
        il[at - 1]["operand"] = "2"
    elif mutation == "no_sink":
        next(i for i in il if i.get("resolved_token") == "System.Reflection.Assembly::Load")["resolved_token"] = (
            "System.Object::ToString"
        )
    elif mutation == "alias":
        il[-1] = {
            "offset": il[-1]["offset"],
            "opcode": "stloc.s",
            "operand": "local(0x0001)",
            "resolved_token": None,
        }
    elif mutation == "array_mutation":
        il[-1]["opcode"] = "stelem.i1"
    elif mutation == "skip_recipe":
        sink = next(i["offset"] for i in il if i.get("resolved_token") == "System.Reflection.Assembly::Load")
        il[0] = {
            "offset": 0,
            "opcode": "br.s",
            "operand": str(sink),
            "resolved_token": None,
        }
        # literal resourceは生かして無条件branchだけ先頭に挿入する。
        il.insert(
            0,
            {
                "offset": -1,
                "opcode": "br.s",
                "operand": str(sink),
                "resolved_token": None,
            },
        )
        il[1] = {
            "offset": 0,
            "opcode": "ldstr",
            "operand": "None",
            "resolved_token": None,
            "string": resource,
        }
    report, artifacts = recovery.recover_model(b"harmless-parent", [method], {resource: encrypted})
    assert report["status"] == "rejected", report
    assert not artifacts


def test_bad_padding_and_invalid_child_do_not_return_bytes():
    _, encrypted, method, resource = _fixture()
    changed = encrypted[:-8] + bytes(8)
    report, artifacts = recovery.recover_model(b"parent", [method], {resource: changed})
    assert report["status"] == "rejected" and not artifacts
    clear = struct.pack("<i", 100) + gzip.compress(bytes(100), mtime=0)
    _, encrypted, method, resource = _fixture(clear=clear)
    report, artifacts = recovery.recover_model(b"parent", [method], {resource: encrypted})
    assert report["reason"] == "decoded_managed_pe_invalid" and not artifacts


@pytest.mark.parametrize("mutation", ["declared_length", "trailing_bytes", "multiple_streams", "overlimit"])
def test_gzip_length_eof_and_output_limit(mutation):
    payload = _payload()
    compressed = gzip.compress(payload, mtime=0)
    length = len(payload)
    if mutation == "declared_length":
        length += 1
    elif mutation == "trailing_bytes":
        compressed += b"unexpected"
    elif mutation == "multiple_streams":
        compressed += compressed
    elif mutation == "overlimit":
        length = recovery.MAX_OUTPUT + 1
    _, encrypted, method, resource = _fixture(clear=struct.pack("<i", length) + compressed)
    report, artifacts = recovery.recover_model(b"parent", [method], {resource: encrypted})
    assert report["status"] == "rejected" and not artifacts


def test_multiple_recipes_and_method_budget_are_rejected(monkeypatch):
    _, encrypted, method, resource = _fixture()
    report, artifacts = recovery.recover_model(b"parent", [method, deepcopy(method)], {resource: encrypted})
    assert report["reason"] == "multiple_resource_recipes" and not artifacts
    monkeypatch.setattr(recovery, "MAX_METHODS", 0)
    report, artifacts = recovery.recover_model(b"parent", [method], {resource: encrypted})
    assert report["reason"] == "input_or_method_limit" and not artifacts


def test_normal_data_with_no_crypto_recipe_is_not_promoted():
    report, artifacts = recovery.recover_managed_tripledes_gzip(b"ordinary data")
    assert report["status"] == "not_candidate" and not artifacts


@pytest.mark.parametrize(
    "mutation",
    [
        "extra_array_alias",
        "local_address_alias",
        "duplicate_offsets",
        "bad_constructor",
    ],
)
def test_unknown_extra_uses_and_malformed_metadata_fail_closed(mutation):
    _, encrypted, method, resource = _fixture()
    il = method["instructions"]
    if mutation in {"extra_array_alias", "local_address_alias"}:
        at = next(n for n, i in enumerate(il) if i.get("resolved_token") == "System.Reflection.Assembly::Load") - 1
        il.insert(
            at,
            {
                "offset": 500,
                "opcode": "ldloca.s" if mutation == "local_address_alias" else "ldloc.s",
                "operand": "local(0x0003)",
                "resolved_token": None,
            },
        )
    elif mutation == "duplicate_offsets":
        il[-1]["offset"] = il[-2]["offset"]
    else:
        next(i for i in il if i.get("resolved_token") == "System.IO.Compression.GZipStream::.ctor")[
            "parameter_count"
        ] = 3
    report, artifacts = recovery.recover_model(b"parent", [method], {resource: encrypted})
    assert report["status"] == "rejected" and not artifacts


def test_elapsed_time_resource_instruction_and_input_limits(monkeypatch):
    _, encrypted, method, resource = _fixture()
    report, artifacts = recovery.recover_model(b"parent", [method], {resource: encrypted}, clock=lambda: 2, deadline=1)
    assert report["reason"] == "elapsed_time_limit" and not artifacts
    monkeypatch.setattr(recovery, "MAX_RESOURCE", len(encrypted) - 1)
    report, artifacts = recovery.recover_model(b"parent", [method], {resource: encrypted})
    assert report["reason"] == "ciphertext_bounds" and not artifacts
    monkeypatch.setattr(recovery, "MAX_RESOURCE", 4 << 20)
    monkeypatch.setattr(recovery, "MAX_METHOD_INSTRUCTIONS", 1)
    report, artifacts = recovery.recover_model(b"parent", [method], {resource: encrypted})
    assert report["reason"] == "method_instruction_limit" and not artifacts
    monkeypatch.setattr(recovery, "MAX_INPUT", 0)
    report, artifacts = recovery.recover_model(b"parent", [method], {resource: encrypted})
    assert report["reason"] == "input_or_method_limit" and not artifacts


def test_raw_span_rejects_virtual_only_and_overlapping_sections():
    from types import SimpleNamespace

    section = SimpleNamespace(VirtualAddress=0x1000, PointerToRawData=0, SizeOfRawData=16)
    assert recovery._raw_span(SimpleNamespace(sections=[section]), bytes(16), 0x1000, 16) == (0, 16)
    with pytest.raises(recovery.RecipeError):
        recovery._raw_span(SimpleNamespace(sections=[section]), bytes(16), 0x100F, 2)
    with pytest.raises(recovery.RecipeError):
        recovery._raw_span(SimpleNamespace(sections=[section, section]), bytes(16), 0x1000, 8)


@pytest.mark.parametrize(
    "blob",
    [
        b"",
        b"\x00",
        b"\x10\x01\x01\x01",
        b"\x00\x01\x01\x1d",
        b"\x00\x01\x01\x05\x00",
        b"\x00\x80\x7f\x01",
        b"\x00\x01\x12\x04\x05",
    ],
)
def test_malformed_or_untrusted_signature_is_not_interpreted(blob):
    assert recovery._signature(blob, {}) is None


def test_assembly_load_bytes_is_distinct_from_string_overload():
    references = {0x0100000A: "System.Reflection.Assembly"}
    byte_load = recovery._signature(bytes.fromhex("000112291d05"), references)
    string_load = recovery._signature(bytes.fromhex("000112290e"), references)
    assert byte_load in recovery._API_SIGNATURES["System.Reflection.Assembly::Load"]
    assert string_load not in recovery._API_SIGNATURES["System.Reflection.Assembly::Load"]


def test_loop_cannot_use_count_before_its_definition():
    _, encrypted, method, resource = _fixture()
    il = method["instructions"]
    jump = next(i for i in il if i["opcode"] == "br.s")
    write = next(n for n, i in enumerate(il) if i.get("resolved_token") == "System.IO.Stream::Write")
    jump["operand"] = str(il[write - 4]["offset"])
    report, artifacts = recovery.recover_model(b"parent", [method], {resource: encrypted})
    assert report["reason"] == "recipe_does_not_dominate_assembly_load" and not artifacts


def test_malformed_managed_metadata_returns_bounded_rejection():
    report, artifacts = recovery.recover_managed_tripledes_gzip(_payload())
    assert report["status"] == "rejected" and not artifacts
    assert report["reason"] == "invalid_managed_metadata"


def test_parser_deadline_and_method_count_limits(monkeypatch):
    from types import SimpleNamespace

    fake = SimpleNamespace(
        net=SimpleNamespace(mdtables=SimpleNamespace(MethodDef=SimpleNamespace(num_rows=recovery.MAX_METHODS + 1)))
    )
    monkeypatch.setattr(recovery.dnfile, "dnPE", lambda **kwargs: fake)
    report, artifacts = recovery.recover_managed_tripledes_gzip(_payload())
    assert report["reason"] == "method_count_limit" and not artifacts
    fake.net.mdtables.MethodDef.num_rows = 0
    ticks = iter([0, recovery.MAX_SECONDS + 1])
    report, artifacts = recovery.recover_managed_tripledes_gzip(_payload(), clock=lambda: next(ticks))
    assert report["status"] == "rejected" and not artifacts


def test_static_unpack_pipeline_forwards_only_verified_child(monkeypatch):
    from unpackers import static_unpacker

    child = _payload()
    marker = {
        "status": "recovered",
        "candidate_only": True,
        "family_attribution_allowed": False,
        "c2_confirmation_allowed": False,
    }
    monkeypatch.setattr(
        static_unpacker, "recover_managed_tripledes_gzip", lambda data: (marker, [("managed-tripledes-gzip-pe", child)])
    )
    parent = bytearray(child)
    parent[0x40] = 1
    report, artifacts = static_unpacker.unpack_bytes(bytes(parent), name="harmless.bin")
    assert report["managed_tripledes_gzip"] == marker
    assert ("managed-tripledes-gzip-pe", child) in artifacts
    assert report["executed"] is False and report["network_contacted"] is False


def _metadata_fixture(version=(4, 0, 0, 0)):
    """実行可能なassemblyではない、有界metadata宣言の合成fixture。"""
    def table(rows):
        return SimpleNamespace(rows=rows, num_rows=len(rows))

    def assembly(name):
        return SimpleNamespace(
            Name=name, Culture="", PublicKey=SimpleNamespace(value=bytes.fromhex("b77a5c561934e089")),
            struct=SimpleNamespace(Flags=0), MajorVersion=version[0], MinorVersion=version[1],
            BuildNumber=version[2], RevisionNumber=version[3],
        )

    assemblies = table([assembly("mscorlib"), assembly("System")])
    types = table([])
    members = table([])
    tables = SimpleNamespace(AssemblyRef=assemblies, TypeRef=types, MemberRef=members, MethodDef=table([]))
    type_tokens = {}
    for name in sorted(recovery._CLASSIC_TYPES):
        namespace, leaf = name.rsplit(".", 1)
        scope_rid = 2 if name in recovery._SYSTEM_TYPES else 1
        types.rows.append(SimpleNamespace(TypeNamespace=namespace, TypeName=leaf,
            ResolutionScope=SimpleNamespace(table=assemblies, row_index=scope_rid, row=assemblies.rows[scope_rid - 1])))
        type_tokens[name] = 0x01000000 | len(types.rows)
    types.num_rows = len(types.rows)

    def compressed(value):
        if value < 0x80:
            return bytes([value])
        return bytes([0x80 | (value >> 8), value & 0xFF])

    def signature_type(name):
        primitive = {"System.Void": 1, "System.Byte": 5, "System.Int32": 8,
                     "System.Int64": 10, "System.String": 14}
        if name.endswith("[]"):
            return b"\x1d" + signature_type(name[:-2])
        if name in primitive:
            return bytes([primitive[name]])
        code = 0x11 if name in recovery._VALUE_TYPES else 0x12
        return bytes([code]) + compressed(((type_tokens[name] & 0xFFFFFF) << 2) | 1)

    member_tokens = {}
    for name, signatures in sorted(recovery._API_SIGNATURES.items()):
        for has_this, returned, parameters in sorted(signatures):
            owner, leaf = name.split("::")
            owner_rid = type_tokens[owner] & 0xFFFFFF
            blob = bytes([0x20 if has_this else 0, len(parameters)]) + signature_type(returned)
            blob += b"".join(signature_type(parameter) for parameter in parameters)
            members.rows.append(SimpleNamespace(Name=leaf, Signature=SimpleNamespace(value=blob),
                Class=SimpleNamespace(table=types, row_index=owner_rid, row=types.rows[owner_rid - 1])))
            member_tokens[name, len(parameters)] = 0x0A000000 | len(members.rows)
    members.num_rows = len(members.rows)
    return SimpleNamespace(net=SimpleNamespace(mdtables=tables)), type_tokens, member_tokens


@pytest.mark.parametrize("version", [(2, 0, 0, 0), (4, 0, 0, 0)])
def test_classic_metadata_identity_and_complete_signatures(version):
    pe, types, members = _metadata_fixture(version)
    references, counts, diagnostic = recovery._framework_references(pe, 1, lambda: 0)
    assert references[types["System.Byte"]] == "System.Byte"
    for (name, count), token in members.items():
        if name == "System.IO.Stream::CopyTo" and version[0] == 2:
            assert token not in references
        else:
            assert references[token] == name
            assert counts[token] == count
    assert diagnostic["metadata_complete"] is True
    assert diagnostic["runtime_assembly_integrity_verified"] is False
    assert diagnostic["runtime_dispatch_verified"] is False
    assert diagnostic["side_effect_free_verified"] is False
    assert diagnostic["nonthrowing_verified"] is False


@pytest.mark.parametrize("mutation", [
    "mscorlib_fake_pair", "system_fake_pair", "full_key", "full_key_flag", "culture", "flags",
    "version", "modern_facade", "forward_scope", "foreign_table", "bad_scope_rid",
    "fake_return_owner", "return_version", "enum_as_class", "generic", "extra_parameter",
    "noncanonical_integer", "signature_bytes", "unknown_owner", "oversized_name",
])
def test_fake_or_unreviewed_framework_declarations_are_not_bound(mutation):
    pe, types, members = _metadata_fixture()
    tables = pe.net.mdtables
    crypto = members["System.Security.Cryptography.TripleDES::Create", 0]
    gzip_ctor = members["System.IO.Compression.GZipStream::.ctor", 2]
    target = crypto
    if mutation in {"mscorlib_fake_pair", "system_fake_pair"}:
        index = 1 if mutation == "system_fake_pair" else 0
        tables.AssemblyRef.rows[index].PublicKey.value = bytes.fromhex("b03f5f7f11d50a3a")
        target = gzip_ctor if index else crypto
    elif mutation in {"full_key", "full_key_flag", "culture", "flags", "version", "modern_facade"}:
        assembly = tables.AssemblyRef.rows[0]
        if mutation == "full_key":
            assembly.PublicKey.value = b"synthetic-full-public-key" * 8
        elif mutation == "full_key_flag":
            assembly.struct.Flags = 1
        elif mutation == "culture":
            assembly.Culture = "ja-JP"
        elif mutation == "flags":
            assembly.struct.Flags = 0x100
        elif mutation == "version":
            assembly.MajorVersion = 9
        else:
            assembly.Name = "System.Runtime"
            assembly.PublicKey.value = bytes.fromhex("b03f5f7f11d50a3a")
    elif mutation in {"forward_scope", "foreign_table", "bad_scope_rid", "unknown_owner", "oversized_name"}:
        row = tables.TypeRef.rows[(types["System.Security.Cryptography.TripleDES"] & 0xFFFFFF) - 1]
        if mutation == "forward_scope":
            row.ResolutionScope = SimpleNamespace(table=tables.TypeRef, row_index=1)
        elif mutation == "foreign_table":
            row.ResolutionScope = SimpleNamespace(table=SimpleNamespace(name="AssemblyRef"), row_index=1)
        elif mutation == "bad_scope_rid":
            row.ResolutionScope.row_index = 3
        elif mutation == "unknown_owner":
            row.TypeNamespace = "NotFramework"
        else:
            row.TypeName = "private-fixture-name" * 100
    else:
        row = tables.MemberRef.rows[(crypto & 0xFFFFFF) - 1]
        if mutation in {"fake_return_owner", "return_version"}:
            returned = deepcopy(tables.TypeRef.rows[(types["System.Security.Cryptography.TripleDES"] & 0xFFFFFF) - 1])
            if mutation == "fake_return_owner":
                returned.ResolutionScope = SimpleNamespace(table=tables.AssemblyRef, row_index=2)
            else:
                other = deepcopy(tables.AssemblyRef.rows[0])
                other.MajorVersion = 2
                tables.AssemblyRef.rows.append(other)
                tables.AssemblyRef.num_rows += 1
                returned.ResolutionScope = SimpleNamespace(table=tables.AssemblyRef, row_index=3)
            tables.TypeRef.rows.append(returned)
            tables.TypeRef.num_rows += 1
            coded = (len(tables.TypeRef.rows) << 2) | 1
            row.Signature.value = bytes([0, 0, 0x12, coded])
        elif mutation == "enum_as_class":
            target = members["System.Security.Cryptography.SymmetricAlgorithm::set_Mode", 1]
            row = tables.MemberRef.rows[(target & 0xFFFFFF) - 1]
            row.Signature.value = row.Signature.value.replace(b"\x11", b"\x12", 1)
        elif mutation == "generic":
            row.Signature.value = b"\x10\x01" + row.Signature.value[1:]
        elif mutation == "extra_parameter":
            row.Signature.value = bytes([0, 1]) + row.Signature.value[2:] + b"\x08"
        elif mutation == "noncanonical_integer":
            row.Signature.value = b"\x00\x80\x00" + row.Signature.value[2:]
        else:
            row.Signature.value += bytes(recovery.MAX_API_SIGNATURE_BYTES)
    references, _, diagnostic = recovery._framework_references(pe, 1, lambda: 0)
    assert target not in references, mutation
    assert diagnostic["unreviewed_reason_counts"]
    assert "private-fixture-name" not in repr(diagnostic)


@pytest.mark.parametrize("table_name", ["TypeRef", "MemberRef", "AssemblyRef"])
@pytest.mark.parametrize("mutation", ["declared_overbudget", "actual_overbudget", "mismatch", "missing", "invalid_count"])
def test_metadata_row_limits_and_invalid_declarations_fail_closed(table_name, mutation):
    pe, _, _ = _metadata_fixture()
    table = getattr(pe.net.mdtables, table_name)
    if mutation == "declared_overbudget":
        table.num_rows = recovery.MAX_REFERENCE_ROWS + 1
    elif mutation == "actual_overbudget":
        table.rows = [table.rows[0]] * (recovery.MAX_REFERENCE_ROWS + 1)
        table.num_rows = len(table.rows)
    elif mutation == "mismatch":
        table.num_rows += 1
    elif mutation == "missing":
        setattr(pe.net.mdtables, table_name, None)
    else:
        table.num_rows = "invalid"
    with pytest.raises(recovery.RecipeError, match="framework_metadata_"):
        recovery._framework_references(pe, 1, lambda: 0)


def test_common_total_metadata_budget_and_signature_recursion_are_fixed():
    pe, _, _ = _metadata_fixture()
    for name in ("TypeDef", "Field", "StandAloneSig", "ModuleRef", "TypeSpec", "MethodSpec"):
        setattr(pe.net.mdtables, name, SimpleNamespace(rows=[SimpleNamespace()] * recovery.MAX_REFERENCE_ROWS,
            num_rows=recovery.MAX_REFERENCE_ROWS))
    with pytest.raises(recovery.RecipeError, match="framework_metadata_incomplete_or_over_budget"):
        recovery._framework_references(pe, 1, lambda: 0)
    assert recovery._signature(b"\x00\x00" + b"\x1d" * recovery.MAX_API_SIGNATURE_DEPTH + b"\x05", {}) is None
    assert recovery._signature(b"\x00\x11\x01" + b"\x05" * 17, {}) is None


@pytest.mark.parametrize("mutation", ["fake_pair", "culture", "full_key", "forward_scope", "overbudget"])
def test_pe_entry_never_promotes_unreviewed_or_overbudget_metadata(monkeypatch, mutation):
    pe, types, _ = _metadata_fixture()
    if mutation == "fake_pair":
        pe.net.mdtables.AssemblyRef.rows[0].PublicKey.value = bytes.fromhex("b03f5f7f11d50a3a")
    elif mutation == "culture":
        pe.net.mdtables.AssemblyRef.rows[0].Culture = "ja-JP"
    elif mutation == "full_key":
        pe.net.mdtables.AssemblyRef.rows[0].struct.Flags = 1
    elif mutation == "forward_scope":
        row = pe.net.mdtables.TypeRef.rows[(types["System.Security.Cryptography.TripleDES"] & 0xFFFFFF) - 1]
        row.ResolutionScope = SimpleNamespace(table=pe.net.mdtables.TypeRef, row_index=1)
    else:
        pe.net.mdtables.AssemblyRef.num_rows = recovery.MAX_REFERENCE_ROWS + 1
    monkeypatch.setattr(recovery.dnfile, "dnPE", lambda **kwargs: pe)
    report, artifacts = recovery.recover_managed_tripledes_gzip(_payload())
    assert not artifacts
    assert report["status"] in {"not_candidate", "rejected"}
    assert report["reason"] in {"framework_api_declaration_not_reviewed", "framework_metadata_incomplete_or_over_budget"}
    assert report["terminal_promotion_eligible"] is False
    assert report["sample_executed"] is False


@pytest.mark.parametrize("version,crypto_stream", [((2, 0, 0, 0), False), ((4, 0, 0, 0), False), ((4, 0, 0, 0), True)])
@pytest.mark.parametrize("key_size", [16, 24])
def test_parser_binds_reviewed_metadata_to_existing_recipes(monkeypatch, version, crypto_stream, key_size):
    payload, encrypted, method, resource = _fixture(key_size=key_size, crypto_stream=crypto_stream)
    pe, types, members = _metadata_fixture(version)
    parent = bytearray(_payload())
    parent[0x200 : 0x204 + len(encrypted)] = struct.pack("<I", len(encrypted)) + encrypted
    pe.sections = [SimpleNamespace(VirtualAddress=0x1000, PointerToRawData=0x200, SizeOfRawData=0x200)]
    pe.net.struct = SimpleNamespace(ResourcesRva=0x1000, ResourcesSize=4 + len(encrypted))
    pe.net.mdtables.MethodDef = SimpleNamespace(rows=[SimpleNamespace(Rva=0x1100)], num_rows=1)
    pe.net.mdtables.ManifestResource = SimpleNamespace(rows=[SimpleNamespace(
        Name=resource, Implementation=None, Offset=0)], num_rows=1)

    class UserString:
        def __init__(self, value):
            self.value = value

        def __str__(self):
            return self.value

    strings = {}
    instructions = []
    for record in method["instructions"]:
        operand = record["operand"]
        if record["opcode"] == "ldstr":
            rid = len(strings) + 1
            strings[rid] = UserString(record["string"])
            operand = SimpleNamespace(value=0x70000000 | rid)
        elif record.get("resolved_token"):
            name = record["resolved_token"]
            if record["opcode"] == "newarr":
                operand = SimpleNamespace(value=types[name])
            else:
                argc = record.get("parameter_count")
                candidates = [(count, token) for (api, count), token in members.items() if api == name]
                operand = SimpleNamespace(value=next(token for count, token in candidates if argc is None or count == argc))
        instructions.append(SimpleNamespace(offset=record["offset"], opcode=SimpleNamespace(name=record["opcode"]), operand=operand))
    pe.net.user_strings = SimpleNamespace(get=strings.get)
    monkeypatch.setattr(recovery.dnfile, "dnPE", lambda **kwargs: pe)
    monkeypatch.setattr(recovery, "read_method_body_from_bytes", lambda data: SimpleNamespace(size=128, instructions=instructions))
    report, artifacts = recovery.recover_managed_tripledes_gzip(bytes(parent))
    assert report["status"] == "recovered", report
    assert artifacts == [("managed-tripledes-gzip-pe", payload)]
    assert report["framework_declaration_validation"]["runtime_assembly_integrity_verified"] is False
