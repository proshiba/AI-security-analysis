"""N520暗号文候補のCIL data-flow限定を検証する。"""

from __future__ import annotations

import base64
import struct
from types import SimpleNamespace

import pytest

from extractors.valleyrat import n520


def _instruction(name: str, operand: object = None) -> SimpleNamespace:
    return SimpleNamespace(opcode=SimpleNamespace(name=name), operand=operand)


def _member(namespace: str, owner: str, name: str) -> SimpleNamespace:
    return SimpleNamespace(
        Name=name,
        Class=SimpleNamespace(
            row=SimpleNamespace(TypeNamespace=namespace, TypeName=owner)
        ),
    )


def _key_body() -> list[SimpleNamespace]:
    return [
        _instruction("ldc.i4.s", 17),
        _instruction("newarr", 0x01000001),
        _instruction("dup"),
        _instruction("ldtoken", 0x04000003),
        _instruction("call", 0x0A000001),
        _instruction("stloc.0"),
        _instruction("ldloc.0"),
        _instruction("ldlen"),
        _instruction("conv.i4"),
        _instruction("newarr", 0x01000002),
        _instruction("stloc.1"),
        _instruction("ldc.i4.0"),
        _instruction("stloc.2"),
        _instruction("ldloc.1"),
        _instruction("ldloc.2"),
        _instruction("ldloc.0"),
        _instruction("ldloc.2"),
        _instruction("ldelem.i4"),
        _instruction("conv.u1"),
        _instruction("stelem.i1"),
        _instruction("ldloc.2"),
        _instruction("ldc.i4.1"),
        _instruction("add"),
        _instruction("stloc.2"),
        _instruction("ldloc.2"),
        _instruction("ldloc.0"),
        _instruction("ldlen"),
        _instruction("conv.i4"),
        _instruction("blt.s", 0),
        _instruction("ldloc.1"),
        _instruction("ret"),
    ]


def _decrypt_body() -> list[SimpleNamespace]:
    return [
        _instruction("call", 0x0A000002),
        _instruction("stloc.0"),
        _instruction("call", 0x0A000003),
        _instruction("stloc.1"),
        _instruction("ldloc.0"),
        _instruction("ldloc.1"),
        _instruction("call", 0x06000001),
        _instruction("callvirt", 0x0A000004),
        _instruction("callvirt", 0x0A000005),
        _instruction("ldloc.0"),
        _instruction("ldloc.2"),
        _instruction("callvirt", 0x0A000006),
        _instruction("ldloc.0"),
        _instruction("callvirt", 0x0A000007),
        _instruction("stloc.3"),
        _instruction("ldloc.3"),
        _instruction("ldarg.0"),
        _instruction("ldc.i4.s", 16),
        _instruction("ldarg.0"),
        _instruction("ldlen"),
        _instruction("callvirt", 0x0A000008),
        _instruction("stloc.s", 4),
        _instruction("call", 0x0A000009),
        _instruction("ldloc.s", 4),
        _instruction("callvirt", 0x0A00000A),
        _instruction("ret"),
    ]


def _reader_body() -> list[SimpleNamespace]:
    return [
        _instruction("ldarg.0"),
        _instruction("call", 0x0A00000B),
        _instruction("stloc.0"),
        _instruction("ldloc.0"),
        _instruction("call", 0x06000002),
        _instruction("stloc.1"),
        _instruction("newobj", 0x0A00000C),
        _instruction("stloc.2"),
        _instruction("ldloc.2"),
        _instruction("ldloc.1"),
        _instruction("callvirt", 0x0A00000D),
        _instruction("ret"),
    ]


def _fixture(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[SimpleNamespace, dict[int, list[SimpleNamespace]], str, str]:
    methods = [
        SimpleNamespace(Name=name, Rva=index)
        for index, name in enumerate(("a", "b", "c", "d", ".cctor", ".cctor"), 1)
    ]
    members = [
        _member("System.Runtime.CompilerServices", "RuntimeHelpers", "InitializeArray"),
        _member("System.Security.Cryptography", "Aes", "Create"),
        _member("System.Security.Cryptography", "SHA256", "Create"),
        _member("System.Security.Cryptography", "HashAlgorithm", "ComputeHash"),
        _member("System.Security.Cryptography", "SymmetricAlgorithm", "set_Key"),
        _member("System.Security.Cryptography", "SymmetricAlgorithm", "set_IV"),
        _member("System.Security.Cryptography", "SymmetricAlgorithm", "CreateDecryptor"),
        _member("System.Security.Cryptography", "ICryptoTransform", "TransformFinalBlock"),
        _member("System.Text", "Encoding", "get_UTF8"),
        _member("System.Text", "Encoding", "GetString"),
        _member("System", "Convert", "FromBase64String"),
        _member("System.Net.Http", "HttpClient", ".ctor"),
        _member("System.Net.Http", "HttpClient", "GetByteArrayAsync"),
    ]
    tables = SimpleNamespace(
        TypeRef=SimpleNamespace(
            rows=[
                SimpleNamespace(TypeNamespace="System", TypeName="Int32"),
                SimpleNamespace(TypeNamespace="System", TypeName="Byte"),
            ]
        ),
        TypeDef=SimpleNamespace(rows=[]),
        Field=SimpleNamespace(
            rows=[
                SimpleNamespace(Name="field_a"),
                SimpleNamespace(Name="field_b"),
                SimpleNamespace(Name="key_data"),
            ]
        ),
        MethodDef=SimpleNamespace(rows=methods),
        MemberRef=SimpleNamespace(rows=members),
        FieldRva=SimpleNamespace(
            rows=[
                SimpleNamespace(
                    Field=SimpleNamespace(row_index=3),
                    Rva=0x200,
                )
            ]
        ),
    )
    image = SimpleNamespace(
        net=SimpleNamespace(mdtables=tables),
        get_offset_from_rva=lambda _rva: 2,
    )
    related = base64.b64encode(b"R" * 32).decode("ascii")
    unrelated = base64.b64encode(b"U" * 32).decode("ascii")
    strings = {0x70000001: related, 0x70000002: unrelated}
    bodies = {
        1: _key_body(),
        2: _decrypt_body(),
        3: _reader_body(),
        4: [
            _instruction("ldsfld", 0x04000001),
            _instruction("call", 0x06000003),
            _instruction("ret"),
        ],
        5: [
            _instruction("ldstr", 0x70000001),
            _instruction("stsfld", 0x04000001),
            _instruction("ret"),
        ],
        6: [
            _instruction("ldstr", 0x70000002),
            _instruction("stsfld", 0x04000002),
            _instruction("ret"),
        ],
    }
    monkeypatch.setattr(n520, "_method_instructions", lambda _i, _d, row: bodies[row.Rva])
    monkeypatch.setattr(n520, "_user_string", lambda _i, token: strings[token])
    return image, bodies, related, unrelated


def test_n520_key_recovery_does_not_require_method_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """任意名のmethodでも一意なinitializer data-flowから鍵を回収する。"""

    image, _, _, _ = _fixture(monkeypatch)
    expected = bytes(range(1, 18))
    data = b"MZ" + struct.pack("<17I", *expected)

    key, proof = n520._recover_key(image, data)

    assert key == expected
    assert proof["method_name_required"] is False
    assert proof["method_identification"] == "validated_cil_initializer_data_flow"


def test_n520_accepts_only_base64_linked_to_cloud_reader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """無関係なBase64 static fieldを復号候補へ混入させない。"""

    image, _, related, unrelated = _fixture(monkeypatch)

    assert n520._base64_values(image, b"MZ") == [related]
    assert unrelated not in n520._base64_values(image, b"MZ")


def test_n520_rejects_conflicting_writes_to_linked_field(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """同一設定fieldへの複数書き込みは探索順で選ばず拒否する。"""

    image, bodies, _, _ = _fixture(monkeypatch)
    bodies[5][2:2] = [
        _instruction("ldstr", 0x70000002),
        _instruction("stsfld", 0x04000001),
    ]

    with pytest.raises(n520.N520ConfigError, match="競合"):
        n520._base64_values(image, b"MZ")


def test_n520_rejects_multiple_fields_reaching_cloud_reader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """異なるfield由来のcloud reader呼び出しは曖昧として拒否する。"""

    image, bodies, _, _ = _fixture(monkeypatch)
    bodies[4][2:2] = [
        _instruction("ldsfld", 0x04000002),
        _instruction("call", 0x06000003),
    ]

    with pytest.raises(n520.N520ConfigError, match="一意"):
        n520._base64_values(image, b"MZ")


def test_n520_data_flow_scan_enforces_total_instruction_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """call graph構築前にmanaged総命令数の上限を強制する。"""

    image, bodies, _, _ = _fixture(monkeypatch)
    monkeypatch.setattr(
        n520,
        "MAXIMUM_TOTAL_INSTRUCTIONS",
        sum(len(body) for body in bodies.values()) - 1,
    )

    with pytest.raises(n520.N520ConfigError, match="総数"):
        n520._base64_values(image, b"MZ")
