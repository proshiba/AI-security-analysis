"""単一host公開契約と既知multi-hostを別candidateで救済しない条件を人工protobufで検証する。"""

from __future__ import annotations

import base64
import gzip

import pytest

from extractors.purehvnc import extractor


def _varint(value):
    output = bytearray()
    while value > 127:
        output.append((value & 127) | 128)
        value >>= 7
    output.append(value)
    return bytes(output)


def _field(number, value):
    return _varint(number << 3 | 2) + _varint(len(value)) + value


def _message(hosts=(b"same.example",), ports=(443, 56001), *, packed=False, extra=b""):
    return b"".join(_field(1, host) for host in hosts) + (
        _field(2, b"".join(_varint(port) for port in ports)) if packed
        else b"".join(_varint(16) + _varint(port) for port in ports)
    ) + extra


def _encoded(value):
    return base64.b64encode(gzip.compress(value, mtime=0)).decode("ascii")


@pytest.mark.parametrize("hosts", [
    (b"first.example", b"other.example"), (b"other.example", b"first.example"),
    (b"same.example", b"same.example"), (b"same.example", b"SAME.EXAMPLE."),
    (b"same.example", b"invalid-single-label"),
])
def test_previously_valid_multi_host_schema_is_fixed_unsupported(hosts):
    """相反、同値、同じ表記、後続invalidも全体を単一hostへ縮めない。"""
    fields = extractor._normalise_config_fields(extractor.parse_protobuf(_message(hosts)))
    assert extractor._valid_config_fields(fields) is False
    with pytest.raises(ValueError, match="host field multiplicity is unsupported"):
        extractor.decode_config_blob([_encoded(_message(hosts))])


@pytest.mark.parametrize("first", [True, False])
@pytest.mark.parametrize("hosts", [(b"same.example", b"other.example"), (b"same.example", b"same.example")])
def test_other_single_host_candidate_cannot_hide_known_unsupported_multiplicity(first, hosts):
    values = [_encoded(_message()), _encoded(_message(hosts))]
    if not first:
        values.reverse()
    with pytest.raises(ValueError, match="host field multiplicity is unsupported"):
        extractor.decode_config_blob(values)


@pytest.mark.parametrize("first", [True, False])
def test_nested_multi_host_candidate_rejects_after_earlier_success_in_both_field_orders(first):
    single = _message()
    multi = _field(17, _message((b"same.example", b"other.example")))
    clear = single + multi if first else multi + single
    with pytest.raises(ValueError, match="host field multiplicity is unsupported"):
        extractor.decode_config_blob([_encoded(clear)])


@pytest.mark.parametrize("host", [b"same.example", b"SAME.EXAMPLE.", b"192.0.2.1", b"2001:DB8::1"])
@pytest.mark.parametrize("packed", [False, True])
def test_every_supported_single_host_form_preserves_decoded_fields(host, packed):
    message = _message((host,), packed=packed)
    raw, fields = extractor.decode_config_blob([_encoded(message)])
    assert raw == message
    assert fields[1] == [host]
    assert fields[2] == [443, 56001]
    assert extractor._valid_config_fields(fields) is True


@pytest.mark.parametrize("changed", [
    _message((b"other.example",)), _message(ports=(443, 56002)),
    _message(ports=(56001, 443)), _message(extra=_field(9, b"other-mutex")),
    _message(extra=_field(3, b"other-certificate")),
])
def test_existing_single_host_candidate_identity_conflicts_are_unchanged(changed):
    with pytest.raises(ValueError, match="conflicting managed PureRAT"):
        extractor.decode_config_blob([_encoded(_message()), _encoded(changed)])


def test_multiple_field_one_without_old_port_schema_is_only_a_wrapper():
    """field番号の存在だけではwrapperをmulti-host設定と決めない。"""
    child = _message()
    wrapper = _field(1, child) + _field(1, child)
    raw, fields = extractor.decode_config_blob([_encoded(wrapper)])
    assert raw == child
    assert fields[1] == [b"same.example"]


@pytest.mark.parametrize("ports", [(0,), (443, 443), ()])
def test_multi_field_one_with_invalid_old_port_schema_is_not_new_known_config(ports):
    value = _encoded(_message((b"same.example", b"other.example"), ports))
    with pytest.raises(ValueError, match="config was not found"):
        extractor.decode_config_blob([value])
    assert extractor.decode_config_blob([_encoded(_message()), value])[1][1] == [b"same.example"]


def test_multi_field_one_with_invalid_first_host_is_not_new_known_config():
    value = _encoded(_message((b"invalid-single-label", b"same.example")))
    with pytest.raises(ValueError, match="config was not found"):
        extractor.decode_config_blob([value])
    assert extractor.decode_config_blob([_encoded(_message()), value])[1][1] == [b"same.example"]


@pytest.mark.parametrize("native_candidate", [False, True])
def test_non_chrd_normal_entry_never_confirms_known_multi_host(native_candidate, monkeypatch):
    value = _encoded(_message((b"same.example", b"other.example")))
    monkeypatch.setattr(extractor, "iter_dotnet_user_strings", lambda _data: iter((value,)))
    monkeypatch.setattr(extractor, "has_clr_metadata", lambda _data: False)

    def native(_data):
        if native_candidate:
            return {"variant": "native_10fx", "endpoints": ["192.0.2.1:443"]}
        raise ValueError("synthetic native is absent")

    monkeypatch.setattr(extractor, "extract_native_config", native)
    result = extractor.extract(b"synthetic-non-chrd-reader", "synthetic.bin")
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["decoded_config_recovered"] is False
    assert result["c2"] == []
    assert result["executed"] is False
    assert result["network_contacted"] is False
    assert result["credentials_published"] is False
