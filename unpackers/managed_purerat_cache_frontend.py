"""PureRAT系managed UTF-16 cache recipeをreal CILから静的に束縛する。

CLR/CILは実行しない。dnfile/dncilで得た命令を限定的な定数dataflowとして
解釈し、未知命令、未知call、未知branch、複数候補をstable reasonで拒否する。
provider/protector名、metadata RID、検体hash、loose URLは受理条件にしない。
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import dnfile
from dncil.cil.body.reader import read_method_body_from_bytes
from malware.purehvnc.managed_resource_recovery import (
    StaticRecoveryError,
    decrypt_keyed_eaz_resource,
)

from unpackers.managed_cil_cfg import (
    CilMethod,
    classify_exact_constant_proxy,
    parse_managed_program,
    verify_length_prefixed_utf16_cache_shape,
)
from unpackers.managed_constructor_guard import preflight_clr_declarations
from unpackers.managed_omlx_direct_tripledes import _helper_api_set
from unpackers.managed_omlx_tripledes import (
    _resource_blobs,
    _verified_transform_recipes,
)
from unpackers.managed_purerat_cache import decode_complete_utf16_cache

from . import managed_bitmap_argb_xor as model

MAX_INPUT_BYTES = 32 << 20
MAX_METHOD_STATES = 20_000
MAX_STATE_INSTRUCTIONS = 512
MAX_ARRAY_LENGTH = 1 << 20
MAX_CALL_TOKENS = 256
MAX_ELAPSED_SECONDS = 20.0


class ManagedPureRatCacheFrontendError(ValueError):
    """review済みのCIL cache recipeから外れた入力を表す。"""


@dataclass
class _Array:
    identifier: int
    length: int
    values: dict[int, int] = field(default_factory=dict)
    writes: list[tuple[int, int]] = field(default_factory=list)

    def store(self, index: int, value: int) -> None:
        if not 0 <= index < self.length or not 0 <= value <= 0xFF:
            raise ManagedPureRatCacheFrontendError("array_write_out_of_bounds")
        self.values[index] = value
        self.writes.append((index, value))

    def load(self, index: int) -> int:
        if not 0 <= index < self.length or index not in self.values:
            raise ManagedPureRatCacheFrontendError("array_read_before_definition")
        return self.values[index]

    def complete_bytes(self) -> bytes:
        if set(self.values) != set(range(self.length)):
            raise ManagedPureRatCacheFrontendError("array_final_state_incomplete")
        return bytes(self.values[index] for index in range(self.length))

    def reverse(self) -> None:
        clear = self.complete_bytes()[::-1]
        self.values = dict(enumerate(clear))


@dataclass
class _Stream:
    data: bytes
    position: int = 0


@dataclass
class _Reader:
    stream: _Stream


@dataclass(frozen=True)
class _RecipeBinding:
    cache_method: CilMethod
    decoder_token: int
    resource_name: str
    resource: bytes
    transform_token: int
    transform_seed: int
    transform_addend: int
    transform_body_sha256: str
    reverse_token: int
    proxy_values: Mapping[int, bool]
    api_roles: Mapping[int, frozenset[str]]
    transform_owner_token: int
    transform_ctor_tokens: frozenset[int]


def _base_report(size: int) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "status": "not_candidate",
        "reason": "managed_utf16_cache_recipe_missing",
        "input_size": size,
        "family_attribution_allowed": False,
        "c2_confirmation_allowed": False,
        "provider_or_protector_label_used": False,
        "raw_key_material_published": False,
        "raw_resource_returned": False,
        "raw_strings_published": False,
        "sample_executed": False,
        "clr_loaded": False,
        "bounded_cil_model_interpreted": False,
        "network_contacted": False,
    }


def _check_time(deadline: float, clock: Callable[[], float]) -> None:
    if clock() > deadline:
        raise ManagedPureRatCacheFrontendError("elapsed_time_limit")


def _token(operand: object) -> int | None:
    value = getattr(operand, "value", operand)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _target(operand: object) -> int | None:
    value = getattr(operand, "offset", operand)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _arg_index(opcode: str, operand: object) -> int | None:
    if opcode.startswith("ldarg.") and opcode[-1:].isdigit():
        return int(opcode[-1])
    if opcode not in {"ldarg", "ldarg.s"}:
        return None
    text = str(operand)
    if text.startswith("argument(0x") and text.endswith(")"):
        try:
            return int(text[11:-1], 16)
        except ValueError:
            return None
    value = getattr(operand, "index", operand)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _raw_method(pe: Any, data: bytes, token: int) -> tuple[Any, ...]:
    rows = list(getattr(getattr(pe.net.mdtables, "MethodDef", None), "rows", ()) or ())
    rid = token & 0xFFFFFF
    if token >> 24 != 6 or not 1 <= rid <= len(rows):
        raise ManagedPureRatCacheFrontendError("method_token_invalid")
    rva = int(getattr(rows[rid - 1], "Rva", 0) or 0)
    start, end = model._method_raw_window(pe, data, rva)
    try:
        body = read_method_body_from_bytes(data[start:end])
    except Exception as exc:
        raise ManagedPureRatCacheFrontendError("method_body_parse_failed") from exc
    return tuple(body.instructions)


def _owner_tokens(methods: Sequence[Any]) -> dict[int, int]:
    return {item.token: item.owner_token for item in methods}


def _discover_binding(
    data: bytes,
    pe: Any,
    program: Any,
    normalized: Sequence[Any],
    *,
    deadline: float,
    clock: Callable[[], float],
) -> _RecipeBinding:
    cache_methods = [
        method
        for method in program.methods
        if verify_length_prefixed_utf16_cache_shape(method).get("status") == "matched"
    ]
    if len(cache_methods) != 1:
        raise ManagedPureRatCacheFrontendError("cache_method_missing_or_ambiguous")
    cache = cache_methods[0]
    normalized_by_token = {item.token: item for item in normalized}
    normalized_cache = normalized_by_token.get(cache.token)
    if normalized_cache is None:
        raise ManagedPureRatCacheFrontendError("cache_method_view_missing")
    instructions = list(normalized_cache.instructions)
    resource_calls = [
        index
        for index, item in enumerate(instructions)
        if item.opcode in {"call", "callvirt"}
        and item.resolved.endswith(
            "System.Reflection.Assembly::GetManifestResourceStream"
        )
    ]
    if len(resource_calls) != 1:
        raise ManagedPureRatCacheFrontendError("cache_resource_call_ambiguous")
    resource_index = resource_calls[0]
    string_candidates = [
        item.user_string
        for item in instructions[max(0, resource_index - 8) : resource_index]
        if item.opcode == "ldstr" and isinstance(item.user_string, str)
    ]
    if len(string_candidates) != 1:
        raise ManagedPureRatCacheFrontendError("cache_resource_name_ambiguous")
    resource_name = string_candidates[0]
    int32_indices = [
        index
        for index, item in enumerate(
            instructions[resource_index + 1 :], resource_index + 1
        )
        if item.resolved.endswith("System.BitConverter::ToInt32")
    ]
    if not int32_indices:
        raise ManagedPureRatCacheFrontendError("cache_length_prefix_call_missing")
    decoder_calls = {
        item.token
        for item in instructions[resource_index + 1 : int32_indices[0]]
        if item.opcode in {"call", "callvirt"}
        and isinstance(item.token, int)
        and item.token >> 24 == 6
    }
    if len(decoder_calls) != 1:
        raise ManagedPureRatCacheFrontendError("cache_decoder_call_ambiguous")
    decoder_token = next(iter(decoder_calls))

    resources_list = _resource_blobs(pe)
    if len({name for name, _ in resources_list}) != len(resources_list):
        raise ManagedPureRatCacheFrontendError("resource_name_ambiguous")
    matches = [blob for name, blob in resources_list if name == resource_name]
    if len(matches) != 1:
        raise ManagedPureRatCacheFrontendError("bound_resource_missing_or_ambiguous")
    resource = matches[0]
    _check_time(deadline, clock)

    transforms = _verified_transform_recipes(
        data,
        pe,
        deadline=deadline,
        clock=clock,
    )
    decoder = normalized_by_token.get(decoder_token)
    if decoder is None:
        raise ManagedPureRatCacheFrontendError("decoder_method_view_missing")
    internal_calls = {
        item.token
        for item in decoder.instructions
        if item.opcode in {"call", "callvirt", "newobj"}
        and isinstance(item.token, int)
        and item.token >> 24 == 6
    }
    transform_tokens = sorted(internal_calls & set(transforms))
    if len(transform_tokens) != 1:
        raise ManagedPureRatCacheFrontendError(
            "keyed_word_transform_missing_or_ambiguous"
        )
    transform_token = transform_tokens[0]
    transform = transforms[transform_token]

    proxy_values = {
        method.token: kind == "constant_true"
        for method in program.methods
        if (kind := classify_exact_constant_proxy(method)) is not None
    }
    helper_cache: dict[int, frozenset[str]] = {}
    metadata_views: list[Any] = []
    api_roles: dict[int, frozenset[str]] = {}
    for token in sorted(internal_calls)[:MAX_CALL_TOKENS]:
        _check_time(deadline, clock)
        try:
            names = _helper_api_set(
                data,
                pe,
                token,
                deadline=deadline,
                clock=clock,
                cache=helper_cache,
                metadata_views=metadata_views,
            )
        except Exception:  # noqa: BLE001,S112 - 候補helper単位でfail-closedに除外する。
            continue
        if names:
            api_roles[token] = names
    reverse_tokens = [
        token
        for token, names in api_roles.items()
        if names == {"System.Array::Reverse"}
    ]
    if len(reverse_tokens) != 1:
        raise ManagedPureRatCacheFrontendError(
            "array_reverse_role_missing_or_ambiguous"
        )

    owners = _owner_tokens(normalized)
    transform_owner = owners.get(transform_token)
    if not isinstance(transform_owner, int):
        raise ManagedPureRatCacheFrontendError("transform_owner_missing")
    transform_ctors = frozenset(
        item.token
        for item in normalized
        if item.owner_token == transform_owner
        and item.name == ".ctor"
        and api_roles.get(item.token) == {"System.Object::.ctor"}
    )
    if len(transform_ctors) != 1:
        raise ManagedPureRatCacheFrontendError(
            "transform_constructor_missing_or_ambiguous"
        )
    return _RecipeBinding(
        cache_method=cache,
        decoder_token=decoder_token,
        resource_name=resource_name,
        resource=resource,
        transform_token=transform_token,
        transform_seed=transform.seed,
        transform_addend=transform.addend,
        transform_body_sha256=normalized_by_token[transform_token].body_sha256,
        reverse_token=reverse_tokens[0],
        proxy_values=proxy_values,
        api_roles=api_roles,
        transform_owner_token=transform_owner,
        transform_ctor_tokens=transform_ctors,
    )


def _signed(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - (1 << 32) if value & (1 << 31) else value


def _truthy(value: Any) -> bool | None:
    if value is None:
        return False
    if isinstance(value, int) and not isinstance(value, bool):
        return value != 0
    if isinstance(value, (_Array, _Stream, _Reader, bytes)):
        return True
    if isinstance(value, tuple):
        if value[:1] in {
            ("assembly",),
            ("assembly-name",),
            ("transform-instance",),
        }:
            return True
        return None
    return None


def _is_unknown_static_field(value: Any) -> bool:
    return isinstance(value, tuple) and value[:1] == ("static-field",)


def _value_signature(value: Any) -> Any:
    if isinstance(value, _Array):
        return (
            "array",
            value.identifier,
            value.length,
            tuple(sorted(value.values.items())),
        )
    if isinstance(value, _Stream):
        return (
            "stream",
            len(value.data),
            value.position,
            hashlib.sha256(value.data).hexdigest(),
        )
    if isinstance(value, _Reader):
        return ("reader", _value_signature(value.stream))
    if isinstance(value, bytes):
        return ("bytes", len(value), hashlib.sha256(value).hexdigest())
    return value


def _dispatcher(
    raw: Sequence[Any],
) -> tuple[int, int, dict[int, int], tuple[int, int, int]]:
    switches = [
        (index, item)
        for index, item in enumerate(raw)
        if str(item.opcode.name) == "switch"
    ]
    if not switches:
        raise ManagedPureRatCacheFrontendError("dispatcher_switch_missing")
    index, switch = max(switches, key=lambda pair: len(pair[1].operand or ()))
    if index < 3:
        raise ManagedPureRatCacheFrontendError("dispatcher_prologue_missing")
    initial = model._integer(str(raw[index - 3].opcode.name), raw[index - 3].operand)
    dispatch_local = model._local(
        str(raw[index - 2].opcode.name), raw[index - 2].operand
    )
    loaded_local = model._local(str(raw[index - 1].opcode.name), raw[index - 1].operand)
    if (
        initial is None
        or dispatch_local is None
        or loaded_local != dispatch_local
        or not str(raw[index - 2].opcode.name).startswith("stloc")
        or not str(raw[index - 1].opcode.name).startswith("ldloc")
    ):
        raise ManagedPureRatCacheFrontendError("dispatcher_prologue_not_exact")
    targets = [_target(item) for item in (switch.operand or ())]
    if not targets or any(target is None for target in targets):
        raise ManagedPureRatCacheFrontendError("dispatcher_target_invalid")
    mapping = {state: int(target) for state, target in enumerate(targets)}
    cursor = index + 1
    while cursor < len(raw):
        if cursor + 2 < len(raw):
            local = model._local(str(raw[cursor].opcode.name), raw[cursor].operand)
            state = model._integer(
                str(raw[cursor + 1].opcode.name), raw[cursor + 1].operand
            )
            branch = str(raw[cursor + 2].opcode.name)
            target = _target(raw[cursor + 2].operand)
            if (
                local == dispatch_local
                and state is not None
                and branch in {"beq", "beq.s"}
                and target is not None
            ):
                if state in mapping and mapping[state] != target:
                    raise ManagedPureRatCacheFrontendError("dispatcher_state_alias")
                mapping[state] = target
                cursor += 3
                continue
        if str(raw[cursor].opcode.name) in {"br", "br.s"}:
            break
        raise ManagedPureRatCacheFrontendError("dispatcher_fallback_shape_unsupported")
    entries = (
        int(raw[index - 2].offset),
        int(raw[index - 1].offset),
        int(switch.offset),
    )
    return initial, dispatch_local, mapping, entries


def _consume_dispatch_entry(
    destination: int,
    entries: tuple[int, int, int],
    stack: list[Any],
    locals_: dict[int, Any],
    dispatch_local: int,
) -> int:
    """dispatcherの3入口をCLR stack効果どおりに1 stateへ正規化する。"""

    dispatch_store, dispatch_load, dispatch_switch = entries
    if destination == dispatch_store:
        if len(stack) != 1 or not isinstance(stack[0], int):
            raise ManagedPureRatCacheFrontendError(
                "dispatcher_next_state_stack_invalid"
            )
        locals_[dispatch_local] = stack.pop()
        value = locals_[dispatch_local]
    elif destination == dispatch_load:
        if stack:
            raise ManagedPureRatCacheFrontendError("dispatcher_stack_not_empty")
        value = locals_.get(dispatch_local)
    elif destination == dispatch_switch:
        if len(stack) != 1 or not isinstance(stack[0], int):
            raise ManagedPureRatCacheFrontendError(
                "dispatcher_next_state_stack_invalid"
            )
        value = stack.pop()
    else:
        raise ManagedPureRatCacheFrontendError("dispatcher_entry_invalid")
    if stack:
        raise ManagedPureRatCacheFrontendError("dispatcher_stack_not_empty")
    if not isinstance(value, int):
        raise ManagedPureRatCacheFrontendError("dispatcher_next_state_nonconcrete")
    return value


def _interpret_decoder(
    raw: Sequence[Any],
    normalized: Any,
    binding: _RecipeBinding,
    *,
    assembly_public_key_state: str,
    entry_token: int | None,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[bytes, bytes, int, int]:
    initial, dispatch_local, dispatch, dispatch_entries = _dispatcher(raw)
    by_offset = {int(item.offset): index for index, item in enumerate(raw)}
    normalized_by_offset = {item.offset: item for item in normalized.instructions}
    locals_: dict[int, Any] = {dispatch_local: initial}
    static_fields: dict[int, Any] = {}
    args: dict[int, Any] = {0: _Stream(binding.resource), 1: 0}
    arrays: list[_Array] = []
    state = initial
    seen: set[Any] = set()
    reverse_count = 0
    pre_key: bytes | None = None
    pre_mask: bytes | None = None
    key_after_reverse_writes: list[tuple[int, int]] = []
    transform_seen = 0
    total_steps = 0

    def pop(stack: list[Any]) -> Any:
        if not stack:
            raise ManagedPureRatCacheFrontendError("cil_stack_underflow")
        return stack.pop()

    while total_steps < MAX_METHOD_STATES:
        _check_time(deadline, clock)
        target = dispatch.get(state)
        if target is None or target not in by_offset:
            raise ManagedPureRatCacheFrontendError("dispatcher_state_target_missing")
        signature = (
            state,
            tuple(
                sorted((key, _value_signature(value)) for key, value in locals_.items())
            ),
            tuple(
                sorted(
                    (key, _value_signature(value))
                    for key, value in static_fields.items()
                )
            ),
            tuple(_value_signature(item) for item in arrays),
        )
        if signature in seen:
            raise ManagedPureRatCacheFrontendError("dispatcher_state_loop")
        seen.add(signature)
        stack: list[Any] = []
        ip = by_offset[target]
        next_state: int | None = None
        for _ in range(MAX_STATE_INSTRUCTIONS):
            total_steps += 1
            if total_steps > MAX_METHOD_STATES or not 0 <= ip < len(raw):
                raise ManagedPureRatCacheFrontendError(
                    "cil_state_or_instruction_budget"
                )
            item = raw[ip]
            offset = int(item.offset)
            opcode = str(item.opcode.name)
            normalized_item = normalized_by_offset.get(offset)
            if normalized_item is None:
                raise ManagedPureRatCacheFrontendError("cil_instruction_view_mismatch")
            integer = model._integer(opcode, item.operand)
            advance = True
            if integer is not None:
                stack.append(integer & 0xFFFFFFFF)
            elif opcode == "ldnull":
                stack.append(None)
            elif opcode.startswith("ldloc"):
                local = model._local(opcode, item.operand)
                if local is None or local not in locals_:
                    raise ManagedPureRatCacheFrontendError(
                        "cil_local_read_before_definition"
                    )
                stack.append(locals_[local])
            elif opcode.startswith("stloc"):
                local = model._local(opcode, item.operand)
                if local is None:
                    raise ManagedPureRatCacheFrontendError("cil_local_index_invalid")
                locals_[local] = pop(stack)
            elif opcode.startswith("ldarg"):
                argument = _arg_index(opcode, item.operand)
                if argument is None or argument not in args:
                    raise ManagedPureRatCacheFrontendError("cil_argument_unsupported")
                stack.append(args[argument])
            elif opcode == "dup":
                stack.append(stack[-1] if stack else pop(stack))
            elif opcode == "pop":
                pop(stack)
            elif opcode in {
                "add",
                "sub",
                "xor",
                "and",
                "or",
                "mul",
                "rem",
                "div",
                "shl",
                "shr",
                "shr.un",
            }:
                right, left = pop(stack), pop(stack)
                if (
                    not isinstance(left, int)
                    or isinstance(left, bool)
                    or not isinstance(right, int)
                    or isinstance(right, bool)
                ):
                    raise ManagedPureRatCacheFrontendError(
                        "cil_integer_operation_nonconcrete"
                    )
                if opcode in {"rem", "div"} and right == 0:
                    raise ManagedPureRatCacheFrontendError("cil_integer_divide_by_zero")
                operations = {
                    "add": left + right,
                    "sub": left - right,
                    "xor": left ^ right,
                    "and": left & right,
                    "or": left | right,
                    "mul": left * right,
                    "rem": left % right if right else 0,
                    "div": left // right if right else 0,
                    "shl": left << (right & 31),
                    "shr": _signed(left) >> (right & 31),
                    "shr.un": (left & 0xFFFFFFFF) >> (right & 31),
                }
                stack.append(operations[opcode] & 0xFFFFFFFF)
            elif opcode == "neg":
                value = pop(stack)
                if not isinstance(value, int):
                    raise ManagedPureRatCacheFrontendError(
                        "cil_integer_operation_nonconcrete"
                    )
                stack.append((-value) & 0xFFFFFFFF)
            elif opcode == "not":
                value = pop(stack)
                if not isinstance(value, int):
                    raise ManagedPureRatCacheFrontendError(
                        "cil_integer_operation_nonconcrete"
                    )
                stack.append((~value) & 0xFFFFFFFF)
            elif opcode in {
                "conv.i",
                "conv.i4",
                "conv.u",
                "conv.u4",
                "conv.i8",
                "conv.u8",
            }:
                value = pop(stack)
                if not isinstance(value, int):
                    raise ManagedPureRatCacheFrontendError("cil_conversion_nonconcrete")
                stack.append(value & 0xFFFFFFFF)
            elif opcode == "conv.u1":
                value = pop(stack)
                if not isinstance(value, int):
                    raise ManagedPureRatCacheFrontendError("cil_conversion_nonconcrete")
                stack.append(value & 0xFF)
            elif opcode == "newarr":
                length = pop(stack)
                if (
                    not isinstance(length, int)
                    or isinstance(length, bool)
                    or not 0 <= length <= MAX_ARRAY_LENGTH
                    or normalized_item.resolved != "System.Byte"
                ):
                    raise ManagedPureRatCacheFrontendError(
                        "cil_byte_array_allocation_invalid"
                    )
                array = _Array(offset, length)
                arrays.append(array)
                stack.append(array)
            elif opcode == "stelem.i1":
                value, index, array = pop(stack), pop(stack), pop(stack)
                if (
                    not isinstance(array, _Array)
                    or not isinstance(index, int)
                    or not isinstance(value, int)
                ):
                    raise ManagedPureRatCacheFrontendError(
                        "cil_byte_array_write_nonconcrete"
                    )
                array.store(index, value & 0xFF)
                if reverse_count:
                    key_after_reverse_writes.append((index, value & 0xFF))
            elif opcode == "ldelem.u1":
                index, array = pop(stack), pop(stack)
                if not isinstance(array, _Array) or not isinstance(index, int):
                    raise ManagedPureRatCacheFrontendError(
                        "cil_byte_array_read_nonconcrete"
                    )
                stack.append(array.load(index))
            elif opcode == "ldlen":
                value = pop(stack)
                if isinstance(value, _Array):
                    stack.append(value.length)
                elif isinstance(value, bytes):
                    stack.append(len(value))
                else:
                    raise ManagedPureRatCacheFrontendError(
                        "cil_length_source_unsupported"
                    )
            elif opcode == "ceq":
                right, left = pop(stack), pop(stack)
                if _is_unknown_static_field(left) or _is_unknown_static_field(right):
                    raise ManagedPureRatCacheFrontendError(
                        "cil_static_field_read_before_definition"
                    )
                stack.append(1 if left == right else 0)
            elif opcode == "ldsfld":
                field_token = _token(item.operand)
                if field_token is None:
                    raise ManagedPureRatCacheFrontendError(
                        "cil_static_field_token_invalid"
                    )
                stack.append(
                    static_fields.get(field_token, ("static-field", field_token))
                )
            elif opcode == "stsfld":
                field_token = _token(item.operand)
                if field_token is None:
                    raise ManagedPureRatCacheFrontendError(
                        "cil_static_field_token_invalid"
                    )
                value = pop(stack)
                if _is_unknown_static_field(value):
                    raise ManagedPureRatCacheFrontendError(
                        "cil_static_field_write_nonconcrete"
                    )
                static_fields[field_token] = value
            elif opcode in {"call", "callvirt", "newobj"}:
                token = _token(item.operand)
                resolved = normalized_item.resolved
                roles = (
                    binding.api_roles.get(token, frozenset())
                    if token is not None
                    else frozenset()
                )
                if token in binding.proxy_values:
                    stack.append(1 if binding.proxy_values[token] else 0)
                elif token == binding.reverse_token:
                    array = pop(stack)
                    if (
                        not isinstance(array, _Array)
                        or array.length != 16
                        or reverse_count
                    ):
                        raise ManagedPureRatCacheFrontendError(
                            "reverse_mask_binding_invalid"
                        )
                    candidates = [
                        candidate for candidate in arrays if candidate.length == 32
                    ]
                    if len(candidates) != 1:
                        raise ManagedPureRatCacheFrontendError(
                            "reverse_key_binding_ambiguous"
                        )
                    pre_key = candidates[0].complete_bytes()
                    pre_mask = array.complete_bytes()
                    array.reverse()
                    reverse_count = 1
                elif token == binding.transform_token:
                    if len(stack) != 4:
                        raise ManagedPureRatCacheFrontendError(
                            "transform_stack_shape_invalid"
                        )
                    instance, key, mask, ciphertext = stack
                    if (
                        not isinstance(instance, tuple)
                        or instance[:1] != ("transform-instance",)
                        or not isinstance(key, _Array)
                        or key.length != 32
                        or not isinstance(mask, _Array)
                        or mask.length != 16
                        or not isinstance(ciphertext, bytes)
                        or ciphertext != binding.resource
                    ):
                        raise ManagedPureRatCacheFrontendError(
                            "transform_argument_binding_invalid"
                        )
                    if pre_key is None or pre_mask is None or reverse_count != 1:
                        raise ManagedPureRatCacheFrontendError(
                            "key_mask_mutation_proof_missing"
                        )
                    expected = bytearray(pre_key)
                    for index, value in enumerate(pre_mask[::-1]):
                        expected[index] ^= value
                    if (
                        key.complete_bytes() != bytes(expected)
                        or mask.complete_bytes() != pre_mask[::-1]
                    ):
                        raise ManagedPureRatCacheFrontendError(
                            "key_mask_mutation_mismatch"
                        )
                    if sorted(index for index, _ in key_after_reverse_writes) != list(
                        range(16)
                    ):
                        raise ManagedPureRatCacheFrontendError(
                            "key_xor_loop_not_exact_16"
                        )
                    transform_seen += 1
                    if transform_seen != 1:
                        raise ManagedPureRatCacheFrontendError(
                            "transform_sink_ambiguous"
                        )
                    return pre_key, pre_mask, len(seen), total_steps
                elif token in binding.transform_ctor_tokens and opcode == "newobj":
                    stack.append(("transform-instance", token))
                elif roles == {"System.Reflection.Assembly::GetName"}:
                    pop(stack)
                    stack.append(("assembly-name",))
                elif roles == {"System.Reflection.AssemblyName::GetPublicKeyToken"}:
                    pop(stack)
                    if assembly_public_key_state != "absent":
                        raise ManagedPureRatCacheFrontendError(
                            "public_key_state_unsupported"
                        )
                    stack.append(None)
                elif roles == {"System.Reflection.Assembly::get_EntryPoint"}:
                    pop(stack)
                    stack.append(entry_token)
                elif roles == {"System.Reflection.MethodInfo::op_Equality"}:
                    right, left = pop(stack), pop(stack)
                    if _is_unknown_static_field(left) or _is_unknown_static_field(
                        right
                    ):
                        raise ManagedPureRatCacheFrontendError(
                            "cil_static_field_read_before_definition"
                        )
                    stack.append(1 if left == right else 0)
                elif roles == {"System.IO.BinaryReader::get_BaseStream"}:
                    reader = pop(stack)
                    if not isinstance(reader, _Reader):
                        raise ManagedPureRatCacheFrontendError("reader_binding_invalid")
                    stack.append(reader.stream)
                elif roles == {"System.IO.Stream::set_Position"}:
                    position, stream = pop(stack), pop(stack)
                    if (
                        not isinstance(stream, _Stream)
                        or not isinstance(position, int)
                        or not 0 <= position <= len(stream.data)
                    ):
                        raise ManagedPureRatCacheFrontendError(
                            "stream_position_invalid"
                        )
                    stream.position = position
                elif roles == {"System.IO.Stream::get_Length"}:
                    stream = pop(stack)
                    if not isinstance(stream, _Stream):
                        raise ManagedPureRatCacheFrontendError(
                            "stream_length_source_invalid"
                        )
                    stack.append(len(stream.data))
                elif roles == {"System.IO.BinaryReader::ReadBytes"}:
                    count, reader = pop(stack), pop(stack)
                    if (
                        not isinstance(reader, _Reader)
                        or not isinstance(count, int)
                        or not 0
                        <= count
                        <= len(reader.stream.data) - reader.stream.position
                    ):
                        raise ManagedPureRatCacheFrontendError("reader_count_invalid")
                    begin = reader.stream.position
                    reader.stream.position += count
                    stack.append(reader.stream.data[begin : begin + count])
                elif roles == {"System.IO.BinaryReader::Close"}:
                    if not isinstance(pop(stack), _Reader):
                        raise ManagedPureRatCacheFrontendError(
                            "reader_close_binding_invalid"
                        )
                elif (
                    roles == {"System.Object::.ctor", "System.IO.BinaryReader::.ctor"}
                    and opcode == "newobj"
                ):
                    stream = pop(stack)
                    if not isinstance(stream, _Stream):
                        raise ManagedPureRatCacheFrontendError(
                            "reader_constructor_binding_invalid"
                        )
                    stack.append(_Reader(stream))
                elif resolved.endswith(
                    "System.Reflection.Assembly::GetExecutingAssembly"
                ):
                    stack.append(("assembly",))
                else:
                    raise ManagedPureRatCacheFrontendError("cil_call_role_unsupported")
            elif opcode in {"br", "br.s"}:
                destination = _target(item.operand)
                if destination is None:
                    raise ManagedPureRatCacheFrontendError("cil_branch_target_invalid")
                if destination in dispatch_entries:
                    next_state = _consume_dispatch_entry(
                        destination,
                        dispatch_entries,
                        stack,
                        locals_,
                        dispatch_local,
                    )
                    break
                if destination not in by_offset:
                    raise ManagedPureRatCacheFrontendError("cil_branch_target_missing")
                ip = by_offset[destination]
                advance = False
            elif opcode in {"brtrue", "brtrue.s", "brfalse", "brfalse.s"}:
                condition = _truthy(pop(stack))
                if condition is None:
                    raise ManagedPureRatCacheFrontendError(
                        "cil_branch_condition_nonconcrete"
                    )
                take = condition if opcode.startswith("brtrue") else not condition
                destination = _target(item.operand)
                if take:
                    if destination is None or destination not in by_offset:
                        raise ManagedPureRatCacheFrontendError(
                            "cil_branch_target_missing"
                        )
                    ip = by_offset[destination]
                    advance = False
            elif opcode in {
                "beq",
                "beq.s",
                "bne.un",
                "bne.un.s",
                "bge",
                "bge.s",
                "bge.un",
                "bge.un.s",
                "bgt",
                "bgt.s",
                "bgt.un",
                "bgt.un.s",
                "ble",
                "ble.s",
                "ble.un",
                "ble.un.s",
                "blt",
                "blt.s",
                "blt.un",
                "blt.un.s",
            }:
                right, left = pop(stack), pop(stack)
                if opcode.startswith(("beq", "bne")):
                    comparison = left == right
                    take = comparison if opcode.startswith("beq") else not comparison
                else:
                    if not isinstance(left, int) or not isinstance(right, int):
                        raise ManagedPureRatCacheFrontendError(
                            "cil_branch_comparison_nonconcrete"
                        )
                    unsigned = ".un" in opcode
                    left_value = left & 0xFFFFFFFF if unsigned else _signed(left)
                    right_value = right & 0xFFFFFFFF if unsigned else _signed(right)
                    if opcode.startswith("bge"):
                        take = left_value >= right_value
                    elif opcode.startswith("bgt"):
                        take = left_value > right_value
                    elif opcode.startswith("ble"):
                        take = left_value <= right_value
                    else:
                        take = left_value < right_value
                destination = _target(item.operand)
                if take:
                    if destination is None or destination not in by_offset:
                        raise ManagedPureRatCacheFrontendError(
                            "cil_branch_target_missing"
                        )
                    ip = by_offset[destination]
                    advance = False
            elif opcode == "switch":
                index = pop(stack)
                targets = [_target(value) for value in (item.operand or ())]
                if not isinstance(index, int) or any(
                    value is None for value in targets
                ):
                    raise ManagedPureRatCacheFrontendError("cil_switch_nonconcrete")
                if 0 <= index < len(targets):
                    ip = by_offset[int(targets[index])]
                    advance = False
            elif opcode in {"nop"}:
                pass
            elif opcode in {"ret", "throw", "rethrow"}:
                raise ManagedPureRatCacheFrontendError(
                    "decoder_terminated_before_transform"
                )
            else:
                raise ManagedPureRatCacheFrontendError("cil_opcode_unsupported")
            if advance:
                ip += 1
        else:
            raise ManagedPureRatCacheFrontendError("cil_state_instruction_budget")
        if next_state is None:
            raise ManagedPureRatCacheFrontendError("dispatcher_next_state_missing")
        state = next_state
    raise ManagedPureRatCacheFrontendError("cil_state_budget")


def recover_managed_purerat_cache_frontend(
    data: bytes,
    *,
    clock: Callable[[], float] = time.monotonic,
    max_elapsed_seconds: float = MAX_ELAPSED_SECONDS,
) -> tuple[dict[str, Any], tuple[tuple[int, str], ...]]:
    """real managed PEから完全UTF-16 cacheまでを静的に復元する。"""

    report = _base_report(len(data) if isinstance(data, bytes) else 0)
    if not isinstance(data, bytes) or not data or len(data) > MAX_INPUT_BYTES:
        report["reason"] = "input_bounds"
        return report, ()
    if (
        isinstance(max_elapsed_seconds, bool)
        or not isinstance(max_elapsed_seconds, (int, float))
        or not 0 < max_elapsed_seconds <= MAX_ELAPSED_SECONDS
    ):
        report["reason"] = "elapsed_limit_invalid"
        return report, ()
    deadline = clock() + float(max_elapsed_seconds)
    try:
        preflight = preflight_clr_declarations(data, max_input_bytes=MAX_INPUT_BYTES)
        if preflight.get("accepted") is not True:
            raise ManagedPureRatCacheFrontendError("constructor_preflight_rejected")
        _check_time(deadline, clock)
        pe = dnfile.dnPE(data=data, fast_load=False)
        program = parse_managed_program(
            data,
            max_input_bytes=MAX_INPUT_BYTES,
            max_elapsed_seconds=min(15.0, max_elapsed_seconds),
        )
        normalized = model._normalize_methods(pe, data, deadline, clock)
        binding = _discover_binding(
            data,
            pe,
            program,
            normalized,
            deadline=deadline,
            clock=clock,
        )
        normalized_decoder = next(
            item for item in normalized if item.token == binding.decoder_token
        )
        raw = _raw_method(pe, data, binding.decoder_token)
        key, mask, state_count, instruction_count = _interpret_decoder(
            raw,
            normalized_decoder,
            binding,
            assembly_public_key_state=program.assembly_public_key_state,
            entry_token=program.entry_token,
            deadline=deadline,
            clock=clock,
        )
        _check_time(deadline, clock)
        clear = decrypt_keyed_eaz_resource(
            binding.resource,
            key,
            key_mask=mask[::-1],
            seed=binding.transform_seed,
            addend=binding.transform_addend,
            allow_partial_word=True,
        )
        table = decode_complete_utf16_cache(clear)
        _check_time(deadline, clock)
    except (ManagedPureRatCacheFrontendError, StaticRecoveryError, ValueError) as exc:
        reason = str(exc)
        report["status"] = "rejected"
        report["reason"] = (
            reason
            if reason
            and len(reason) <= 128
            and all(character.isalnum() or character in "_-" for character in reason)
            else "managed_utf16_cache_frontend_failed"
        )
        return report, ()
    except Exception:  # noqa: BLE001 - parser差の詳細を公開せず安定理由へ閉じる。
        report["status"] = "rejected"
        report["reason"] = "managed_utf16_cache_frontend_failed"
        return report, ()

    report.update(
        {
            "status": "recovered_complete_managed_utf16_cache",
            "reason": "secondary_string_transform_not_recovered",
            "recipe": "real_cil_ordered_key_reverse_mask_eaz_complete_utf16_v1",
            "input_sha256": hashlib.sha256(data).hexdigest(),
            "cache_method": {
                "method_token": f"0x{binding.cache_method.token:08x}",
                "method_body_sha256": binding.cache_method.body_sha256,
            },
            "decoder": {
                "method_token": f"0x{binding.decoder_token:08x}",
                "dispatcher_state_count": state_count,
                "interpreted_instruction_count": instruction_count,
                "ordered_overwrite_semantics_verified": True,
                "reverse_mask_verified": True,
                "exact_16_iteration_key_xor_verified": True,
            },
            "resource": {
                "name_sha256": hashlib.sha256(
                    binding.resource_name.encode("utf-8")
                ).hexdigest(),
                "size": len(binding.resource),
                "sha256": hashlib.sha256(binding.resource).hexdigest(),
            },
            "transform": {
                "method_token": f"0x{binding.transform_token:08x}",
                "method_body_sha256": binding.transform_body_sha256,
                "seed": binding.transform_seed,
                "addend": binding.transform_addend,
                "partial_word_profile_verified": True,
            },
            "key_material": {
                "key_final_sha256": hashlib.sha256(key).hexdigest(),
                "mask_final_sha256": hashlib.sha256(mask).hexdigest(),
                "raw_key_material_published": False,
            },
            "cache": {
                "complete_table_consumed": True,
                "complete_table_entry_count": len(table),
                "decoded_string_sha256": [
                    hashlib.sha256(value.encode("utf-8")).hexdigest()
                    for _, value in table
                ],
                "raw_offsets_published": False,
                "raw_strings_published": False,
            },
            "bounded_cil_model_interpreted": True,
        }
    )
    return report, table


__all__ = [
    "ManagedPureRatCacheFrontendError",
    "recover_managed_purerat_cache_frontend",
]
