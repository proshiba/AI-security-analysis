"""KMTA形式を扱うnative handoff loaderからpayloadを静的復元する。

検体をload・実行・emulateせず、x64 PE export内のRIP相対byte参照と、
非実行sectionに置かれた連続key／IV materialだけを候補にする。復号結果は
PKCS#7、KMTA header、path長、PE exact extent、ImageBase／SizeOfImageの
全条件が一致した場合だけ返す。
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

try:
    import capstone
    from capstone import x86_const
except ImportError:  # pragma: no cover - dependency statusをreportで返す
    capstone = None
    x86_const = None

try:
    import pefile
except ImportError:  # pragma: no cover - dependency statusをreportで返す
    pefile = None

try:
    from Cryptodome.Cipher import AES
except ImportError:  # pragma: no cover - dependency statusをreportで返す
    AES = None

from unpackers.bounded_pe_scan import inspect_structural_pe_extent

MAX_LOADER_SIZE = 32 * 1024 * 1024
MAX_CIPHERTEXT_SIZE = 64 * 1024 * 1024
MAX_EXPORTS = 256
MAX_EXPORT_SCAN_BYTES = 256 * 1024
MAX_INSTRUCTIONS = 100_000
MAX_RECIPE_CANDIDATES = 64
MAX_DECRYPT_WORK = 256 * 1024 * 1024
MAX_KMTA_HEADER_SIZE = 64 * 1024
MAX_PATH_BYTES = 16 * 1024

_IMAGE_FILE_MACHINE_AMD64 = 0x8664
_IMAGE_SCN_MEM_EXECUTE = 0x20000000
_KEY_SIZE = 32
_IV_SIZE = 16
_RECIPE_SIZE = _KEY_SIZE + _IV_SIZE


@dataclass(frozen=True)
class _Recipe:
    """code参照で拘束されたAES key／IV候補。"""

    export_rva: int
    material_rva: int
    material: bytes


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _base_report(status: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": status,
        "executed": False,
        "emulated": False,
        "network_contacted": False,
    }


def _section_for_rva(image: object, rva: int, size: int = 1) -> object | None:
    if rva < 0 or size < 1:
        return None
    end = rva + size
    if end < rva:
        return None
    for section in image.sections:
        start = int(section.VirtualAddress)
        raw_size = int(section.SizeOfRawData)
        if start <= rva and end <= start + raw_size:
            return section
    return None


def _mapped_bytes(
    data: bytes, image: object, rva: int, size: int, *, executable: bool | None
) -> bytes | None:
    section = _section_for_rva(image, rva, size)
    if section is None:
        return None
    is_executable = bool(int(section.Characteristics) & _IMAGE_SCN_MEM_EXECUTE)
    if executable is not None and is_executable != executable:
        return None
    offset = int(section.PointerToRawData) + rva - int(section.VirtualAddress)
    if offset < 0 or offset + size > len(data):
        return None
    return data[offset : offset + size]


def _consecutive_runs(values: set[int]) -> list[tuple[int, int]]:
    ordered = sorted(values)
    if not ordered:
        return []
    runs: list[tuple[int, int]] = []
    start = previous = ordered[0]
    for value in ordered[1:]:
        if value != previous + 1:
            runs.append((start, previous + 1))
            start = value
        previous = value
    runs.append((start, previous + 1))
    return runs


def _export_ranges(image: object) -> tuple[list[tuple[int, int]], str | None]:
    directory = getattr(image, "DIRECTORY_ENTRY_EXPORT", None)
    symbols = getattr(directory, "symbols", ()) if directory is not None else ()
    if len(symbols) > MAX_EXPORTS:
        return [], "export_limit_blocked"

    executable_rvas: set[int] = set()
    for symbol in symbols:
        if getattr(symbol, "forwarder", None):
            continue
        rva = int(symbol.address)
        section = _section_for_rva(image, rva)
        if section is None:
            continue
        if int(section.Characteristics) & _IMAGE_SCN_MEM_EXECUTE:
            executable_rvas.add(rva)

    ordered = sorted(executable_rvas)
    ranges: list[tuple[int, int]] = []
    for index, rva in enumerate(ordered):
        section = _section_for_rva(image, rva)
        if section is None:
            continue
        section_end = int(section.VirtualAddress) + int(section.SizeOfRawData)
        end = section_end
        if index + 1 < len(ordered) and ordered[index + 1] < section_end:
            end = ordered[index + 1]
        end = min(end, rva + MAX_EXPORT_SCAN_BYTES)
        if rva < end:
            ranges.append((rva, end))
    return ranges, None


def _referenced_recipes(
    loader: bytes, image: object
) -> tuple[list[_Recipe], dict[str, object], str | None]:
    ranges, range_error = _export_ranges(image)
    if range_error is not None:
        return [], {}, range_error
    if not ranges:
        return [], {"executable_exports_scanned": 0}, None

    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    image_base = int(image.OPTIONAL_HEADER.ImageBase)
    instruction_count = 0
    candidates: list[_Recipe] = []
    candidate_material: set[bytes] = set()
    reference_run_count = 0

    for export_rva, end_rva in ranges:
        code = _mapped_bytes(
            loader,
            image,
            export_rva,
            end_rva - export_rva,
            executable=True,
        )
        if code is None:
            continue
        references: set[int] = set()
        try:
            instructions = decoder.disasm(code, image_base + export_rva)
            for instruction in instructions:
                instruction_count += 1
                if instruction_count > MAX_INSTRUCTIONS:
                    return [], {}, "instruction_limit_blocked"
                if instruction.mnemonic != "mov" or len(instruction.operands) < 2:
                    continue
                for operand in instruction.operands[1:]:
                    if (
                        operand.type == x86_const.X86_OP_MEM
                        and operand.mem.base == x86_const.X86_REG_RIP
                        and operand.size == 1
                    ):
                        references.add(
                            instruction.address
                            + instruction.size
                            + int(operand.mem.disp)
                        )
        except (AttributeError, TypeError, ValueError, capstone.CsError):
            continue

        for start_va, end_va in _consecutive_runs(references):
            if end_va - start_va < _RECIPE_SIZE:
                continue
            reference_run_count += 1
            for material_va in range(start_va, end_va - _RECIPE_SIZE + 1):
                material_rva = material_va - image_base
                material = _mapped_bytes(
                    loader,
                    image,
                    material_rva,
                    _RECIPE_SIZE,
                    executable=False,
                )
                if material is None or material in candidate_material:
                    continue
                candidate_material.add(material)
                candidates.append(
                    _Recipe(
                        export_rva=export_rva,
                        material_rva=material_rva,
                        material=material,
                    )
                )
                if len(candidates) > MAX_RECIPE_CANDIDATES:
                    return [], {}, "recipe_candidate_limit_blocked"

    return (
        candidates,
        {
            "executable_exports_scanned": len(ranges),
            "instructions_inspected": instruction_count,
            "contiguous_reference_runs": reference_run_count,
            "referenced_key_iv_candidates": len(candidates),
        },
        None,
    )


def _executable_marker_present(loader: bytes, image: object) -> bool:
    for section in image.sections:
        if not int(section.Characteristics) & _IMAGE_SCN_MEM_EXECUTE:
            continue
        start = int(section.PointerToRawData)
        size = int(section.SizeOfRawData)
        if (
            0 <= start <= len(loader)
            and start + size <= len(loader)
            and b"KMTA" in loader[start : start + size]
        ):
            return True
    return False


def _parse_kmta_plaintext(
    plaintext: bytes,
) -> tuple[dict[str, object], bytes] | None:
    if len(plaintext) < 0x28 + 0x200:
        return None
    try:
        (
            magic,
            header_size,
            preferred_base,
            expected_image_size,
            options,
            ansi_size,
            wide_size,
        ) = struct.unpack_from("<4sIQQQII", plaintext)
    except struct.error:
        return None
    if magic != b"KMTA":
        return None
    if not 1 <= ansi_size <= MAX_PATH_BYTES:
        return None
    if not 2 <= wide_size <= MAX_PATH_BYTES or wide_size % 2:
        return None
    if header_size != 0x28 + ansi_size + wide_size:
        return None
    if not 0x28 < header_size <= MAX_KMTA_HEADER_SIZE:
        return None
    if header_size + 0x200 > len(plaintext):
        return None

    ansi_path = plaintext[0x28 : 0x28 + ansi_size]
    wide_path = plaintext[0x28 + ansi_size : header_size]
    if not ansi_path.endswith(b"\0") or b"\0" in ansi_path[:-1]:
        return None
    if not wide_path.endswith(b"\0\0"):
        return None
    try:
        ansi_text = ansi_path[:-1].decode("utf-8")
        wide_text = wide_path[:-2].decode("utf-16le")
    except UnicodeDecodeError:
        return None
    if not wide_text or "\0" in wide_text or ansi_text != wide_text:
        return None

    payload = plaintext[header_size:]
    extent = inspect_structural_pe_extent(payload, max_extent=MAX_CIPHERTEXT_SIZE)
    if extent.extent is None or int(extent.extent) != len(payload):
        return None
    try:
        image = pefile.PE(data=payload, fast_load=True)
    except (AttributeError, ValueError, pefile.PEFormatError):
        return None
    if image.FILE_HEADER.Machine != _IMAGE_FILE_MACHINE_AMD64:
        return None
    if image.OPTIONAL_HEADER.Magic != 0x20B:
        return None
    if int(image.OPTIONAL_HEADER.ImageBase) != preferred_base:
        return None
    if int(image.OPTIONAL_HEADER.SizeOfImage) != expected_image_size:
        return None

    return (
        {
            "header_size": header_size,
            "ansi_path_size": ansi_size,
            "utf16_path_size": wide_size,
            "options": options,
            "pe_machine": "0x8664",
            "pe_image_base": f"0x{preferred_base:x}",
            "pe_image_size": expected_image_size,
            "pe_section_count": int(image.FILE_HEADER.NumberOfSections),
            "pe_validation": extent.reason,
            "decoded_size": len(payload),
            "decoded_sha256": _sha256(payload),
        },
        payload,
    )


def recover_native_kmta_payload(
    loader: bytes, ciphertext: bytes
) -> tuple[dict[str, object], bytes | None]:
    """native loaderの静的constant dataflowからKMTA内包PEを復元する。"""

    if type(loader) is not bytes or type(ciphertext) is not bytes:
        return _base_report("invalid_input"), None
    if not 1 <= len(loader) <= MAX_LOADER_SIZE:
        return _base_report("loader_size_blocked"), None
    if not 16 <= len(ciphertext) <= MAX_CIPHERTEXT_SIZE:
        return _base_report("ciphertext_size_blocked"), None
    if len(ciphertext) % 16:
        return _base_report("ciphertext_alignment_mismatch"), None
    if capstone is None or x86_const is None or pefile is None or AES is None:
        return _base_report("dependency_missing"), None

    try:
        image = pefile.PE(data=loader, fast_load=False)
    except (AttributeError, ValueError, pefile.PEFormatError):
        return _base_report("loader_pe_invalid"), None
    if (
        image.FILE_HEADER.Machine != _IMAGE_FILE_MACHINE_AMD64
        or image.OPTIONAL_HEADER.Magic != 0x20B
    ):
        return _base_report("loader_architecture_unsupported"), None
    if not _executable_marker_present(loader, image):
        return _base_report("loader_profile_not_found"), None

    recipes, scan_report, scan_error = _referenced_recipes(loader, image)
    if scan_error is not None:
        report = _base_report(scan_error)
        report.update(scan_report)
        return report, None
    if not recipes:
        report = _base_report("loader_profile_not_found")
        report.update(scan_report)
        return report, None
    if len(recipes) * len(ciphertext) > MAX_DECRYPT_WORK:
        report = _base_report("decrypt_work_limit_blocked")
        report.update(scan_report)
        return report, None

    matches: list[tuple[_Recipe, dict[str, object], bytes]] = []
    for recipe in recipes:
        key = recipe.material[:_KEY_SIZE]
        iv = recipe.material[_KEY_SIZE:]
        plaintext = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
        padding = plaintext[-1]
        if not 1 <= padding <= 16:
            continue
        if plaintext[-padding:] != bytes([padding]) * padding:
            continue
        parsed = _parse_kmta_plaintext(plaintext[:-padding])
        if parsed is None:
            continue
        info, payload = parsed
        matches.append((recipe, info, payload))

    unique: dict[str, tuple[_Recipe, dict[str, object], bytes]] = {}
    for match in matches:
        unique[_sha256(match[2])] = match
    if len(unique) != 1:
        report = _base_report(
            "ambiguous_payloads" if len(unique) > 1 else "payload_validation_failed"
        )
        report.update(scan_report)
        report["candidate_recipe_matches"] = len(matches)
        report["unique_payload_count"] = len(unique)
        return report, None

    recipe, info, payload = next(iter(unique.values()))
    report = _base_report("pe_recovered")
    report.update(scan_report)
    report.update(
        {
            "candidate_recipe_matches": len(matches),
            "unique_payload_count": 1,
            "cipher": "AES-256-CBC",
            "padding": "PKCS7",
            "key_iv_source": "x64_export_rip_relative_byte_reference_run",
            "export_rva": f"0x{recipe.export_rva:x}",
            "material_rva": f"0x{recipe.material_rva:x}",
            "material_sha256": _sha256(recipe.material),
            "kmta": info,
        }
    )
    return report, payload
