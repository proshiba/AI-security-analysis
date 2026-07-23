"""ACRStealerの配布層、ファイルポンプ、内包シェルコードを静的解析する。

検体はロードも実行もしない。ZIPの巨大メンバーは先頭の上限付き範囲だけを
ストリーム読取し、PE節境界またはCABヘッダで実データを切り分ける。
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import re
import struct
import zipfile

import pefile

from extractors.common import (
    build_result,
    endpoint_candidates,
    extract_strings,
    sha256_bytes,
    url_candidates,
)

MAX_PREFIX_BYTES = 32 * 1024 * 1024
MAX_ZIP_MEMBERS = 20_000
PUMPED_SIZE_THRESHOLD = 128 * 1024 * 1024
PUMPED_RATIO_THRESHOLD = 50.0
MAX_NATIVE_PAYLOAD_BYTES = 16 * 1024 * 1024

# GhidraでRun -> ProcessRunRequest -> ExecutePrimaryWorkflowを確認したlayout。
# 未確認buildへ固定RVAを流用しない。
REVIEWED_NATIVE_LAYOUTS = {
    "06f6a0dc417bf0c8d1fa54754f53d37d190a3b9bf66658e00a630ae0bb56dfab": {
        "image_base": 0x66540000,
        "table_va": 0x66647180,
        "encoded_va": 0x66647580,
        "destination_va": 0x6658A020,
        "decoded_size": 0xBD153,
    }
}

REVIEWED_ROLES = {
    "06f6a0dc417bf0c8d1fa54754f53d37d190a3b9bf66658e00a630ae0bb56dfab": "native_loader_shellcode",
    "1220d2250778f214b8ef2d37cf6c0904fb6080a42ad4e1e9bd253f84c8e7e10e": "file_pumped_pe_delivery",
    "14ac0c55100d957d1b198583461b2605e6e72c2538039b54c538dc7e356ddce3": "file_pumped_pe_delivery",
    "5fbed74e14ac66724e9d88829ade0c3d7f640288d902f7721eca96eab632d165": "file_pumped_sfx_autoit_delivery",
    "7c9a76145f39a052020aed4eb60927ad678c792c15bdf4f192d36a569e0457f8": "file_pumped_pe_delivery",
    "c4b117f30786d0b328d90c2818e4c454e81d29ed5921d8f8847e80333a12ee86": "file_pumped_pe_delivery",
    "cb336a6e3fc0e9aa62b5768bffc207c09b372546636a5c58057a1b6d0708df06": "sfx_autoit_delivery",
    "b7dacc50bebb59e302a886e3585a521d61c38dd27cfc7de1522bce998cb173f3": "msi_delivery",
    "b2ab8825b84e6f0209cf713dcf7156c93ae82f37a6d9f0ca9072e228825c8d63": "synthetic_go_decoy_or_loader_unconfirmed",
    "31cf473bb93abef0760d4992d45bafcd936edb7c26193c175f8491f8ffaef0e0": "related_payload_zigclipper_reported",
}

ASCII_DOMAIN = re.compile(
    r"(?<![A-Za-z0-9.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:cc|com|net|org|ru|top|xyz|site|online)(?![A-Za-z0-9.-])",
    re.I,
)


@dataclass(frozen=True)
class RecoveredArtifact:
    """メモリー内で復元した1アーティファクト。"""

    kind: str
    name: str
    data: bytes
    metadata: dict[str, object]

    def public(self) -> dict[str, object]:
        """生バイト列を除く公開用メタデータを返す。"""

        return {
            "kind": self.kind,
            "name": self.name,
            "size": len(self.data),
            "sha256": sha256_bytes(self.data),
            **self.metadata,
        }


def _align(value: int, alignment: int) -> int:
    if alignment <= 0:
        raise ValueError("invalid PE file alignment")
    return (value + alignment - 1) // alignment * alignment


def _de_pump_pe(prefix: bytes) -> tuple[bytes | None, dict[str, object]]:
    """上限付きprefixから明白なポンプ節と末尾証明書を除いたPEを返す。"""

    if not prefix.startswith(b"MZ"):
        return None, {"status": "not_pe"}
    try:
        image = pefile.PE(data=prefix, fast_load=True)
    except pefile.PEFormatError:
        return None, {"status": "invalid_pe"}
    alignment = image.OPTIONAL_HEADER.FileAlignment
    patched = bytearray(prefix)
    section_end = image.OPTIONAL_HEADER.SizeOfHeaders
    adjusted: list[dict[str, object]] = []
    for section in image.sections:
        raw_size = int(section.SizeOfRawData)
        virtual_size = int(section.Misc_VirtualSize)
        actual_size = raw_size
        # rawだけがvirtualの8倍超かつ16MB超なら、末尾ポンプとみなす。
        if raw_size > max(16 * 1024 * 1024, virtual_size * 8):
            candidate = _align(virtual_size, alignment)
            if 0 < candidate <= MAX_PREFIX_BYTES:
                actual_size = candidate
                struct.pack_into("<I", patched, section.get_file_offset() + 16, candidate)
                adjusted.append(
                    {
                        "section": section.Name.rstrip(b"\0").decode("ascii", errors="replace"),
                        "declared_raw_size": raw_size,
                        "recovered_raw_size": candidate,
                    }
                )
        section_end = max(section_end, int(section.PointerToRawData) + actual_size)
    if section_end <= 0 or section_end > len(prefix):
        return None, {
            "status": "prefix_limit",
            "required_bytes": section_end,
            "prefix_bytes": len(prefix),
            "adjusted_sections": adjusted,
        }
    security = image.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    struct.pack_into("<II", patched, security.get_file_offset(), 0, 0)
    return bytes(patched[:section_end]), {
        "status": "recovered",
        "section_end": section_end,
        "certificate_removed": bool(security.VirtualAddress or security.Size),
        "adjusted_sections": adjusted,
    }


def _cab_from_prefix(prefix: bytes) -> tuple[bytes | None, dict[str, object]]:
    """prefix内のサイズ整合したMicrosoft CABを1件だけ回収する。"""

    offset = prefix.find(b"MSCF")
    if offset < 0 or offset + 12 > len(prefix):
        return None, {"status": "not_found"}
    size = struct.unpack_from("<I", prefix, offset + 8)[0]
    if size < 36 or size > MAX_PREFIX_BYTES or offset + size > len(prefix):
        return None, {"status": "invalid_or_truncated", "offset": offset, "declared_size": size}
    return prefix[offset : offset + size], {
        "status": "recovered",
        "offset": offset,
        "declared_size": size,
    }


def _recover_pumped_zip(data: bytes) -> tuple[list[RecoveredArtifact], list[dict[str, object]]]:
    artifacts: list[RecoveredArtifact] = []
    observations: list[dict[str, object]] = []
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return artifacts, observations
    members = archive.infolist()
    if len(members) > MAX_ZIP_MEMBERS:
        return artifacts, [{"status": "member_limit", "member_count": len(members)}]
    for member in members:
        ratio = member.file_size / max(member.compress_size, 1)
        if member.is_dir() or member.file_size < PUMPED_SIZE_THRESHOLD or ratio < PUMPED_RATIO_THRESHOLD:
            continue
        record: dict[str, object] = {
            "member": member.filename,
            "declared_size": member.file_size,
            "compressed_size": member.compress_size,
            "compression_ratio": round(ratio, 2),
        }
        try:
            with archive.open(member) as stream:
                prefix = stream.read(MAX_PREFIX_BYTES)
        except (RuntimeError, OSError, zipfile.BadZipFile) as exc:
            record.update({"status": "read_error", "error": type(exc).__name__})
            observations.append(record)
            continue
        recovered, detail = _de_pump_pe(prefix)
        if recovered is not None:
            artifacts.append(
                RecoveredArtifact(
                    "depumped-pe",
                    member.filename,
                    recovered,
                    {"source_declared_size": member.file_size, "depump": detail},
                )
            )
            record.update({"status": "depumped_pe", "recovered_size": len(recovered)})
        else:
            cab, cab_detail = _cab_from_prefix(prefix)
            if cab is not None:
                artifacts.append(
                    RecoveredArtifact(
                        "pumped-pe-cab",
                        member.filename,
                        cab,
                        {"source_declared_size": member.file_size, "cab": cab_detail},
                    )
                )
                record.update({"status": "carved_cab", "recovered_size": len(cab)})
            else:
                record.update(
                    {
                        "status": "prefix_limit",
                        "prefix_bytes": len(prefix),
                        "depump": detail,
                        "cab": cab_detail,
                    }
                )
        observations.append(record)
    return artifacts, observations


def _decode_reviewed_native_loader(data: bytes) -> RecoveredArtifact | None:
    digest = sha256_bytes(data)
    layout = REVIEWED_NATIVE_LAYOUTS.get(digest)
    if layout is None:
        return None
    try:
        image = pefile.PE(data=data, fast_load=True)
        if image.OPTIONAL_HEADER.ImageBase != layout["image_base"]:
            return None
        table_offset = image.get_offset_from_rva(layout["table_va"] - layout["image_base"])
        encoded_offset = image.get_offset_from_rva(layout["encoded_va"] - layout["image_base"])
        destination_offset = image.get_offset_from_rva(
            layout["destination_va"] - layout["image_base"]
        )
        decoded_size = int(layout["decoded_size"])
        if decoded_size <= 0 or decoded_size > MAX_NATIVE_PAYLOAD_BYTES:
            return None
        table = struct.unpack_from("<256I", data, table_offset)
        inverse = {value: index for index, value in enumerate(table)}
        if len(inverse) != 256:
            return None
        encoded = struct.unpack_from(f"<{decoded_size}I", data, encoded_offset)
        decoded = bytearray(data[destination_offset : destination_offset + decoded_size])
        if len(decoded) != decoded_size:
            return None
        unresolved = 0
        for index, value in enumerate(encoded):
            replacement = inverse.get(value)
            if replacement is None:
                # Ghidraで確認したloopも未一致時は既存destination byteを保持する。
                unresolved += 1
                continue
            decoded[index] = replacement
    except (ValueError, struct.error, pefile.PEFormatError):
        return None
    return RecoveredArtifact(
        "dword-substitution-shellcode",
        "reviewed-native-loader",
        bytes(decoded),
        {
            "transform": "256-entry-dword-substitution",
            "table_entries": 256,
            "unresolved_dwords_retained": unresolved,
            "reviewed_layout": digest,
        },
    )


def recover_artifacts(data: bytes) -> tuple[list[RecoveredArtifact], list[dict[str, object]]]:
    """ACRStealer向けの上限付き非実行復元を行う。"""

    artifacts, observations = _recover_pumped_zip(data)
    native = _decode_reviewed_native_loader(data)
    if native is not None:
        artifacts.append(native)
    return artifacts, observations


def _capabilities(blobs: list[bytes]) -> tuple[dict[str, bool], list[str], list[str]]:
    joined = b"\n".join(blob[:MAX_PREFIX_BYTES] for blob in blobs)
    strings = extract_strings(joined, minimum=5)
    lowered = joined.lower()
    capabilities = {
        "browser_collection_markers": any(
            marker in lowered for marker in (b"login data", b"local state", b"cookies", b"web data")
        ),
        "wallet_collection_markers": any(
            marker in lowered for marker in (b"wallet.dat", b"metamask", b"electrum", b"exodus")
        ),
        "dead_drop_resolver_markers": any(
            marker in lowered
            for marker in (b"steamcommunity.com", b"docs.google.com", b"telegra.ph")
        ),
        "legacy_http_route_markers": b"/ujs/" in lowered or b"/up" in lowered,
        "go_runtime": b"go build id:" in lowered or b"runtime.main" in lowered,
        "go_network_package": b"net/http." in lowered or b"net.dial" in lowered,
        "synthetic_overall_strings": lowered.count(b"overall ") >= 8,
    }
    urls = url_candidates(strings)
    endpoints = endpoint_candidates(strings)
    domains = sorted(
        {
            match.group().lower().rstrip(".")
            for value in strings
            for match in ASCII_DOMAIN.finditer(value)
            if not match.group().lower().endswith(("microsoft.com", "digicert.com"))
        }
    )
    return capabilities, urls, sorted(set(endpoints + domains))


def extract(data: bytes, source_name: str = "sample.bin") -> dict:
    """公開可能なACRStealer静的解析結果を返す。"""

    digest = hashlib.sha256(data).hexdigest()
    artifacts, pump_observations = recover_artifacts(data)
    capability_blobs = [data, *(artifact.data for artifact in artifacts)]
    capabilities, urls, network_literals = _capabilities(capability_blobs)
    role = REVIEWED_ROLES.get(digest, "unresolved_acrstealer_related_artifact")
    c2_candidates = [
        value
        for value in urls
        if not any(host in value.lower() for host in ("microsoft.com", "digicert.com"))
    ]
    config = {
        "source_name": source_name,
        "artifact_role": role,
        "reviewed_hash": digest in REVIEWED_ROLES,
        "static_config_recovered": False,
        "c2_liveness_confirmed": False,
        "capabilities": capabilities,
        "pump_observations": pump_observations,
        "recovered_artifacts": [artifact.public() for artifact in artifacts],
        "network_literals": network_literals,
        "c2_candidates": c2_candidates,
    }
    findings: list[dict[str, object]] = [
        {
            "kind": "payload.sha256",
            "value": artifact.public()["sha256"],
            "role": artifact.kind,
            "confidence": "confirmed_static_transform",
        }
        for artifact in artifacts
    ]
    findings.extend(
        {
            "kind": "url",
            "value": value,
            "role": "static_network_literal_candidate",
            "confidence": "candidate_requires_config_corroboration",
        }
        for value in c2_candidates
    )
    limitations = [
        "検体と復元アーティファクトは実行していません。",
        "外部ホスト、C2、dead-drop resolverへ接続していません。",
        "MalwareBazaarのACRStealerタグは配布関係を含み、各ファイル単体がACRStealer本体であることを保証しません。",
        "一般文字列のURLやドメインは設定構造で裏付けられるまでC2候補に留めます。",
    ]
    if not artifacts:
        limitations.append("対応済みファイルポンプまたはレビュー済みnative loader layoutを検出できませんでした。")
    return build_result("acrstealer", data, config, findings, limitations)
