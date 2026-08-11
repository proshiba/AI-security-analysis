"""Extract ValleyRAT configuration indicators across reviewed campaign variants."""

from __future__ import annotations

from extractors.common import (
    build_result,
    endpoint_candidates,
    extract_strings,
    ipv4_candidates,
    valid_host,
)
from extractors.stealer_common import infrastructure_urls
from extractors.valleyrat.nvml_dat import (
    NvmlDatError,
    looks_like_nvml_dat,
    public_recovery_summary,
    recover_nvml_dat,
)


def identify_variant(strings: list[str]) -> str:
    """Identify a config representation without assuming all ValleyRAT builds match."""
    lower = "\n".join(strings).lower()
    if "odaktomk" in lower or all(
        item in lower for item in ("vvas.bin", "loggercollector.dll")
    ):
        return "dll_sideload_vvas_bundle"
    if "config.enc" in lower or "n520" in lower:
        return "single_pe_n520_managed"
    if "silverfox" in lower:
        return "silverfox_related"
    if all(
        item in lower
        for item in ("myappdomainmanager", "initializenewdomain", "enumuilanguagesa")
    ):
        return "appdomainmanager_pixel_loader"
    nvml_markers = ("nvml.dat", "nvml.dll", "runtimebroker.exe")
    nvml_loader_apis = ("queueuserapc", "virtualalloc", "virtualprotect", "readfile")
    if all(item in lower for item in nvml_markers) and sum(
        item in lower for item in nvml_loader_apis
    ) >= 3:
        # raw ISO/IMGとcompact proxy DLLの両方で成立するhash非依存構造。
        # filename共存だけではなく、APC・memory保護・DAT読込みAPIを要求する。
        return "nvml_compact_dat_iso_bundle"
    winos_stage_markers = (
        "ipdatespecial",
        "sedebugprivilege",
        "192.168.1.200",
        "remark",
    )
    if all(item in lower for item in winos_stage_markers):
        return "pdfcore8_winos_recovered_stage"
    return "unresolved_variant"


def decode_vvas_reversed_config(strings: list[str]) -> dict[str, str]:
    """Decode the reviewed reversed key/value config used by vvaS shellcode."""
    for value in strings:
        if ":1p" not in value or ":1o" not in value:
            continue
        fields = {}
        for item in value[::-1].split("|"):
            if ":" in item:
                key, raw = item.split(":", 1)
                fields[key] = raw
        endpoints = {}
        for index in (1, 2, 3):
            host, port = fields.get(f"p{index}"), fields.get(f"o{index}")
            if (
                host
                and port
                and port.isdigit()
                and valid_host(host)
                and host != "127.0.0.1"
                and 0 < int(port) <= 65535
            ):
                endpoints[f"endpoint_{index}"] = f"{host}:{int(port)}"
        return endpoints
    return {}


def extract(data: bytes, name: str = "sample") -> dict:
    """Return static ValleyRAT config candidates without contacting endpoints."""
    strings = extract_strings(data)
    nvml_recovery = None
    if looks_like_nvml_dat(data):
        try:
            nvml_recovery = recover_nvml_dat(data)
        except NvmlDatError:
            # trailer長だけが偶然一致したdataをValleyRATへ昇格しない。
            nvml_recovery = None
    variant = (
        "nvml_compact_dat_winos_stage"
        if nvml_recovery is not None
        else identify_variant(strings)
    )
    decoded = decode_vvas_reversed_config(strings)
    if nvml_recovery is not None:
        decoded = {
            f"endpoint_{index}": endpoint
            for index, endpoint in enumerate(
                nvml_recovery.codemark_config["endpoints"], start=1
            )
        }
    endpoints, urls = endpoint_candidates(strings), infrastructure_urls(strings)
    if not decoded and variant == "unresolved_variant":
        endpoints = []
        urls = []
    if variant == "pdfcore8_winos_recovered_stage" and not decoded:
        # 復元stageに残るRFC1918の既定slotは実運用C2ではない。外層または
        # 実行時更新から注入されたglobal endpointだけを別証跡で公開する。
        endpoints = []
        urls = []
    if decoded:
        endpoints = sorted(set(decoded.values()))
    ips = (
        sorted({item.split(":", 1)[0] for item in endpoints})
        if decoded
        else (ipv4_candidates(strings) if variant == "dll_sideload_vvas_bundle" else [])
    )
    if ips and not decoded:
        endpoints = [item for item in endpoints if item.split(":", 1)[0] in ips]
    findings = [
        {
            "kind": "network.endpoint",
            "value": item,
            "role": "static_config_c2" if decoded else "candidate_c2",
            "confidence": "confirmed_static_config" if decoded else "inferred",
            "source": (
                "nvml_dat_codemark"
                if nvml_recovery is not None
                else "decoded_vvas_config" if decoded else "static_string"
            ),
        }
        for item in endpoints
    ]
    if not decoded:
        findings += [
            {
                "kind": "network.ip",
                "value": item,
                "role": "candidate_c2_host",
                "confidence": "inferred",
                "source": "decoded_static_string",
            }
            for item in ips
        ]
    findings += [
        {
            "kind": "network.url",
            "value": item,
            "role": "config_or_stage_url",
            "confidence": "inferred",
            "source": "static_string",
        }
        for item in urls
    ]
    return build_result(
        "valleyrat",
        data,
        {
            "variant": variant,
            "decoded_vvas": decoded,
            "static_config_recovered": bool(decoded),
            "c2_liveness_confirmed": False,
            "source_name": name,
            "endpoints": endpoints,
            "ipv4": ips,
            "urls": urls,
            "nvml_dat": (
                public_recovery_summary(nvml_recovery, data)
                if nvml_recovery is not None
                else None
            ),
            "placeholder_defaults_excluded": (
                ["192.168.1.200:6669", "192.168.1.200:9999"]
                if variant == "pdfcore8_winos_recovered_stage"
                else []
            ),
        },
        findings,
        [
            "反転形式を構造どおり復号した値だけを静的設定として確認済みにします。現在の稼働状態と所有者は未確認です。",
            "一般文字列だけから得た値はC2候補に留め、未解決外層では公開しません。",
            "Winos復元stageのRFC1918既定slotは実運用C2として公開しません。",
            "NVML.DATは復号stageを実行せず、codemarkで構造検証できたslotだけを静的設定として採用します。",
        ],
    )
