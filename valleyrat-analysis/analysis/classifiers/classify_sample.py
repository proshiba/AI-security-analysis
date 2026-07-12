from __future__ import annotations

import argparse
import hashlib
import io
import json
import zipfile
from pathlib import Path

import olefile


CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def inspect_zip(data: bytes) -> tuple[dict, list[dict]]:
    candidates: list[dict] = []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = [item for item in archive.infolist() if not item.is_dir()]
        names = [Path(item.filename).name for item in infos]
        lower = {name.lower() for name in names}
        observations = {"member_count": len(infos), "members": names}

        required = {"chgport.exe", "loggercollector.dll", "vvas.bin"}
        if required.issubset(lower):
            candidates.append({
                "campaign_type": "dll_sideload_vvas_bundle",
                "confidence": "high",
                "reasons": ["chgport.exe, LoggerCollector.dll and vvaS.bin coexist"],
            })

        for info in infos:
            if not info.filename.lower().endswith(".msi"):
                continue
            msi = archive.read(info)
            if not msi.startswith(bytes.fromhex("d0cf11e0a1b11ae1")):
                continue
            ole = olefile.OleFileIO(io.BytesIO(msi))
            kinds: set[str] = set()
            for stream in ole.listdir(streams=True, storages=False):
                head = ole.openstream(stream).read(8)
                if head.startswith(b"MSCF"):
                    kinds.add("cab")
                elif head.startswith(b"MZ"):
                    kinds.add("pe")
            campaign = "msi_embedded_cab_custom_actions" if {"cab", "pe"}.issubset(kinds) else "msi_unknown"
            candidates.append({
                "campaign_type": campaign,
                "confidence": "high" if campaign != "msi_unknown" else "medium",
                "reasons": ["MSI/OLE", *sorted(f"embedded_{kind}" for kind in kinds)],
                "msi_member": info.filename,
            })

        if len(infos) == 1 and not candidates:
            member = archive.read(infos[0])
            if zipfile.is_zipfile(io.BytesIO(member)):
                nested_observations, nested_candidates = inspect_zip(member)
                observations["nested_zip"] = nested_observations
                candidates.extend(nested_candidates)
            elif member.startswith(b"MZ"):
                candidates.append({
                    "campaign_type": "single_pe",
                    "confidence": "medium",
                    "reasons": ["single PE member"],
                })
    return observations, candidates


def classify(path: Path, registry: Path) -> dict:
    data = path.read_bytes()
    sample_hash = sha256_bytes(data)
    known = json.loads(registry.read_text(encoding="utf-8-sig"))["malware_types"]
    observations: dict = {"sha256": sample_hash, "size": len(data), "is_zip": zipfile.is_zipfile(io.BytesIO(data))}
    candidates: list[dict] = []
    if observations["is_zip"]:
        archive_observations, candidates = inspect_zip(data)
        observations["archive"] = archive_observations
    if not candidates:
        candidates = [{"campaign_type": "unknown", "confidence": "low", "reasons": ["no structural handler matched"]}]
    candidates.sort(key=lambda item: CONFIDENCE_ORDER[item["confidence"]])

    family = "unknown"
    family_confidence = "low"
    attribution_basis = "none"
    for family_id, metadata in known.items():
        if sample_hash in metadata.get("known_sample_sha256", []):
            family, family_confidence, attribution_basis = family_id, "high", "known_sha256"
            break
    if family == "unknown" and candidates[0]["campaign_type"] in {
        "dll_sideload_vvas_bundle", "msi_embedded_cab_custom_actions"
    }:
        family, family_confidence, attribution_basis = "valleyrat", "medium", "known_chain_structure_only"

    return {
        "sample": str(path),
        "malware_type": family,
        "malware_type_confidence": family_confidence,
        "attribution_basis": attribution_basis,
        "campaign_type": candidates[0]["campaign_type"],
        "campaign_confidence": candidates[0]["confidence"],
        "candidates": candidates,
        "observations": observations,
        "family_label_used_to_select_campaign": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Classify malware type and campaign from hashes and package structure.")
    parser.add_argument("--sample", required=True, type=Path)
    parser.add_argument("--registry", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = classify(args.sample, args.registry)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
