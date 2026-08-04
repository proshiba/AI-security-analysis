"""StealC設定抽出と新旧module役割判定を統合する。"""

from extractors.stealc.extractor import extract as extract_v1
from extractors.stealc.structural import classify_module_role, protocol_guidance


def extract(data: bytes, source_name: str = "sample.bin") -> dict:
    """v1設定抽出を保ったまま、v2以降の構造証拠を追加する。"""
    result = extract_v1(data, source_name)
    structural_profile = classify_module_role(data)
    result["config"]["structural_profile"] = structural_profile
    result["config"]["protocol_analysis"] = protocol_guidance(structural_profile)
    if structural_profile["module_role"] == "chrome_app_bound_key_helper":
        result["limitations"].append(
            "最深の復元PEはChrome App-Bound Encryption helperであり、"
            "最深layerがC2 coreであることを意味しません。"
        )
    return result


__all__ = ["classify_module_role", "extract"]
