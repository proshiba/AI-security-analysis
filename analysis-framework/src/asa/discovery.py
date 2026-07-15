"""Offline discovery that emits normalized facts before family selection."""

from __future__ import annotations

import hashlib
import io
import re
import zipfile
from pathlib import Path, PurePosixPath

import pyzipper

from extractors.common import extract_strings

MAX_MEMBER = 256 * 1024 * 1024
SCRIPT_SUFFIXES = {".js", ".jse", ".vbs", ".vbe", ".ps1", ".hta", ".osascript", ".applescript", ".vba"}


def safe_member_name(name: str) -> str:
    """Reject archive traversal, absolute, drive-qualified, and empty names."""
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if not normalized or normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        raise ValueError(f"unsafe archive member: {name}")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"unsafe archive member: {name}")
    return normalized


def read_submission(path: Path, password: str = "infected") -> tuple[bytes, str, dict]:
    """Read a raw file or one authenticated single-member ZIP without extraction."""
    outer = path.read_bytes()
    metadata = {"outer_sha256": hashlib.sha256(outer).hexdigest(), "outer_size": len(outer)}
    if not zipfile.is_zipfile(io.BytesIO(outer)):
        return outer, path.name, metadata
    with pyzipper.AESZipFile(io.BytesIO(outer)) as archive:
        infos = [item for item in archive.infolist() if not item.is_dir()]
        if len(infos) != 1:
            raise ValueError(f"expected one archive member, found {len(infos)}")
        info = infos[0]
        name = safe_member_name(info.filename)
        if info.file_size > MAX_MEMBER:
            raise ValueError(f"archive member exceeds {MAX_MEMBER} bytes")
        data = archive.read(info, pwd=password.encode())
        if len(data) != info.file_size:
            raise ValueError("archive member size mismatch")
    metadata.update({"inner_sha256": hashlib.sha256(data).hexdigest(), "inner_size": len(data)})
    return data, name, metadata


def infer_family(strings_ci: list[str]) -> str | None:
    """Infer only families with sufficiently distinctive static markers."""
    text = "\n".join(strings_ci)
    if sum(marker in text for marker in ("rpsgwra{l", "[iljvvrsrel", "tvdqhg''''")) >= 3:
        return "spyglace"
    if all(item in text for item in ("mx-go/internal/mail", "mx-go/internal/control", "mx-go/internal/remote")):
        return "mx-go"
    if any(item in text for item in ("quasar.client", "xclient.core")) and "reconnectdelay" in text:
        return "venomrat"
    if any(item in text for item in ("ledger/live/", "security dump-keychain")) and any(
        item in text for item in ("keychain", "osascript", "login data")
    ):
        return "amosstealer"
    if any(item in text for item in ("lummac2", "lumma stealer")):
        return "lummastealer"
    if any(item in text for item in ("remusstealer", "remus stealer")):
        return "remusstealer"
    if any(item in text for item in ("information.txt", "passwords.txt")) and "wallet" in text:
        return "vidar"
    if any(item in text for item in ("formbook", "xloader")):
        return "formbook"
    if any(item in text for item in ("remcos agent", "rmc-")):
        return "remcosrat"
    if any(item in text for item in ("agenttesla", "otnmpxnddvnptbn")):
        return "agenttesla"
    if any(item in text for item in ("vvas.bin", "odaktomk", "n520")):
        return "valleyrat"
    return None


def infer_campaign(family: str | None, strings_ci: list[str], member_names: list[str]) -> str | None:
    """Infer reviewed campaign shapes while preserving unknown variants."""
    text, names = "\n".join(strings_ci), {item.lower() for item in member_names}
    name = next(iter(names), "")
    suffix = Path(name).suffix.lower()
    if family == "spyglace":
        if "sgznqhtgnghvmzxponum" in text:
            return "apt_c60_repository_xor"
        if suffix == ".lnk" and any(item in text for item in ("mshta", "cdn.jsdelivr.net", "certutil")):
            return "apt_c60_lnk_mshta"
        return "direct_spyglace_pe"
    if family == "valleyrat" and {"chgport.exe", "loggercollector.dll", "vvas.bin"} <= names:
        return "dll_sideload_vvas_bundle"
    if family == "mx-go" and "/api/v1/heartbeat_direct" in text:
        return "remotely_controlled_bulk_email_spam_bot"
    if family == "venomrat" and "quasar.client" in text:
        return "direct_dotnet_quasar_module"
    if family in {"formbook", "amosstealer"} and suffix in SCRIPT_SUFFIXES:
        return "script_delivery"
    if family in {"formbook", "amosstealer"} and suffix in {".xlsm", ".docm"}:
        return "macro_office_delivery"
    if family == "amosstealer" and suffix in {".macho", ".dylib"}:
        return "direct_macho"
    if family == "vidar" and suffix == ".zip":
        return "nested_zip_delivery"
    if family == "lummastealer":
        return "go_pe_loader" if "go build id" in text or "runtime.main" in text else "packed_native_pe"
    if family == "remusstealer" and suffix == ".7z":
        return "encrypted_7z_delivery"
    if family == "remusstealer" and ("go build id" in text or "runtime.main" in text):
        return "go_pe_loader"
    if family in {"formbook", "vidar", "remusstealer"} and suffix in {".exe", ".dll"}:
        return "direct_pe_or_pe_loader"
    return None


def discover(
    path: Path, password: str = "infected", family_hint: str | None = None, campaign_hint: str | None = None
) -> tuple[bytes, dict]:
    """Return normalized discovery facts and retained in-memory bytes."""
    data, name, metadata = read_submission(path, password)
    strings = extract_strings(data)
    strings_ci = [item.lower() for item in strings]
    member_names = [name]
    family = family_hint or infer_family(strings_ci)
    campaign = campaign_hint or infer_campaign(family, strings_ci, member_names)
    facts = {
        "submission": {**metadata, "name": name, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)},
        "classification": {"family_hint": family, "campaign_hint": campaign},
        "container": {"member_names_ci": [item.lower() for item in member_names]},
        "static": {"strings_ci": strings_ci},
    }
    return data, facts
