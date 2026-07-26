from __future__ import annotations

"""Malware-Traffic-Analysis.net のPCAPを安全にオフライン解析する。"""

import argparse
import csv
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.parse
from collections import Counter, defaultdict
from datetime import date, datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Iterable


MANIFEST = Path()
RESULTS = Path()
WORK_ROOT = Path()
SEVEN_ZIP = Path(r"C:\Program Files\7-Zip\7z.exe")
TSHARK = Path(r"C:\Program Files\Wireshark\tshark.exe")
CAPINFOS = Path(r"C:\Program Files\Wireshark\capinfos.exe")
ANALYSIS_DATE = date.today()
MAX_RECORDS = 5000


FAMILY_PATTERNS = {
    "agenttesla": ("agenttesla", "agenttesla-style"),
    "asyncrat": ("async-rat", "asyncrat"),
    "formbook-xloader": ("xloader", "formbook"),
    "ghostweaver-rat": ("ghostweaver",),
    "guloader": ("guloader",),
    "koi-stealer": ("koi-stealer", "koi-loader"),
    "lumma": ("lumma",),
    "masslogger": ("masslogger",),
    "mintsloader": ("mintsloader",),
    "netsupport-rat": ("netsupport",),
    "njrat": ("njrat",),
    "phantomstealer": ("phantomstealer",),
    "raspberry-robin": ("raspberry-robin",),
    "remcosrat": ("remcos",),
    "rhadamanthys": ("rhadamanthys",),
    "sectop-rat": ("sectop", "arechclient"),
    "stealc": ("stealc",),
    "vip-recovery": ("vip-recovery", "vip recovery"),
    "xworm": ("xworm",),
}


def atomic_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def sha256_file(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def run(command: list[str], *, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )


def list_members(archive: Path, password: str) -> list[dict[str, object]]:
    process = run([str(SEVEN_ZIP), "l", "-slt", f"-p{password}", "--", str(archive)])
    if process.returncode != 0:
        raise RuntimeError(f"7z list failed rc={process.returncode}")
    records: list[dict[str, object]] = []
    current: dict[str, object] = {}
    in_members = False
    for line in process.stdout.splitlines():
        if line == "----------":
            in_members = True
            current = {}
            continue
        if not in_members:
            continue
        if not line.strip():
            if current:
                records.append(current)
                current = {}
            continue
        if " = " not in line:
            continue
        key, value = line.split(" = ", 1)
        current[key] = value
    if current:
        records.append(current)

    pcaps: list[dict[str, object]] = []
    for record in records:
        name = str(record.get("Path", ""))
        path = PurePosixPath(name.replace("\\", "/"))
        if path.is_absolute() or ".." in path.parts or (path.parts and ":" in path.parts[0]):
            raise ValueError("archive contains unsafe member path")
        if path.suffix.lower() not in {".pcap", ".pcapng", ".cap"}:
            continue
        record["Size"] = int(str(record.get("Size", "0")) or 0)
        pcaps.append(record)
    return sorted(pcaps, key=lambda item: (int(item["Size"]), str(item["Path"])), reverse=True)


def extract_member(archive: Path, member: str, password: str, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    process = run(
        [
            str(SEVEN_ZIP),
            "x",
            "-y",
            f"-p{password}",
            f"-o{destination}",
            str(archive),
            member,
        ],
        timeout=600,
    )
    if process.returncode != 0:
        raise RuntimeError(f"7z extract failed rc={process.returncode}")
    output = (destination / Path(member.replace("/", os.sep))).resolve()
    root = destination.resolve()
    if root not in output.parents:
        raise ValueError("extracted path escaped work root")
    if not output.is_file():
        raise FileNotFoundError(output)
    return output


def capinfos(path: Path) -> dict[str, object]:
    process = run([str(CAPINFOS), "-Tm", str(path)], timeout=300)
    if process.returncode != 0:
        raise RuntimeError(f"capinfos failed rc={process.returncode}")
    rows = list(csv.DictReader(process.stdout.splitlines()))
    if len(rows) != 1:
        raise ValueError("unexpected capinfos output")
    row = rows[0]
    integer_keys = {"Number of packets", "File size (bytes)", "Data size (bytes)"}
    float_keys = {"Capture duration (seconds)", "Average packet rate (packets/sec)"}
    result: dict[str, object] = dict(row)
    for key in integer_keys:
        try:
            result[key] = int(str(row.get(key, "0")))
        except ValueError:
            pass
    for key in float_keys:
        try:
            result[key] = float(str(row.get(key, "0")))
        except ValueError:
            pass
    return result


def tshark_rows(
    pcap: Path,
    fields: list[str],
    *,
    display_filter: str | None = None,
) -> Iterable[list[str]]:
    command = [
        str(TSHARK),
        "-n",
        "-r",
        str(pcap),
    ]
    if display_filter:
        command.extend(["-Y", display_filter])
    command.extend(
        [
            "-T",
            "fields",
            "-E",
            "separator=/t",
            "-E",
            "occurrence=f",
        ]
    )
    for field in fields:
        command.extend(["-e", field])
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    assert process.stdout is not None
    for line in process.stdout:
        values = line.rstrip("\r\n").split("\t")
        if len(values) < len(fields):
            values.extend([""] * (len(fields) - len(values)))
        yield values[: len(fields)]
    stderr = process.stderr.read() if process.stderr else ""
    returncode = process.wait()
    if returncode != 0:
        raise RuntimeError(f"tshark failed rc={returncode}: {stderr[:200]}")


def address(value4: str, value6: str) -> str:
    return value4 or value6


def port(tcp: str, udp: str) -> str:
    return tcp or udp


def private_address(value: str) -> bool | None:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return None


def packet_inventory(pcap: Path) -> dict[str, object]:
    fields = [
        "frame.time_epoch",
        "frame.len",
        "_ws.col.Protocol",
        "ip.src",
        "ipv6.src",
        "ip.dst",
        "ipv6.dst",
        "tcp.srcport",
        "tcp.dstport",
        "udp.srcport",
        "udp.dstport",
        "tcp.stream",
        "udp.stream",
    ]
    protocols: Counter[str] = Counter()
    endpoints: dict[str, dict[str, int]] = defaultdict(lambda: {"sent_packets": 0, "sent_bytes": 0, "received_packets": 0, "received_bytes": 0})
    conversations: dict[tuple[str, str, str, str, str], dict[str, object]] = {}
    first_epoch: float | None = None
    last_epoch: float | None = None
    for values in tshark_rows(pcap, fields):
        epoch_s, length_s, protocol, ip4_src, ip6_src, ip4_dst, ip6_dst, tcp_src, tcp_dst, udp_src, udp_dst, tcp_stream, udp_stream = values
        try:
            epoch = float(epoch_s)
            length = int(length_s)
        except ValueError:
            continue
        first_epoch = epoch if first_epoch is None else min(first_epoch, epoch)
        last_epoch = epoch if last_epoch is None else max(last_epoch, epoch)
        protocols[protocol or "UNKNOWN"] += 1
        src = address(ip4_src, ip6_src)
        dst = address(ip4_dst, ip6_dst)
        if not src or not dst:
            continue
        endpoints[src]["sent_packets"] += 1
        endpoints[src]["sent_bytes"] += length
        endpoints[dst]["received_packets"] += 1
        endpoints[dst]["received_bytes"] += length
        transport = "tcp" if tcp_src or tcp_dst else "udp" if udp_src or udp_dst else "ip"
        src_port = port(tcp_src, udp_src)
        dst_port = port(tcp_dst, udp_dst)
        stream = tcp_stream or udp_stream
        key = (transport, src, src_port, dst, dst_port)
        record = conversations.setdefault(
            key,
            {
                "transport": transport,
                "src": src,
                "src_port": src_port,
                "dst": dst,
                "dst_port": dst_port,
                "stream_first": stream,
                "packets": 0,
                "bytes": 0,
                "first_epoch": epoch,
                "last_epoch": epoch,
            },
        )
        record["packets"] = int(record["packets"]) + 1
        record["bytes"] = int(record["bytes"]) + length
        record["first_epoch"] = min(float(record["first_epoch"]), epoch)
        record["last_epoch"] = max(float(record["last_epoch"]), epoch)
    endpoint_rows = []
    for host, counts in endpoints.items():
        endpoint_rows.append({"host": host, "is_private": private_address(host), **counts})
    return {
        "protocol_packet_counts": dict(protocols.most_common()),
        "endpoint_count": len(endpoint_rows),
        "top_endpoints": sorted(endpoint_rows, key=lambda row: int(row["sent_bytes"]) + int(row["received_bytes"]), reverse=True)[:100],
        "conversation_count": len(conversations),
        "top_directional_conversations": sorted(conversations.values(), key=lambda row: int(row["bytes"]), reverse=True)[:200],
        "first_epoch": first_epoch,
        "last_epoch": last_epoch,
    }


def dns_inventory(pcap: Path) -> dict[str, object]:
    fields = [
        "frame.number",
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "dns.flags.response",
        "dns.qry.name",
        "dns.qry.type",
        "dns.a",
        "dns.aaaa",
        "dns.cname",
        "dns.resp.ttl",
        "dns.flags.rcode",
    ]
    names: dict[str, dict[str, object]] = {}
    total = 0
    for values in tshark_rows(pcap, fields, display_filter="dns"):
        total += 1
        frame, epoch, src, dst, response, name, qtype, ipv4, ipv6, cname, ttl, rcode = values
        normalized = name.rstrip(".").lower()
        if not normalized:
            continue
        record = names.setdefault(
            normalized,
            {"name": normalized, "queries": 0, "responses": 0, "qtypes": set(), "answers": set(), "cnames": set(), "ttls": set(), "rcodes": set()},
        )
        record["responses" if response == "1" else "queries"] = int(record["responses" if response == "1" else "queries"]) + 1
        if qtype:
            record["qtypes"].add(qtype)
        for answer in (ipv4, ipv6):
            if answer:
                record["answers"].add(answer)
        if cname:
            record["cnames"].add(cname.rstrip(".").lower())
        if ttl:
            record["ttls"].add(ttl)
        if rcode:
            record["rcodes"].add(rcode)
    records = []
    for record in names.values():
        records.append({key: sorted(value) if isinstance(value, set) else value for key, value in record.items()})
    return {"packet_count": total, "unique_name_count": len(records), "names": sorted(records, key=lambda row: (int(row["queries"]) + int(row["responses"]), str(row["name"])), reverse=True)[:2000]}


def sanitize_uri(uri: str) -> dict[str, object]:
    if not uri:
        return {"path": ""}
    parsed = urllib.parse.urlsplit(uri if "://" in uri else f"http://placeholder{uri}")
    query_names = sorted({name for name, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)})
    result: dict[str, object] = {"path": parsed.path or "/"}
    if parsed.query:
        result["query_present"] = True
        result["query_names"] = query_names
        result["query_sha256"] = hashlib.sha256(parsed.query.encode("utf-8", errors="replace")).hexdigest()
    return result


def http_inventory(pcap: Path) -> dict[str, object]:
    fields = [
        "frame.number",
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "tcp.stream",
        "http.request.method",
        "http.host",
        "http.request.uri",
        "http.user_agent",
        "http.response.code",
        "http.content_type",
        "http.content_length",
    ]
    records: list[dict[str, object]] = []
    total = 0
    for values in tshark_rows(pcap, fields, display_filter="http.request or http.response"):
        total += 1
        if len(records) >= MAX_RECORDS:
            continue
        frame, epoch, src, dst, stream, method, host, uri, user_agent, response_code, content_type, content_length = values
        record: dict[str, object] = {
            "frame": frame,
            "epoch": epoch,
            "src": src,
            "dst": dst,
            "tcp_stream": stream,
            "kind": "request" if method else "response",
        }
        if method:
            record.update({"method": method, "host": host.lower(), "uri": sanitize_uri(uri), "user_agent": user_agent})
        else:
            record.update({"response_code": response_code, "content_type": content_type, "content_length": content_length})
        records.append(record)
    return {"message_count": total, "records_truncated": total > MAX_RECORDS, "records": records}


def tls_inventory(pcap: Path) -> dict[str, object]:
    fields = [
        "frame.number",
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "tcp.stream",
        "tls.handshake.type",
        "tls.handshake.extensions_server_name",
        "tls.handshake.extensions_alpn_str",
        "tls.handshake.version",
        "tls.handshake.ciphersuite",
        "tls.handshake.ja3",
        "tls.handshake.ja3s",
    ]
    records: list[dict[str, str]] = []
    total = 0
    seen: set[tuple[str, ...]] = set()
    for values in tshark_rows(pcap, fields, display_filter="tls.handshake"):
        total += 1
        key = tuple(values[2:])
        if key in seen or len(records) >= MAX_RECORDS:
            continue
        seen.add(key)
        frame, epoch, src, dst, stream, handshake_type, sni, alpn, version, cipher, ja3, ja3s = values
        records.append(
            {
                "frame": frame,
                "epoch": epoch,
                "src": src,
                "dst": dst,
                "tcp_stream": stream,
                "handshake_type": handshake_type,
                "sni": sni.lower(),
                "alpn": alpn,
                "version": version,
                "cipher": cipher,
                "ja3": ja3,
                "ja3s": ja3s,
            }
        )
    return {"handshake_packet_count": total, "unique_record_count": len(records), "records_truncated": len(records) >= MAX_RECORDS, "records": records}


def ftp_inventory(pcap: Path) -> dict[str, object]:
    fields = [
        "frame.number",
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "tcp.stream",
        "ftp.request.command",
        "ftp.request.arg",
        "ftp.response.code",
    ]
    records: list[dict[str, object]] = []
    commands: Counter[str] = Counter()
    for values in tshark_rows(pcap, fields, display_filter="ftp"):
        frame, epoch, src, dst, stream, command, argument, response_code = values
        command_upper = command.upper()
        if command_upper:
            commands[command_upper] += 1
        argument_record: object = argument
        if command_upper in {"PASS", "ACCT", "USER", "STOR", "RETR", "APPE", "DELE", "RNFR", "RNTO"} and argument:
            argument_record = {
                "redacted": True,
                "length": len(argument),
                "sha256": hashlib.sha256(argument.encode("utf-8", errors="replace")).hexdigest(),
            }
        records.append(
            {
                "frame": frame,
                "epoch": epoch,
                "src": src,
                "dst": dst,
                "tcp_stream": stream,
                "command": command_upper,
                "argument": argument_record,
                "response_code": response_code,
            }
        )
    return {"message_count": len(records), "command_counts": dict(commands), "records": records[:MAX_RECORDS], "records_truncated": len(records) > MAX_RECORDS}


def unknown_tcp_inventory(pcap: Path) -> dict[str, object]:
    fields = [
        "frame.number",
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.stream",
        "tcp.len",
        "tcp.payload",
    ]
    display_filter = "tcp.payload && !http && !tls && !ftp && !ftp-data && !smtp && !smb && !smb2"
    streams: dict[str, dict[str, object]] = {}
    for values in tshark_rows(pcap, fields, display_filter=display_filter):
        frame, epoch, src, dst, src_port, dst_port, stream, length, payload_hex = values
        if not stream or not payload_hex:
            continue
        record = streams.setdefault(
            stream,
            {
                "tcp_stream": stream,
                "src": src,
                "src_port": src_port,
                "dst": dst,
                "dst_port": dst_port,
                "payload_packets": 0,
                "payload_bytes": 0,
                "first_frame": frame,
                "first_epoch": epoch,
                "prefix_observations": [],
            },
        )
        record["payload_packets"] = int(record["payload_packets"]) + 1
        try:
            record["payload_bytes"] = int(record["payload_bytes"]) + int(length)
        except ValueError:
            pass
        observations = record["prefix_observations"]
        if isinstance(observations, list) and len(observations) < 8:
            try:
                payload = bytes.fromhex(payload_hex.replace(":", ""))
            except ValueError:
                payload = b""
            prefix = payload[:32]
            printable = sum(32 <= byte < 127 for byte in prefix)
            item: dict[str, object] = {
                "frame": frame,
                "length": len(payload),
                "prefix_sha256": hashlib.sha256(prefix).hexdigest(),
                "prefix_length": len(prefix),
                "printable_ratio": round(printable / len(prefix), 3) if prefix else 0,
            }
            if prefix and printable / len(prefix) < 0.5:
                item["binary_prefix_hex"] = prefix.hex()
            observations.append(item)
    return {
        "stream_count": len(streams),
        "streams": sorted(streams.values(), key=lambda row: int(row["payload_bytes"]), reverse=True)[:500],
        "streams_truncated": len(streams) > 500,
    }


def family_candidates(item: dict[str, object]) -> list[str]:
    text = f"{item.get('page_title', '')} {item.get('archive_name', '')}".lower()
    return sorted(
        family
        for family, patterns in FAMILY_PATTERNS.items()
        if any(pattern in text for pattern in patterns)
    )


def freshness(published_date: str) -> dict[str, object]:
    observed = date.fromisoformat(published_date)
    age_days = (ANALYSIS_DATE - observed).days
    if age_days <= 90:
        band = "current_window"
    elif age_days <= 180:
        band = "recent_historical"
    elif age_days <= 365:
        band = "historical"
    else:
        band = "legacy"
    return {
        "analysis_date": ANALYSIS_DATE.isoformat(),
        "published_date": published_date,
        "age_days": age_days,
        "age_band": band,
        "current_use_status": "unknown",
        "assessment": (
            "公開日の古さだけでは通信方式の廃止を断定しない。"
            "新しいPCAPでの再観測、時系列、設定や亜種の差を合わせて評価する。"
        ),    }


def analyze(index: int, item: dict[str, object]) -> dict[str, object]:
    archive = Path(str(item["archive_path"]))
    published = str(item["published_date"])
    password = f"infected_{published.replace('-', '')}"
    members = list_members(archive, password)
    if not members:
        raise ValueError("archive contains no PCAP member")
    primary = members[0]
    member = str(primary["Path"])
    work = (WORK_ROOT / f"case-{index:03d}").resolve()
    expected_parent = WORK_ROOT.resolve()
    if expected_parent not in work.parents:
        raise ValueError("unsafe work directory")
    pcap = extract_member(archive, member, password, work)
    try:
        capture = capinfos(pcap)
        result = {
            "schema_version": 1,
            "capture_id": f"mta-{published}-{index:03d}",
            "source": {
                "provider": "Malware-Traffic-Analysis.net",
                "page_url": item["page_url"],
                "page_title": item["page_title"],
                "archive_url": item["archive_url"],
                "archive_name": item["archive_name"],
                "published_date": published,
                "reported_family_candidates": family_candidates(item),
                "reported_label_is_not_independent_attribution": True,
            },
            "archive": {
                "sha256": item["zip_sha256"],
                "size": item["zip_size"],
                "encrypted": True,
                "pcap_member_count": len(members),
                "additional_members_not_analyzed": max(0, len(members) - 1),
            },
            "pcap": {
                "member_name": member,
                "member_size": int(primary["Size"]),
                "sha256": sha256_file(pcap),
                "capture_metadata": capture,
            },
            "freshness": freshness(published),
            "packet_inventory": packet_inventory(pcap),
            "dns": dns_inventory(pcap),
            "http": http_inventory(pcap),
            "tls": tls_inventory(pcap),
            "ftp": ftp_inventory(pcap),
            "unknown_tcp": unknown_tcp_inventory(pcap),
            "safety": {
                "pcap_replayed": False,
                "sample_executed": False,
                "exported_object_executed": False,
                "network_name_resolution_enabled": False,
                "live_c2_contacted": False,
                "analysis_mode": "offline_file_input",
            },
            "analysis_completed_at": datetime.now(timezone.utc).isoformat(),
        }
        return result
    finally:
        if work.exists():
            resolved = work.resolve()
            if expected_parent not in resolved.parents:
                raise ValueError("refusing unsafe cleanup")
            shutil.rmtree(resolved)


def main() -> int:
    global MANIFEST, RESULTS, WORK_ROOT, SEVEN_ZIP, TSHARK, CAPINFOS, ANALYSIS_DATE

    parser = argparse.ArgumentParser(
        description="暗号化アーカイブ内のPCAPを展開後、外部通信せずに解析します。"
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--seven-zip", type=Path, default=SEVEN_ZIP)
    parser.add_argument("--tshark", type=Path, default=TSHARK)
    parser.add_argument("--capinfos", type=Path, default=CAPINFOS)
    parser.add_argument("--analysis-date", type=date.fromisoformat, default=date.today())
    args = parser.parse_args()

    MANIFEST = args.manifest.resolve()
    RESULTS = args.results.resolve()
    WORK_ROOT = args.work_root.resolve()
    SEVEN_ZIP = args.seven_zip.resolve()
    TSHARK = args.tshark.resolve()
    CAPINFOS = args.capinfos.resolve()
    ANALYSIS_DATE = args.analysis_date

    for executable in (SEVEN_ZIP, TSHARK, CAPINFOS):
        if not executable.is_file():
            parser.error(f"実行ファイルが見つかりません: {executable}")
    if not MANIFEST.is_file():
        parser.error(f"台帳が見つかりません: {MANIFEST}")

    RESULTS.mkdir(parents=True, exist_ok=True)
    WORK_ROOT.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    items = manifest.get("items", [])
    total = len(items)
    if total == 0:
        parser.error("台帳に解析対象がありません")
    width = max(2, len(str(total)))
    completed = 0
    errors = 0
    for index, item in enumerate(items, 1):
        output = RESULTS / f"{index:03d}-{item['published_date']}" / "analysis.json"
        if output.is_file():
            completed += 1
            print(f"[{index:0{width}d}/{total}] reuse {output}", flush=True)
            continue
        try:
            result = analyze(index, item)
            atomic_json(output, result)
            item["analysis_status"] = "complete"
            item["analysis_result"] = str(output)
            item["pcap_sha256"] = result["pcap"]["sha256"]
            item["capture_start"] = result["pcap"]["capture_metadata"].get("Start time")
            item["capture_end"] = result["pcap"]["capture_metadata"].get("End time")
            completed += 1
            print(
                f"[{index:0{width}d}/{total}] complete packets={result['pcap']['capture_metadata'].get('Number of packets')} "
                f"dns={result['dns']['unique_name_count']} http={result['http']['message_count']} "
                f"tls={result['tls']['handshake_packet_count']} ftp={result['ftp']['message_count']}",
                flush=True,
            )
        except Exception as exc:
            errors += 1
            item["analysis_status"] = "error"
            item["analysis_error"] = f"{type(exc).__name__}: {exc}"
            print(f"[{index:0{width}d}/{total}] ERROR {type(exc).__name__}: {exc}", flush=True)
        atomic_json(MANIFEST, manifest)
    manifest["analysis_summary"] = {
        "requested": total,
        "completed": completed,
        "errors": errors,
        "pcap_replayed": False,
        "sample_executed": False,
        "live_c2_contacted": False,
    }
    atomic_json(MANIFEST, manifest)
    print(f"finished completed={completed} errors={errors}", flush=True)
    return 0 if completed == total and errors == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())