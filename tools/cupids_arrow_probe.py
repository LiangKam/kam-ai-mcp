#!/usr/bin/env python3
"""Remote, evidence-preserving probe for Cupid's Arrow public resource endpoints.

Only performs ordinary HTTP(S), DNS and public-archive requests. It does not
attempt authentication bypass, credential guessing, or unrestricted crawling.
"""
from __future__ import annotations

import base64
import csv
import gzip
import hashlib
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
import zlib
from pathlib import Path
from typing import Any, Iterable

import requests

OUT = Path(os.environ.get("PROBE_OUT", "probe-output"))
RAW = OUT / "raw"
META = OUT / "metadata"
MEDIA = OUT / "media"
for d in (OUT, RAW, META, MEDIA):
    d.mkdir(parents=True, exist_ok=True)

DOMAIN = "drcupidarrow.com"
COMMON_URL = "https://drcupidarrow.com/dao_as/android/version_1_0_8"
RESOURCE_URL = "https://drcupidarrow.com/dao_as/android/v_1_0_1_AS/"
UAS = {
    "unity": "UnityPlayer/2022.3.62f3 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
    "dalvik": "Dalvik/2.1.0 (Linux; U; Android 13; Pixel 7 Build/TQ3A.230805.001)",
    "chrome": "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Chrome/126.0 Mobile Safari/537.36",
}

RESULTS: list[dict[str, Any]] = []
DISCOVERED_URLS: set[str] = set()


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", errors="replace")


def write_json(path: Path, obj: Any) -> None:
    write_text(path, json.dumps(obj, ensure_ascii=False, indent=2, default=str))


def run(cmd: list[str], timeout: int = 45) -> dict[str, Any]:
    started = time.time()
    try:
        p = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
        return {
            "cmd": cmd,
            "returncode": p.returncode,
            "stdout": p.stdout,
            "stderr": p.stderr,
            "elapsed_ms": int((time.time() - started) * 1000),
        }
    except Exception as e:
        return {
            "cmd": cmd,
            "returncode": None,
            "stdout": "",
            "stderr": f"{type(e).__name__}: {e}",
            "elapsed_ms": int((time.time() - started) * 1000),
        }


def detect_type(data: bytes, content_type: str = "") -> str:
    h = data[:64]
    ct = content_type.lower()
    if h.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if h.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if h[:4] in (b"RIFF",) and h[8:12] == b"WEBP":
        return "webp"
    if len(data) >= 12 and data[4:8] == b"ftyp":
        return "mp4"
    if h.startswith(b"GIF87a") or h.startswith(b"GIF89a"):
        return "gif"
    if h.startswith(b"ID3") or h[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"):
        return "mp3"
    if h.startswith(b"OggS"):
        return "ogg"
    if h.startswith(b"PK\x03\x04"):
        return "zip"
    if h.startswith(b"\x1f\x8b"):
        return "gzip"
    if h.startswith(b"UnityFS"):
        return "unityfs"
    if b"#EXTM3U" in data[:4096]:
        return "hls"
    stripped = data.lstrip()[:1024].lower()
    if stripped.startswith((b"<!doctype html", b"<html", b"<head", b"<body")) or "text/html" in ct:
        return "html"
    if stripped.startswith((b"{", b"[")) or "json" in ct:
        return "json"
    if "text/" in ct:
        return "text"
    try:
        data[:4096].decode("utf-8")
        return "text"
    except Exception:
        return "binary"


def ext_for(kind: str, content_type: str, url: str) -> str:
    known = {"png":".png","jpeg":".jpg","webp":".webp","mp4":".mp4","gif":".gif","mp3":".mp3","ogg":".ogg","zip":".zip","gzip":".gz","unityfs":".bundle","hls":".m3u8","json":".json","html":".html","text":".txt","binary":".bin"}
    if kind in known:
        return known[kind]
    suffix = Path(urllib.parse.urlparse(url).path).suffix
    return suffix if 1 <= len(suffix) <= 8 else ".bin"


def safe_name(s: str, limit: int = 150) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("._")
    return (s[:limit] or "item")


def extract_urls(data: bytes, base_url: str) -> set[str]:
    found: set[str] = set()
    texts: list[str] = []
    for enc in ("utf-8", "utf-16", "utf-16le", "utf-16be", "latin1"):
        try:
            texts.append(data.decode(enc))
        except Exception:
            pass
    for text in texts:
        for u in re.findall(r"https?://[^\s\"'<>\\]+", text, flags=re.I):
            found.add(u.rstrip(")]},;"))
        for p in re.findall(r"(?:[A-Za-z0-9_.-]+/){1,8}[A-Za-z0-9_.-]+\.(?:png|jpe?g|webp|mp4|m3u8|txt|json|dat|download)", text, flags=re.I):
            found.add(urllib.parse.urljoin(base_url, p))
        for p in re.findall(r"\b\d{6,12}\.(?:png|jpe?g|webp|mp4|m3u8|download)\b", text, flags=re.I):
            found.add(urllib.parse.urljoin(base_url, p))
    return found


def fetch(url: str, label: str, ua_name: str = "unity", verify: bool = True, method: str = "GET", timeout: int = 35, max_bytes: int = 80_000_000) -> dict[str, Any]:
    headers = {
        "User-Agent": UAS[ua_name],
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close",
        "X-Unity-Version": "2022.3.62f3",
    }
    started = time.time()
    rec: dict[str, Any] = {"label": label, "url": url, "method": method, "ua": ua_name, "verify_tls": verify}
    try:
        with requests.request(method, url, headers=headers, allow_redirects=True, timeout=timeout, verify=verify, stream=True) as r:
            chunks: list[bytes] = []
            total = 0
            if method != "HEAD":
                for chunk in r.iter_content(1024 * 256):
                    if not chunk:
                        continue
                    chunks.append(chunk)
                    total += len(chunk)
                    if total >= max_bytes:
                        break
            data = b"".join(chunks)
            ct = r.headers.get("content-type", "")
            kind = detect_type(data, ct)
            sha = hashlib.sha256(data).hexdigest() if data else ""
            rec.update({
                "status": r.status_code,
                "ok": 200 <= r.status_code < 400,
                "final_url": r.url,
                "content_type": ct,
                "content_length_header": r.headers.get("content-length", ""),
                "bytes": len(data),
                "sha256": sha,
                "detected_type": kind,
                "headers": dict(r.headers),
                "history": [{"status": h.status_code, "url": h.url, "headers": dict(h.headers)} for h in r.history],
                "truncated_at": max_bytes if total >= max_bytes else None,
            })
            if data:
                host = urllib.parse.urlparse(url).netloc
                file_name = f"{safe_name(label)}__{safe_name(host)}__{sha[:12]}{ext_for(kind, ct, url)}"
                target_dir = MEDIA if kind in {"png","jpeg","webp","mp4","gif","mp3","ogg","hls"} else RAW
                out = target_dir / file_name
                out.write_bytes(data)
                rec["saved_path"] = str(out)
                urls = extract_urls(data, r.url)
                if urls:
                    rec["embedded_urls"] = sorted(urls)
                    DISCOVERED_URLS.update(urls)
                preview = ""
                if kind in {"text","json","html","hls"}:
                    preview = data[:12000].decode("utf-8", errors="replace")
                    write_text(META / f"{safe_name(label)}__preview.txt", preview)
                    rec["preview"] = preview[:1000]
            else:
                rec["saved_path"] = ""
    except Exception as e:
        rec.update({"status": None, "ok": False, "final_url": url, "content_type": "", "bytes": 0, "sha256": "", "detected_type": "empty", "saved_path": "", "error": f"{type(e).__name__}: {e}"})
    rec["elapsed_ms"] = int((time.time() - started) * 1000)
    RESULTS.append(rec)
    print(json.dumps({k: rec.get(k) for k in ("label","status","url","final_url","bytes","detected_type","error")}, ensure_ascii=False), flush=True)
    return rec


def decode_candidates(data: bytes) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = [("raw", data)]
    seen = {hashlib.sha256(data).hexdigest()}
    funcs = [
        ("gzip", lambda b: gzip.decompress(b)),
        ("zlib", lambda b: zlib.decompress(b)),
        ("zlib_raw", lambda b: zlib.decompress(b, -zlib.MAX_WBITS)),
        ("base64", lambda b: base64.b64decode(re.sub(rb"\s+", b"", b), validate=True)),
    ]
    for name, fn in funcs:
        try:
            decoded = fn(data)
            h = hashlib.sha256(decoded).hexdigest()
            if decoded and h not in seen:
                seen.add(h)
                out.append((name, decoded))
        except Exception:
            pass
    return out


def save_summary() -> None:
    write_json(OUT / "probe_results.json", RESULTS)
    fields = ["label","status","ok","method","ua","verify_tls","url","final_url","content_type","content_length_header","bytes","detected_type","sha256","saved_path","elapsed_ms","error"]
    with (OUT / "probe_results.csv").open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader(); w.writerows(RESULTS)
    write_json(OUT / "discovered_urls.json", sorted(DISCOVERED_URLS))
    valid = [r for r in RESULTS if r.get("detected_type") in {"png","jpeg","webp","mp4","gif","mp3","ogg","hls"}]
    write_json(OUT / "valid_media.json", valid)
    write_text(OUT / "SUMMARY.md", "\n".join([
        "# Cupid's Arrow remote probe summary",
        "",
        f"- UTC: {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())}",
        f"- Requests recorded: {len(RESULTS)}",
        f"- Successful HTTP responses: {sum(1 for r in RESULTS if r.get('ok'))}",
        f"- Valid media files: {len(valid)}",
        f"- Discovered URLs: {len(DISCOVERED_URLS)}",
        "",
        "See `probe_results.csv`, `probe_results.json`, `dns/`, `raw/`, and `media/`.",
    ]))


def main() -> int:
    write_json(OUT / "run_context.json", {
        "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python": sys.version,
        "platform": sys.platform,
        "domain": DOMAIN,
        "common_url": COMMON_URL,
        "resource_url": RESOURCE_URL,
    })

    # DNS from system and multiple public resolvers.
    dns_dir = OUT / "dns"; dns_dir.mkdir(exist_ok=True)
    dns_records: list[dict[str, Any]] = []
    for host in [DOMAIN, "www." + DOMAIN]:
        try:
            dns_records.append({"host": host, "socket_getaddrinfo": socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)})
        except Exception as e:
            dns_records.append({"host": host, "socket_error": f"{type(e).__name__}: {e}"})
        for typ in ["A","AAAA","CNAME","NS","SOA","MX","TXT","CAA"]:
            for resolver in [None, "8.8.8.8", "1.1.1.1", "9.9.9.9"]:
                cmd = ["dig", "+time=5", "+tries=1", "+noall", "+answer"]
                if resolver: cmd += ["@" + resolver]
                cmd += [host, typ]
                rr = run(cmd, timeout=15)
                rr.update({"host": host, "type": typ, "resolver": resolver or "system"})
                dns_records.append(rr)
    write_json(dns_dir / "dns_records.json", dns_records)

    # Public intelligence / history endpoints.
    intel_urls = {
        "google_doh_a": f"https://dns.google/resolve?name={DOMAIN}&type=A",
        "google_doh_aaaa": f"https://dns.google/resolve?name={DOMAIN}&type=AAAA",
        "cloudflare_doh_a": f"https://cloudflare-dns.com/dns-query?name={DOMAIN}&type=A",
        "crtsh": f"https://crt.sh/?q=%25.{DOMAIN}&output=json",
        "certspotter": f"https://api.certspotter.com/v1/issuances?domain={DOMAIN}&include_subdomains=true&expand=dns_names",
        "hackertarget_hosts": f"https://api.hackertarget.com/hostsearch/?q={DOMAIN}",
        "urlscan_domain": f"https://urlscan.io/api/v1/search/?q=domain:{DOMAIN}&size=100",
        "urlscan_path": f"https://urlscan.io/api/v1/search/?q=filename:data_config.txt%20AND%20domain:{DOMAIN}&size=100",
        "wayback_all": f"https://web.archive.org/cdx/search/cdx?url={DOMAIN}/*&output=json&fl=timestamp,original,statuscode,mimetype,digest,length&filter=statuscode:200&collapse=urlkey&limit=10000",
    }
    for label, url in intel_urls.items():
        fetch(url, "intel_" + label, "chrome", timeout=60, max_bytes=30_000_000)

    # Core site, privacy page and standard discovery files.
    core_urls = [
        f"https://{DOMAIN}/",
        f"http://{DOMAIN}/",
        f"https://www.{DOMAIN}/",
        f"https://{DOMAIN}/privacy-policy.html",
        f"https://{DOMAIN}/robots.txt",
        f"https://{DOMAIN}/sitemap.xml",
        COMMON_URL,
        COMMON_URL + "/",
        COMMON_URL + ".txt",
        COMMON_URL + "/data_config.txt",
        COMMON_URL + "/version-android.txt",
        COMMON_URL.rsplit("/",1)[0] + "/version-android.txt",
        RESOURCE_URL,
        urllib.parse.urljoin(RESOURCE_URL, "data_config.txt"),
        urllib.parse.urljoin(RESOURCE_URL, "version-android.txt"),
        urllib.parse.urljoin(RESOURCE_URL, "manifest.json"),
        urllib.parse.urljoin(RESOURCE_URL, "config.json"),
    ]
    for i, url in enumerate(dict.fromkeys(core_urls)):
        fetch(url, f"core_{i:02d}", "unity", timeout=45)
        if url.startswith("https://"):
            fetch(url, f"core_{i:02d}_chrome", "chrome", timeout=45)

    # Probe a bounded set of likely resource-version roots.
    version_roots = []
    for major, minor, patch in [(1,0,p) for p in range(1,11)] + [(1,1,p) for p in range(0,3)]:
        version_roots.extend([
            f"https://{DOMAIN}/dao_as/android/v_{major}_{minor}_{patch}_AS/",
            f"https://{DOMAIN}/dao_as/android/v_{major}_{minor}_{patch}/",
            f"https://{DOMAIN}/dao_as/android/version_{major}_{minor}_{patch}/",
        ])
    for idx, root in enumerate(version_roots):
        fetch(urllib.parse.urljoin(root, "data_config.txt"), f"version_manifest_{idx:02d}", "unity", timeout=25, max_bytes=20_000_000)

    # Known package-backed and first remote IDs, plus all first video chapter parts.
    ids = [
        "1010001","1010002","1010003","1010004","1010005","1010010",
        "2050101","2050102","2050103","2050104",
        "2051901","2051902","2051903","2051904",
        "2010001","2020001","2030001","2040001",
    ]
    suffixes = [".png", ".jpg", ".webp", ".mp4", ".m3u8", ".download", ""]
    media_roots = list(dict.fromkeys([RESOURCE_URL] + [r for r in version_roots if r.endswith("_AS/")]))
    # Bound direct candidates to the known root first; broader roots only test 1010004 and 2050101.
    for rid in ids:
        for suf in suffixes:
            fetch(urllib.parse.urljoin(RESOURCE_URL, rid + suf), f"candidate_{rid}_{safe_name(suf or 'noext')}", "unity", timeout=30, max_bytes=100_000_000)
    for root in media_roots[1:]:
        root_tag = safe_name(urllib.parse.urlparse(root).path)
        for rid in ["1010004", "2050101"]:
            for suf in [".png", ".mp4", ".download"]:
                fetch(urllib.parse.urljoin(root, rid + suf), f"crossver_{root_tag}_{rid}_{safe_name(suf)}", "unity", timeout=20, max_bytes=100_000_000)

    # Decode and inspect every retrieved data_config-like response.
    for rec in list(RESULTS):
        if "manifest" not in rec.get("label", "") and "data_config" not in rec.get("url", ""):
            continue
        saved = rec.get("saved_path")
        if not saved or not Path(saved).exists():
            continue
        data = Path(saved).read_bytes()
        for decoder, decoded in decode_candidates(data):
            name = safe_name(rec["label"] + "_" + decoder)
            (META / f"{name}.bin").write_bytes(decoded)
            found = extract_urls(decoded, rec.get("final_url") or rec["url"])
            DISCOVERED_URLS.update(found)
            try:
                text = decoded.decode("utf-8")
                write_text(META / f"{name}.txt", text)
                try:
                    obj = json.loads(text)
                    write_json(META / f"{name}.json", obj)
                except Exception:
                    pass
            except Exception:
                pass

    # Fetch only discovered URLs that remain on the first-party domain or archive snapshots.
    for i, url in enumerate(sorted(DISCOVERED_URLS)[:500]):
        host = urllib.parse.urlparse(url).hostname or ""
        if host == DOMAIN or host.endswith("." + DOMAIN) or host.endswith("web.archive.org"):
            fetch(url, f"discovered_{i:04d}", "unity", timeout=45, max_bytes=120_000_000)

    save_summary()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
