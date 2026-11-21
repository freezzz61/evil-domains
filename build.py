#!/usr/bin/env python3
"""Build a domain-only sing-box rule-set from itdoginfo and roscom-vpn."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

ITDOG_API = "https://api.github.com/repos/itdoginfo/allow-domains/contents"
ITDOG_RAW = "https://raw.githubusercontent.com/itdoginfo/allow-domains/main"
# Ссылка на бинарный релиз hydraponique/roscomvpn-geosite
ROSCOM_SRS = "https://github.com/hydraponique/roscomvpn-geosite/releases/latest/download/all.srs"

RUSSIA_INSIDE_EXCLUDED = {
    "telegram.lst", "cloudflare.lst", "google_ai.lst", "google_play.lst",
    "hetzner.lst", "ovh.lst", "digitalocean.lst", "cloudfront.lst",
    "hodca.lst", "roblox.lst", "google_meet.lst",
}

SELECTED_SERVICES = [
    "telegram", "ovh", "digitalocean", "google_ai",
    "cloudflare", "google_play",
]

USER_AGENT = "evil-domains-builder/0.4"
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
    r"(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*\.?$",
    re.I,
)


def fetch(url: str) -> bytes:
    headers = {"User-Agent": USER_AGENT}
    token = os.environ.get("GITHUB_TOKEN")
    if token and "api.github.com" in url:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=45) as response:
        data = response.read()
    if not data:
        raise RuntimeError(f"Empty response: {url}")
    return data


def github_directory(path: str) -> list[dict]:
    data = json.loads(fetch(f"{ITDOG_API}/{path}"))
    if not isinstance(data, list):
        raise RuntimeError(f"Unexpected GitHub API response for {path}")
    return [
        item for item in data
        if item.get("type") == "file" and item.get("name", "").endswith(".lst")
    ]


def parse_domain_line(line: str) -> str | None:
    line = line.strip().lower()
    if not line or line.startswith("#"):
        return None
    line = line.removeprefix("||").removesuffix("^")
    line = line.lstrip(".")
    if line.startswith("*."):
        line = line[2:]
    line = line.rstrip(".")
    if not line or "/" in line or ":" in line or "*" in line or " " in line:
        return None
    try:
        line = line.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if not DOMAIN_RE.fullmatch(line):
        return None
    if "." not in line:
        return None
    return line


def extract_domains_from_json(obj) -> set[str]:
    found: set[str] = set()
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in ("domain", "domain_suffix"):
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, str):
                            parsed = parse_domain_line(item)
                            if parsed:
                                found.add(parsed)
                elif isinstance(value, str):
                    parsed = parse_domain_line(value)
                    if parsed:
                        found.add(parsed)
            else:
                found.update(extract_domains_from_json(value))
    elif isinstance(obj, list):
        for item in obj:
            found.update(extract_domains_from_json(item))
    return found


def add_itdog_file(path: str, domains: set[str]) -> int:
    raw = fetch(f"{ITDOG_RAW}/{path}").decode("utf-8", errors="replace")
    before = len(domains)
    for line in raw.splitlines():
        parsed = parse_domain_line(line)
        if parsed:
            domains.add(parsed)
    return len(domains) - before


def compile_srs(json_path: Path, srs_path: Path) -> None:
    try:
        subprocess.run(
            ["sing-box", "rule-set", "compile", str(json_path), "-o", str(srs_path)],
            check=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("sing-box not found in PATH.") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"sing-box rule-set compile failed with code {exc.returncode}") from exc


def main() -> None:
    domains: set[str] = set()
    unique_additions: dict[str, int] = {}
    
    out_dir = Path("output")
    out_dir.mkdir(exist_ok=True)

    for directory in ("Categories", "Services"):
        for item in github_directory(directory):
            name = item["name"]
            if name in RUSSIA_INSIDE_EXCLUDED:
                continue
            unique_additions[f"itdoginfo/{directory}/{name}"] = add_itdog_file(
                f"{directory}/{name}", domains
            )

    for service in SELECTED_SERVICES:
        path = f"Services/{service}.lst"
        unique_additions[f"itdoginfo/{path}"] = add_itdog_file(path, domains)

    # Скачиваем SRS от hydraponique, декомпилируем и забираем домены
    try:
        print("Downloading roscomvpn-geosite...")
        roscom_srs_data = fetch(ROSCOM_SRS)
        temp_srs = out_dir / "temp_roscom.srs"
        temp_srs.write_bytes(roscom_srs_data)
        
        temp_json = out_dir / "temp_roscom.json"
        subprocess.run(
            ["sing-box", "rule-set", "decompile", str(temp_srs), "-o", str(temp_json)],
            check=True,
            capture_output=True
        )
        
        roscom = json.loads(temp_json.read_text(encoding="utf-8"))
        roscom_domains = extract_domains_from_json(roscom)
        
        if roscom_domains:
            before = len(domains)
            domains.update(roscom_domains)
            unique_additions["hydraponique/roscomvpn-geosite"] = len(domains) - before
            print(f"Added {len(domains) - before} unique domains from roscomvpn.")
        
        temp_srs.unlink()
        temp_json.unlink()
    except Exception as e:
        print(f"Warning: Failed to fetch or parse roscomvpn data: {e}. Continuing without it.")

    if len(domains) < 100:
        raise RuntimeError(f"Suspiciously small result: only {len(domains)} domains")

    json_path = out_dir / "evil-domains.json"
    srs_path = out_dir / "evil-domains.srs"

    payload = {
        "version": 3,
        "rules": [{"domain_suffix": sorted(domains)}],
    }
    json_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    compile_srs(json_path, srs_path)

    report = {
        "total_domains": len(domains),
        "unique_additions_by_source": unique_additions,
        "contains_ip_cidr": False,
    }
    (out_dir / "build-report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (urllib.error.URLError, json.JSONDecodeError, RuntimeError) as exc:
        print(f"BUILD FAILED: {exc}", file=sys.stderr)
        sys.exit(1)
