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
ROSCOM_JSON = "https://github.com/aleksandrberlin/roscom-vpn/releases/latest/download/all.json"

# itdoginfo's Russia/inside builder excludes these standalone services from
# its combined list. We add the selected services explicitly below instead.
RUSSIA_INSIDE_EXCLUDED = {
    "telegram.lst", "cloudflare.lst", "google_ai.lst", "google_play.lst",
    "hetzner.lst", "ovh.lst", "digitalocean.lst", "cloudfront.lst",
    "hodca.lst", "roblox.lst", "google_meet.lst",
}
SELECTED_SERVICES = [
    "meta", "telegram", "ovh", "digitalocean", "google_ai",
    "cloudflare", "twitter", "google_play",
]

USER_AGENT = "evil-domains-builder/0.1"
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*\.?$", re.I)


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            data = response.read()
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.code} for URL: {url}") from exc
    if not data:
        raise RuntimeError(f"Empty response: {url}")
    return data


def github_directory(path: str) -> list[dict]:
    data = json.loads(fetch(f"{ITDOG_API}/{path}"))
    if not isinstance(data, list):
        raise RuntimeError(f"Unexpected GitHub API response for {path}")
    return [item for item in data if item.get("type") == "file" and item.get("name", "").endswith(".lst")]


def parse_domain_line(line: str) -> str | None:
    line = line.strip().lower()
    if not line or line.startswith("#"):
        return None
    # Inputs are intended to be domain lists. Reject URLs, IPs, CIDRs and
    # rule syntax rather than silently converting them.
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
            if key in ("domain", "domain_suffix", "domain_keyword"):
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


def main() -> None:
    domains: set[str] = set()
    source_counts: dict[str, int] = {}

    # Reproduce the upstream Russia-inside composition: Categories + Services,
    # excluding the same standalone services that upstream excludes.
    for directory in ("Categories", "Services"):
        for item in github_directory(directory):
            name = item["name"]
            if name in RUSSIA_INSIDE_EXCLUDED:
                continue
            source_counts[f"itdoginfo/{directory}/{name}"] = add_itdog_file(
                f"{directory}/{name}", domains
            )

    # Add selected standalone services as domain-only lists.
    for service in SELECTED_SERVICES:
        path = f"Services/{service}.lst"
        source_counts[f"itdoginfo/{path}"] = add_itdog_file(path, domains)

    # roscom-vpn publishes all.json as a sing-box JSON rule-set.
    roscom = json.loads(fetch(ROSCOM_JSON).decode("utf-8"))
    roscom_domains = extract_domains_from_json(roscom)
    if not roscom_domains:
        raise RuntimeError("roscom-vpn all.json yielded zero valid domain entries")
    before = len(domains)
    domains.update(roscom_domains)
    source_counts["roscom-vpn/all.json"] = len(domains) - before

    if len(domains) < 100:
        raise RuntimeError(f"Suspiciously small result: only {len(domains)} domains")

    out_dir = Path("output")
    out_dir.mkdir(exist_ok=True)
    json_path = out_dir / "evil-domains.json"
    srs_path = out_dir / "evil-domains.srs"
    payload = {
        "version": 3,
        "rules": [{"domain_suffix": sorted(domains)}],
    }
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    subprocess.run(
        ["sing-box", "rule-set", "compile", str(json_path), "-o", str(srs_path)],
        check=True,
    )

    report = {
        "total_domains": len(domains),
        "sources": source_counts,
        "contains_ip_cidr": False,
    }
    Path("output/build-report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError,
            subprocess.CalledProcessError, RuntimeError) as exc:
        print(f"BUILD FAILED: {exc}", file=sys.stderr)
        sys.exit(1)
