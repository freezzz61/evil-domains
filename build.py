#!/usr/bin/env python3
"""Build domain and IPv4 subnet sing-box rule-sets."""
from __future__ import annotations

import ipaddress
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

ROSCOM_BASE = (
    "https://cdn.jsdelivr.net/gh/"
    "hydraponique/roscomvpn-geosite/release/sing-box"
)

ROSCOM_CATEGORIES = [
    "category-geoblock-ru.srs",
]

# Эти файлы исключены из автоматического сбора доменов.
RUSSIA_INSIDE_EXCLUDED = {
    "telegram.lst",
    "cloudflare.lst",
    "google_ai.lst",
    "google_play.lst",
    "hetzner.lst",
    "ovh.lst",
    "digitalocean.lst",
    "cloudfront.lst",
    "hodca.lst",
    "roblox.lst",
    "google_meet.lst",
}

# Дополнительные доменные списки.
SELECTED_SERVICES = [
    "telegram",
    "ovh",
    "digitalocean",
    "google_ai",
    "cloudflare",
    "google_play",
]

# Источники IPv4-подсетей.
SUBNET_SOURCES = [
    "telegram",
    "meta",
    "twitter",
    "cloudflare",
]

USER_AGENT = "evil-domains-builder/1.0"

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
        if item.get("type") == "file"
        and item.get("name", "").endswith(".lst")
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

    if not line or "/" in line or ":" in line:
        return None

    if "*" in line or " " in line:
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


def parse_ipv4_line(line: str) -> str | None:
    line = line.strip()

    if not line or line.startswith("#"):
        return None

    try:
        network = ipaddress.ip_network(line, strict=False)
    except ValueError:
        return None

    if network.version != 4:
        return None

    return str(network)


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


def add_itdog_domains(path: str, domains: set[str]) -> int:
    raw = fetch(f"{ITDOG_RAW}/{path}").decode(
        "utf-8", errors="replace"
    )

    before = len(domains)

    for line in raw.splitlines():
        parsed = parse_domain_line(line)

        if parsed:
            domains.add(parsed)

    return len(domains) - before


def add_itdog_subnets(path: str, subnets: set[str]) -> int:
    raw = fetch(f"{ITDOG_RAW}/{path}").decode(
        "utf-8", errors="replace"
    )

    before = len(subnets)

    for line in raw.splitlines():
        parsed = parse_ipv4_line(line)

        if parsed:
            subnets.add(parsed)

    added = len(subnets) - before

    if added == 0:
        raise RuntimeError(
            f"No valid IPv4 subnets found in {path}"
        )

    return added


def compile_srs(json_path: Path, srs_path: Path) -> None:
    try:
        subprocess.run(
            [
                "sing-box",
                "rule-set",
                "compile",
                str(json_path),
                "-o",
                str(srs_path),
            ],
            check=True,
        )

    except FileNotFoundError as exc:
        raise RuntimeError(
            "sing-box not found in PATH"
        ) from exc

    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"sing-box compilation failed: {json_path}"
        ) from exc

    if not srs_path.exists() or srs_path.stat().st_size == 0:
        raise RuntimeError(
            f"Compiled file is missing or empty: {srs_path}"
        )


def main() -> None:
    domains: set[str] = set()
    subnets: set[str] = set()

    domain_sources: dict[str, int] = {}
    subnet_sources: dict[str, int] = {}

    out_dir = Path("output")
    out_dir.mkdir(exist_ok=True)

    # --------------------------------------------------
    # 1. ITDOGINFO DOMAINS
    # --------------------------------------------------

    print("Collecting domains from itdoginfo...")

    for directory in ("Categories", "Services"):
        for item in github_directory(directory):
            name = item["name"]

            if name in RUSSIA_INSIDE_EXCLUDED:
                continue

            path = f"{directory}/{name}"

            domain_sources[f"itdoginfo/{path}"] = (
                add_itdog_domains(path, domains)
            )

    # Дополнительные выбранные сервисы.
    for service in SELECTED_SERVICES:
        path = f"Services/{service}.lst"

        domain_sources[f"itdoginfo/{path}"] = (
            add_itdog_domains(path, domains)
        )

    print(f"Collected domains: {len(domains)}")

    # --------------------------------------------------
    # 2. ITDOGINFO IPv4 SUBNETS
    # --------------------------------------------------

    print("Collecting IPv4 subnets from itdoginfo...")

    for service in SUBNET_SOURCES:
        path = f"Subnets/IPv4/{service}.lst"

        subnet_sources[f"itdoginfo/{path}"] = (
            add_itdog_subnets(path, subnets)
        )

    print(f"Collected unique IPv4 subnets: {len(subnets)}")

    # --------------------------------------------------
    # 3. ROSCOMVPN DOMAINS
    # --------------------------------------------------

    for category in ROSCOM_CATEGORIES:
        url = f"{ROSCOM_BASE}/{category}"

        temp_srs = out_dir / f"temp_{category}"
        temp_json = out_dir / f"temp_{category}.json"

        print(f"Downloading {category}...")

        try:
            temp_srs.write_bytes(fetch(url))

            subprocess.run(
                [
                    "sing-box",
                    "rule-set",
                    "decompile",
                    str(temp_srs),
                    "-o",
                    str(temp_json),
                ],
                check=True,
                capture_output=True,
                text=True,
            )

            roscom = json.loads(
                temp_json.read_text(encoding="utf-8")
            )

            roscom_domains = extract_domains_from_json(roscom)

            if not roscom_domains:
                raise RuntimeError(
                    f"No domains extracted from {category}"
                )

            before = len(domains)
            domains.update(roscom_domains)

            added = len(domains) - before

            domain_sources[
                f"hydraponique/{category}"
            ] = added

            print(
                f"Added {added} unique domains from {category}"
            )

        finally:
            temp_srs.unlink(missing_ok=True)
            temp_json.unlink(missing_ok=True)

    # --------------------------------------------------
    # 4. VALIDATION
    # --------------------------------------------------

    if len(domains) < 100:
        raise RuntimeError(
            f"Suspiciously small domain result: {len(domains)}"
        )

    if len(subnets) < 5:
        raise RuntimeError(
            f"Suspiciously small subnet result: {len(subnets)}"
        )

    # Убираем вложенные и перекрывающиеся подсети.
    collapsed_subnets = list(
        ipaddress.collapse_addresses(
            ipaddress.ip_network(item)
            for item in subnets
        )
    )

    collapsed_subnets = sorted(
        collapsed_subnets,
        key=lambda net: (
            int(net.network_address),
            net.prefixlen,
        ),
    )

    # --------------------------------------------------
    # 5. DOMAIN RULE-SET
    # --------------------------------------------------

    domain_json = out_dir / "evil-domains.json"
    domain_srs = out_dir / "evil-domains.srs"

    domain_payload = {
        "version": 3,
        "rules": [
            {
                "domain_suffix": sorted(domains)
            }
        ],
    }

    domain_json.write_text(
        json.dumps(
            domain_payload,
            ensure_ascii=False,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )

    compile_srs(domain_json, domain_srs)

    # --------------------------------------------------
    # 6. SUBNET RULE-SET
    # --------------------------------------------------

    subnet_json = out_dir / "evil-subnets.json"
    subnet_srs = out_dir / "evil-subnets.srs"

    subnet_payload = {
        "version": 3,
        "rules": [
            {
                "ip_cidr": [
                    str(network)
                    for network in collapsed_subnets
                ]
            }
        ],
    }

    subnet_json.write_text(
        json.dumps(
            subnet_payload,
            ensure_ascii=False,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )

    compile_srs(subnet_json, subnet_srs)

    # --------------------------------------------------
    # 7. REPORT
    # --------------------------------------------------

    report = {
        "total_domains": len(domains),
        "total_ipv4_subnets_raw": len(subnets),
        "total_ipv4_subnets_collapsed": len(collapsed_subnets),
        "domain_sources": domain_sources,
        "subnet_sources": subnet_sources,
        "contains_ipv4_cidr": True,
        "contains_ipv6_cidr": False,
    }

    report_path = out_dir / "build-report.json"

    report_path.write_text(
        json.dumps(
            report,
            ensure_ascii=False,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )

    print("\nBUILD SUCCESSFUL")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()

    except (
        urllib.error.URLError,
        json.JSONDecodeError,
        RuntimeError,
        subprocess.CalledProcessError,
    ) as exc:
        print(
            f"BUILD FAILED: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)
