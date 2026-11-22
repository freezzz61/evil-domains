#!/usr/bin/env python3
"""Build evil-domains, comparison reports and GeoSite/GeoIP databases."""

from __future__ import annotations

import csv
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path

ITDOG_API = "https://api.github.com/repos/itdoginfo/allow-domains/contents"
ITDOG_RAW = "https://raw.githubusercontent.com/itdoginfo/allow-domains/main"

ROSCOM_BASE = (
    "https://cdn.jsdelivr.net/gh/"
    "hydraponique/roscomvpn-geosite/release/sing-box"
)
ROSCOM_CATEGORIES = ["category-geoblock-ru.srs"]

RUNET_BASE = (
    "https://raw.githubusercontent.com/"
    "runetfreedom/russia-blocked-geosite/release"
)

RUNET_COMMUNITY_URL = f"{RUNET_BASE}/antifilter-download-community.txt"
RUNET_REFILTER_URL = f"{RUNET_BASE}/refilter.txt"
RUNET_ANTIFILTER_URL = f"{RUNET_BASE}/antifilter-download.txt"

RFL_BASE = (
    "https://raw.githubusercontent.com/"
    "Noktomezo/RussiaFancyLists/main/lists"
)
RFL_BLACKLIST_URL = f"{RFL_BASE}/blacklist/domains/full.lst"
RFL_GEOBLOCK_URL = f"{RFL_BASE}/geoblock/full.lst"

TELEGRAM_CIDR_URL = "https://core.telegram.org/resources/cidr.txt"

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

SELECTED_SERVICES = [
    "telegram",
    "ovh",
    "digitalocean",
    "google_ai",
    "cloudflare",
    "google_play",
]

USER_AGENT = "evil-domains-builder/1.0"

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
    r"(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*\.?$",
    re.I,
)

OUT = Path("output")
COMPARISON = OUT / "comparison"


def log(message: str) -> None:
    print(f"[evil-domains] {message}", flush=True)


def fetch(url: str, timeout: int = 120) -> bytes:
    headers = {"User-Agent": USER_AGENT}

    token = os.environ.get("GITHUB_TOKEN")
    if token and "api.github.com" in url:
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(url, headers=headers)

    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = response.read()

    if not data:
        raise RuntimeError(f"Empty response: {url}")

    return data


def parse_domain_line(line: str) -> str | None:
    line = line.strip().lower()

    if not line or line.startswith(("#", "!")):
        return None

    line = line.split("#", 1)[0].strip()
    line = line.removeprefix("||").removesuffix("^")
    line = line.removeprefix("domain:")
    line = line.removeprefix("full:")
    line = line.removeprefix("domain_suffix:")
    line = line.lstrip(".")

    if line.startswith("*."):
        line = line[2:]

    line = line.rstrip(".")

    if (
        not line
        or "/" in line
        or ":" in line
        or "*" in line
        or " " in line
        or "@" in line
    ):
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


def parse_text_domains(data: bytes) -> set[str]:
    text = data.decode("utf-8-sig", errors="replace")
    result: set[str] = set()

    for line in text.splitlines():
        domain = parse_domain_line(line)
        if domain:
            result.add(domain)

    return result


def extract_domains_from_json(obj) -> set[str]:
    result: set[str] = set()

    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in ("domain", "domain_suffix"):
                values = value if isinstance(value, list) else [value]

                for item in values:
                    if isinstance(item, str):
                        domain = parse_domain_line(item)
                        if domain:
                            result.add(domain)
            else:
                result.update(extract_domains_from_json(value))

    elif isinstance(obj, list):
        for item in obj:
            result.update(extract_domains_from_json(item))

    return result


def github_directory(path: str) -> list[dict]:
    data = json.loads(fetch(f"{ITDOG_API}/{path}"))

    if not isinstance(data, list):
        raise RuntimeError(f"Unexpected GitHub API response: {path}")

    return [
        item
        for item in data
        if item.get("type") == "file"
        and item.get("name", "").endswith(".lst")
    ]


def add_itdog_file(path: str, domains: set[str]) -> int:
    raw = fetch(f"{ITDOG_RAW}/{path}")
    found = parse_text_domains(raw)

    before = len(domains)
    domains.update(found)

    return len(domains) - before


def download_roscom_category(category: str) -> set[str]:
    import tempfile

    import_path = f"{ROSCOM_BASE}/{category}"
    data = fetch(import_path)

    with tempfile.TemporaryDirectory() as temp:
        srs_path = Path(temp) / "source.srs"
        json_path = Path(temp) / "source.json"

        srs_path.write_bytes(data)

        subprocess.run(
            [
                "sing-box",
                "rule-set",
                "decompile",
                str(srs_path),
                "-o",
                str(json_path),
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        parsed = json.loads(json_path.read_text(encoding="utf-8"))

    return extract_domains_from_json(parsed)


def write_domain_file(path: Path, domains: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        for domain in sorted(domains):
            file.write(f"domain:{domain}\n")


def compile_srs(json_path: Path, srs_path: Path) -> None:
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


def build_legacy_geoip_dat() -> None:
    """Build the legacy Telegram GeoIP DAT."""

    repo = Path("v2fly-geoip")

    if repo.exists():
        shutil.rmtree(repo)

    log("Cloning v2fly/geoip...")

    subprocess.run(
        [
            "git",
            "clone",
            "--depth",
            "1",
            "https://github.com/v2fly/geoip.git",
            str(repo),
        ],
        check=True,
    )

    config = {
        "input": [
            {
                "type": "text",
                "action": "add",
                "args": {
                    "name": "telegram",
                    "uri": str((OUT / "geoip-raw.txt").resolve()),
                },
            }
        ],
        "output": [
            {
                "type": "v2rayGeoIPDat",
                "action": "output",
                "args": {
                    "outputDir": str(OUT.resolve()),
                    "outputName": "evil-domains-geoip.dat",
                    "wantedList": ["telegram"],
                },
            }
        ],
    }

    config_path = repo / "evil-domains-geoip-config.json"

    config_path.write_text(
        json.dumps(config, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    log("Building evil-domains-geoip.dat...")

    subprocess.run(
        [
            "go",
            "run",
            "./",
            "-c",
            str(config_path.resolve()),
        ],
        cwd=repo,
        check=True,
    )

    log("Legacy GeoIP DAT built.")


def load_comparison_sources() -> tuple[dict[str, set[str]], dict[str, str]]:
    sources: dict[str, set[str]] = {}
    errors: dict[str, str] = {}

    optional_sources = {
        "runetfreedom_antifilter_all": RUNET_ANTIFILTER_URL,
        "russiafancylists_blacklist": RFL_BLACKLIST_URL,
        "russiafancylists_geoblock": RFL_GEOBLOCK_URL,
    }

    for name, url in optional_sources.items():
        try:
            log(f"Downloading comparison source: {name}")
            sources[name] = parse_text_domains(fetch(url))
            log(f"{name}: {len(sources[name])} domains")
        except Exception as exc:
            errors[name] = str(exc)
            log(f"WARNING: {name}: {exc}")

    return sources, errors


def build_comparison(
    sources: dict[str, set[str]],
    errors: dict[str, str],
    evil_domains: set[str],
) -> None:
    COMPARISON.mkdir(parents=True, exist_ok=True)

    all_sources = dict(sources)
    all_sources["evil_domains"] = evil_domains

    groups = {
        "rkn": [
            "itdog",
            "roscomvpn",
            "runetfreedom_ru_blocked",
            "runetfreedom_antifilter_all",
            "refilter",
            "russiafancylists_blacklist",
            "evil_domains",
        ],
        "foreign_geoblock": [
            "russiafancylists_geoblock",
        ],
    }

    statistics = []

    for name, domains in sorted(all_sources.items()):
        statistics.append({
            "source": name,
            "domains": len(domains),
            "available": True,
        })

    for name, error in sorted(errors.items()):
        statistics.append({
            "source": name,
            "domains": None,
            "available": False,
            "error": error,
        })

    with (COMPARISON / "source-statistics.csv").open(
        "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=["source", "domains", "available", "error"],
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(statistics)

    pairwise = []

    for group_name, members in groups.items():
        available = [
            name for name in members
            if name in all_sources
        ]

        for left_name, right_name in combinations(available, 2):
            left = all_sources[left_name]
            right = all_sources[right_name]

            intersection = left & right
            union = left | right

            pairwise.append({
                "group": group_name,
                "source_a": left_name,
                "source_b": right_name,
                "domains_a": len(left),
                "domains_b": len(right),
                "intersection": len(intersection),
                "only_a": len(left - right),
                "only_b": len(right - left),
                "jaccard_percent": round(
                    len(intersection) / len(union) * 100, 2
                ) if union else 100,
            })

    with (COMPARISON / "pairwise-overlap.csv").open(
        "w", newline="", encoding="utf-8"
    ) as file:
        fields = [
            "group",
            "source_a",
            "source_b",
            "domains_a",
            "domains_b",
            "intersection",
            "only_a",
            "only_b",
            "jaccard_percent",
        ]
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(pairwise)

    unique_report = {}

    for group_name, members in groups.items():
        available = [
            name for name in members
            if name in all_sources
        ]

        for name in available:
            own = all_sources[name]
            others = set()

            for other_name in available:
                if other_name != name:
                    others.update(all_sources[other_name])

            unique = own - others
            unique_report[name] = len(unique)

            filename = f"only-{name.replace('_', '-')}.txt"
            write_domain_file(COMPARISON / filename, unique)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sources": {
            name: len(domains)
            for name, domains in sorted(all_sources.items())
        },
        "unique_domains": unique_report,
        "errors": errors,
        "pairwise": pairwise,
        "groups": groups,
    }

    report_path = COMPARISON / "comparison-report.json"
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# evil-domains — source comparison",
        "",
        f"Generated: {report['generated_at']}",
        "",
        "## Source statistics",
        "",
        "| Source | Domains |",
        "|---|---:|",
    ]

    for name, count in sorted(report["sources"].items()):
        lines.append(f"| {name} | {count:,} |")

    lines += [
        "",
        "## Unique domains",
        "",
        "| Source | Unique domains |",
        "|---|---:|",
    ]

    for name, count in sorted(unique_report.items()):
        lines.append(f"| {name} | {count:,} |")

    lines += [
        "",
        "## Pairwise overlap",
        "",
        "| Source A | Source B | Intersection | Only A | Only B | Jaccard |",
        "|---|---|---:|---:|---:|---:|",
    ]

    for item in pairwise:
        lines.append(
            f"| {item['source_a']} | {item['source_b']} "
            f"| {item['intersection']:,} "
            f"| {item['only_a']:,} "
            f"| {item['only_b']:,} "
            f"| {item['jaccard_percent']}% |"
        )

    if errors:
        lines += ["", "## Source errors", ""]
        for name, error in sorted(errors.items()):
            lines.append(f"- **{name}:** {error}")

    lines += [
        "",
        "Note: sources may overlap or use different collection criteria.",
        "Derived lists are not necessarily independent sources.",
        "Foreign geoblock lists are kept separate from Russian blocklists.",
        "",
    ]

    (COMPARISON / "comparison-report.md").write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    history_path = COMPARISON / "comparison-history.json"

    if history_path.exists():
        history = json.loads(history_path.read_text(encoding="utf-8"))
    else:
        history = []

    snapshot = {
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "sources": report["sources"],
        "unique_domains": unique_report,
    }

    if not history or history[-1].get("date") != snapshot["date"]:
        history.append(snapshot)
    else:
        history[-1] = snapshot

    history = history[-90:]

    history_path.write_text(
        json.dumps(history, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    log("Comparison reports generated.")


def build_happ_geosite(
    evil_domains: set[str],
    ru_blocked: set[str],
    roscom_domains: set[str],
) -> None:
    repo = Path("domain-list-community")

    if repo.exists():
        shutil.rmtree(repo)

    log("Cloning v2fly/domain-list-community...")

    subprocess.run(
        [
            "git",
            "clone",
            "--depth",
            "1",
            "https://github.com/v2fly/domain-list-community.git",
            str(repo),
        ],
        check=True,
    )

    data_dir = repo / "data"

    # Full standard V2Fly GeoSite database with custom Happ categories.
    write_domain_file(data_dir / "evil-domains", evil_domains)
    write_domain_file(data_dir / "ru-blocked", ru_blocked)
    write_domain_file(data_dir / "category-geoblock-ru", roscom_domains)

    log("Building full Happ GeoSite database...")

    subprocess.run(
        [
            "go",
            "run",
            "./",
            "--outputdir=../output",
            "--outputname=evil-domains-happ.dat",
        ],
        cwd=repo,
        check=True,
    )

    # Legacy custom-only GeoSite database for OneXray.
    custom_data = Path("geosite-data")

    if custom_data.exists():
        shutil.rmtree(custom_data)

    custom_data.mkdir(parents=True, exist_ok=True)

    write_domain_file(custom_data / "evil-domains", evil_domains)

    log("Building legacy evil-domains.dat...")

    subprocess.run(
        [
            "go",
            "run",
            "./",
            "--datapath=../geosite-data",
            "--outputdir=../output",
            "--outputname=evil-domains.dat",
        ],
        cwd=repo,
        check=True,
    )

    log("Happ and legacy GeoSite databases built.")


def validate_artifacts() -> None:
    required = [
        "evil-domains.json",
        "evil-domains.srs",
        "evil-domains.dat",
        "evil-domains-geoip.dat",
        "evil-domains-happ.dat",
        "geosite-raw.txt",
        "geoip-raw.txt",
        "build-report.json",
        "comparison/comparison-report.md",
        "comparison/comparison-report.json",
        "comparison/source-statistics.csv",
        "comparison/pairwise-overlap.csv",
        "comparison/comparison-history.json",
    ]

    log("Validating generated artifacts...")

    for name in required:
        path = OUT / name

        if not path.is_file() or path.stat().st_size == 0:
            raise RuntimeError(f"Missing or empty artifact: {path}")

        log(f"OK: {name} ({path.stat().st_size:,} bytes)")

    log("All required artifacts are present.")


def main() -> None:
    OUT.mkdir(exist_ok=True)
    COMPARISON.mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------
    # 1. ITDOG
    # ---------------------------------------------------------

    log("Collecting ITDOG domains...")

    itdog_domains: set[str] = set()
    unique_additions: dict[str, int] = {}

    for directory in ("Categories", "Services"):
        for item in github_directory(directory):
            name = item["name"]

            if name in RUSSIA_INSIDE_EXCLUDED:
                continue

            key = f"itdoginfo/{directory}/{name}"

            unique_additions[key] = add_itdog_file(
                f"{directory}/{name}",
                itdog_domains,
            )

    for service in SELECTED_SERVICES:
        path = f"Services/{service}.lst"
        key = f"itdoginfo/{path}"

        unique_additions[key] = add_itdog_file(
            path,
            itdog_domains,
        )

    log(f"ITDOG: {len(itdog_domains)} domains")

    # ---------------------------------------------------------
    # 2. ROSCOMVPN
    # ---------------------------------------------------------

    log("Collecting RoscomVPN domains...")

    roscom_domains: set[str] = set()

    for category in ROSCOM_CATEGORIES:
        found = download_roscom_category(category)
        roscom_domains.update(found)

    log(f"RoscomVPN: {len(roscom_domains)} domains")

    # ---------------------------------------------------------
    # 3. Final evil-domains aggregate
    # ---------------------------------------------------------

    domains = set(itdog_domains)
    domains.update(roscom_domains)

    if len(domains) < 100:
        raise RuntimeError(
            f"Suspiciously small result: {len(domains)} domains"
        )

    log(f"evil-domains total: {len(domains)}")

    json_path = OUT / "evil-domains.json"
    srs_path = OUT / "evil-domains.srs"
    geosite_txt = OUT / "geosite-raw.txt"
    geoip_txt = OUT / "geoip-raw.txt"

    payload = {
        "version": 3,
        "rules": [{"domain_suffix": sorted(domains)}],
    }

    json_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    write_domain_file(geosite_txt, domains)

    # ---------------------------------------------------------
    # 4. Telegram IP list
    # ---------------------------------------------------------

    log("Downloading Telegram CIDRs...")

    cidr_raw = fetch(TELEGRAM_CIDR_URL).decode("utf-8")

    with geoip_txt.open("w", encoding="utf-8") as file:
        for line in cidr_raw.splitlines():
            line = line.strip()

            if line and not line.startswith("#"):
                file.write(f"{line}\n")

    # ---------------------------------------------------------
    # 5. Sing-box SRS
    # ---------------------------------------------------------

    compile_srs(json_path, srs_path)

    # ---------------------------------------------------------
    # 6. Legacy GeoIP DAT
    # ---------------------------------------------------------

    build_legacy_geoip_dat()

    # ---------------------------------------------------------
    # 7. Comparison sources
    # ---------------------------------------------------------

    log("Collecting comparison sources...")

    community = parse_text_domains(fetch(RUNET_COMMUNITY_URL))
    refilter = parse_text_domains(fetch(RUNET_REFILTER_URL))

    runetfreedom_ru_blocked = community | refilter

    comparison_sources = {
        "itdog": itdog_domains,
        "roscomvpn": roscom_domains,
        "runetfreedom_ru_blocked": runetfreedom_ru_blocked,
        "refilter": refilter,
    }

    comparison_errors: dict[str, str] = {}

    optional_sources, optional_errors = load_comparison_sources()
    comparison_sources.update(optional_sources)
    comparison_errors.update(optional_errors)

    # ---------------------------------------------------------
    # 8. Happ and legacy GeoSite DAT
    # ---------------------------------------------------------

    build_happ_geosite(
        evil_domains=domains,
        ru_blocked=runetfreedom_ru_blocked,
        roscom_domains=roscom_domains,
    )

    # ---------------------------------------------------------
    # 9. Comparison reports
    # ---------------------------------------------------------

    build_comparison(
        comparison_sources,
        comparison_errors,
        domains,
    )

    # ---------------------------------------------------------
    # 10. Build report
    # ---------------------------------------------------------

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_domains": len(domains),
        "itdog_domains": len(itdog_domains),
        "roscomvpn_domains": len(roscom_domains),
        "runetfreedom_ru_blocked_domains": len(runetfreedom_ru_blocked),
        "telegram_cidrs": len([
            line for line in cidr_raw.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]),
        "unique_additions_by_source": unique_additions,
        "comparison_errors": comparison_errors,
        "happ_geosite": "evil-domains-happ.dat",
        "happ_categories": [
            "evil-domains",
            "ru-blocked",
            "category-geoblock-ru",
        ],
        "legacy_geosite": "evil-domains.dat",
        "legacy_geoip": "evil-domains-geoip.dat",
    }

    (OUT / "build-report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    # ---------------------------------------------------------
    # 11. Validate all artifacts
    # ---------------------------------------------------------

    validate_artifacts()

    log(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (
        urllib.error.URLError,
        json.JSONDecodeError,
        RuntimeError,
        subprocess.CalledProcessError,
    ) as exc:
        print(f"BUILD FAILED: {exc}", file=sys.stderr)
        sys.exit(1)
