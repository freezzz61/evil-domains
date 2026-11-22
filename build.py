#!/usr/bin/env python3
"""Build a domain-only sing-box rule-set (srs) and Xray GeoData (dat)."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

# ... (остальные константы остаются без изменений) ...

# Официальный список CIDR-адресов Telegram
TELEGRAM_CIDR_URL = "https://core.telegram.org/resources/cidr.txt"

# ... (функции fetch, github_directory, parse_domain_line, ... остаются без изменений) ...

def main() -> None:
    # ... (начало функции main без изменений) ...

    # --- 1. Сбор доменов ---
    # ... (код сбора доменов из itdoginfo и roscomvpn-geosite) ...

    if len(domains) < 100:
        raise RuntimeError(f"Suspiciously small result: only {len(domains)} domains")

    # --- 2. Сохранение файлов ---
    json_path = out_dir / "evil-domains.json"
    srs_path = out_dir / "evil-domains.srs"
    txt_path = out_dir / "geosite-raw.txt"
    geoip_txt_path = out_dir / "geoip-raw.txt"

    # Формируем JSON для sing-box (Podkop)
    payload = {
        "version": 3,
        "rules": [{"domain_suffix": sorted(domains)}],
    }
    json_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    # Формируем TXT для v2fly (OneXray) - домены
    with txt_path.open("w", encoding="utf-8") as f:
        for d in sorted(domains):
            f.write(f"domain:{d}\n")

    # --- 3. Сбор IP-адресов Telegram ---
    print("Downloading Telegram CIDR list...")
    try:
        cidr_raw = fetch(TELEGRAM_CIDR_URL).decode("utf-8")
        with geoip_txt_path.open("w", encoding="utf-8") as f:
            for line in cidr_raw.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    f.write(f"{line}\n")
        print(f"Saved Telegram CIDRs to {geoip_txt_path}")
    except Exception as e:
        print(f"Warning: Failed to fetch Telegram CIDR list: {e}. Skipping geoip.")

    # --- 4. Компиляция SRS ---
    compile_srs(json_path, srs_path)

    # --- 5. Отчет ---
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
    # ... (блок обработки ошибок без изменений) ...
