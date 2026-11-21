# Evil Domains

Domain-only aggregate for sing-box / Podkop.

## Outputs
- `output/evil-domains.json` — source JSON rule-set (version 3)
- `output/evil-domains.srs` — compiled binary rule-set
- `output/build-report.json` — source and domain counts

## Sources
- itdoginfo/allow-domains: Russia Inside composition (Categories + Services), plus selected standalone service lists.
- aleksandrberlin/roscom-vpn: `all.json`.

Only valid domain names are emitted. IP addresses and CIDR ranges are not included.
Matched domains are intended to use the proxy outbound; unmatched traffic remains direct.

## Build locally
Requires Python 3.10+ and `sing-box` in PATH:

```sh
python build.py
```

GitHub Actions runs daily and on pushes to `main`.
