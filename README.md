# SearchStrike-Checker

PowerShell forensic detection tool for the **SearchStrike** malware campaign (KISA 2026 hunting guidance), plus an automated tracker that maintains the indicator-of-compromise (IOC) data feeding it.

## What's in this repo

- **`SearchStrike-Checker.ps1`** / **`.bat`** / **`.md`** — the working detection tool and its documentation. Run `SearchStrike-Checker.bat` (or the `.ps1` directly) on a Windows host to scan for filesystem, registry, process, network, and hash indicators of SearchStrike infection. **These three files are never modified by the IOC tracker below.**
- **`iocs/`** — cumulative, machine-readable IOC data, updated automatically on a schedule (see "How the tracker works").
- **`snapshots/<YYYY-MM-DD>.md`** — one dated report per tracker run.
- **`latest.md`** — the most recent snapshot report (same content, overwritten every run).
- **`SCRIPT-SYNC.md`** — a running checklist of indicators the tracker has found that are not yet reflected in `SearchStrike-Checker.ps1`, for a human to apply.

## How to run the detection tool

```
SearchStrike-Checker.bat
```

or directly:

```
PowerShell.exe -ExecutionPolicy Bypass -File SearchStrike-Checker.ps1
```

Run as Administrator for a full scan (HKLM Run key access requires elevation). Findings are printed to the console and logged to `SearchStrike_Check_<timestamp>.log` next to the script. See `SearchStrike-Checker.md` for a detailed breakdown of each check.

## How the tracker works

An automated agent periodically re-reads `iocs/`, searches for new SearchStrike/EtherRAT reporting, and merges any new indicators in — cumulatively, never deleting or downgrading confidence. Every indicator carries a **provenance** tag:

- `seed` — extracted verbatim from `SearchStrike-Checker.ps1`'s hardcoded arrays
- `verified` — confirmed in the body of a report successfully fetched by the tracker
- `unverified` — seen only in a search snippet, or in a report whose fetch was blocked

## ⚠️ Firewall usage — read before blocking anything

- **`iocs/domains.txt` is the ONLY file safe to feed into a firewall / blocklist.** It contains attacker-registered C2 domains only (`seed` and `verified` provenance), one per line, un-defanged.
- **`iocs/rpc-endpoints.txt` must NEVER be blocked.** It lists legitimate public Ethereum RPC providers (e.g. Flashbots, LlamaRPC, BlockPI, dRPC, Blast API) that the malware abuses as a blockchain-based C2 channel ("EtherHiding"). Blocking them breaks real blockchain traffic for legitimate users and does not stop the malware, which simply switches providers. Use this file only as a hunting/detection signal (e.g. DNS query logging), never as a block list.
- `iocs/unverified-domains.txt` — C2 domain candidates not yet confirmed; review before blocking.
- `iocs/needs-review.txt` — hosts whose classification (attacker infrastructure vs. abused legitimate service) is unclear; do not block until reviewed.
- `iocs/sha256.txt` — known-malicious file hashes, tab-separated: `sha256 <TAB> masqueraded tool <TAB> date <TAB> provenance`.

Raw blocklist URL (for firewall/EDR ingestion):
```
https://raw.githubusercontent.com/cisspco/SearchStrike-Checker/main/iocs/domains.txt
```

## Current counts (as of 2026-09-04 UTC)

| File | Count |
|---|---|
| C2 domains (`iocs/domains.txt`) | 10 |
| Abused RPC endpoints (`iocs/rpc-endpoints.txt`) | 5 |
| Needs review (`iocs/needs-review.txt`) | 4 |
| File hashes (`iocs/sha256.txt`) | 11 |
| Unverified domain candidates (`iocs/unverified-domains.txt`) | 0 |

See `latest.md` for the full current snapshot and campaign summary.
