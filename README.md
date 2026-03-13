# Guardian

Build integrity and supply chain defense toolkit.

## Tools

### config-check
Scans build configuration files for integrity issues — obfuscation, suspicious imports, hidden content, and known threat patterns. Zero-dependency npm package with pluggable rulesets.

```bash
# Install globally
npm install -g guardian-config-check

# Scan current directory (generic rules + built-in IOCs)
guardian-config-check

# Scan specific directory with verbose output
guardian-config-check --dir /path/to/project --verbose

# JSON output for CI/CD integration
guardian-config-check --json --pre-commit

# Generic rules only (no campaign IOC matching)
guardian-config-check --no-builtin-rulesets

# Add a custom ruleset
guardian-config-check --ruleset ./my-iocs.json
```

Install as git hook:
```bash
bash guardian/config-check/install-hook.sh
```

### push-monitor
Webhook server that monitors GitHub push events for anomalous patterns — multi-repo bursts, config-only modifications, force pushes, identity forgery.

```bash
cd guardian/push-monitor
WEBHOOK_SECRET=your_secret PORT=3000 node push-monitor.js
```

Endpoints: `POST /webhook`, `GET /health`, `GET /status`

### safe-build
Network-isolated build system using Docker. Installs dependencies with network access, then runs the build with **zero network connectivity** — preventing any external communication during build.

```bash
# Docker mode
bash guardian/safe-build/safe-build.sh /path/to/project "npm run build"

# Or use Docker Compose
cd guardian/safe-build
docker-compose run deps
docker-compose run build
```

GitHub Actions: Copy `safe-build.yml` to `.github/workflows/`

## Detection Rules

### YARA Rules (`rules/yara/`)
- `supply_chain_campaign.yar` — Supply chain attack indicators
- `config_injection.yar` — Config file injection detection
- `timestamp_forgery.yar` — Timestamp forgery toolkit detection

### Sigma Rules (`rules/sigma/`)
- `blockchain_api_build.yml` — Blockchain API calls from build processes
- `hidden_node_process.yml` — Hidden detached Node.js child processes
- `system_clock_git.yml` — System time changes before git operations

### GitHub Actions (`rules/github-actions/`)
- `supply-chain-check.yml` — Comprehensive CI/CD integrity check

## Setup Scripts

### Branch Protection
```bash
bash guardian/setup/branch-protection.sh owner/repo-name
```

### CODEOWNERS
Copy `guardian/setup/CODEOWNERS` to `.github/CODEOWNERS` in your repo.

### Pre-commit Hook
Copy `guardian/setup/pre-commit` to `.git/hooks/pre-commit` and `chmod +x`.

## Quick Deploy

1. Copy `rules/github-actions/supply-chain-check.yml` to `.github/workflows/` on all repos
2. Copy `commit-verify/commit-verify.yml` to `.github/workflows/` on all repos
3. Copy `setup/CODEOWNERS` to `.github/CODEOWNERS` on all repos
4. Run `bash setup/branch-protection.sh owner/repo` for each repo
5. Install pre-commit hook: `bash config-check/install-hook.sh`
6. Start push monitor: `node push-monitor/push-monitor.js`

## Research Credit

Detection rules and IOCs in this toolkit are based on the **Cross-Chain TxDataHiding Crypto Heist** research series by [Ransom-ISAC](https://ransom-isac.org/) and [Crystal Intelligence](https://crystalintelligence.com/):

- [Part 1: Cross-Chain TxDataHiding Crypto Heist](https://ransom-isac.org/blog/cross-chain-txdatahiding-crypto-heist/) — Discovery of the XCTDH technique: blockchain-based C2 using TRON/Aptos indexing and BSC payload delivery
- [Parts 1-2 Technical Analysis (GitHub)](https://github.com/Ransom-ISAC-Org/LOCKSTAR/tree/main/XCTDH%20Crypto%20Heist%20-%20Parts%201%20and%202) — YARA rules, detection tooling, and payload simulation
- [Part 4: How Financial Forensics Proved North Korea's Blockchain Malware](https://crystalintelligence.com/investigations/how-we-proved-north-koreas-blockchain-malware-campaign/) — Crystal Intelligence & Ransom-ISAC collaboration on attribution and financial forensics

Identity forgery and timestamp manipulation detection (YARA rules, Sigma rules, and pre-commit checks) based on original analysis by **Ben Bishop**.

## License

MIT
