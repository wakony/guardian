# guardian-config-check

Build configuration integrity scanner. Detects supply chain compromise indicators in config files — zero dependencies, pluggable rulesets.

## Install

```bash
npm install -g guardian-config-check
```

## Usage

```bash
# Scan current directory
guardian-config-check

# Scan a specific project
guardian-config-check --dir /path/to/project

# JSON output for CI/CD pipelines
guardian-config-check --json

# Verbose scan progress
guardian-config-check --verbose

# Generic detection only (no campaign-specific IOCs)
guardian-config-check --no-builtin-rulesets

# Load a custom ruleset
guardian-config-check --ruleset ./my-indicators.json
```

## What it detects

**Generic rules** (always active):

| Rule | Severity | What it catches |
|------|----------|-----------------|
| `OBFUSCATED_CONFIG` | CRITICAL/HIGH | Hex escapes, unicode escapes, obfuscator variable names (`_0x...`), bracket-notation chains, string concatenation building, hex/base64 blobs, high Shannon entropy lines |
| `TRAILING_WHITESPACE_PAYLOAD` | CRITICAL | 50+ trailing spaces on a line (steganographic concealment) |
| `SUSPICIOUS_IMPORT` | CRITICAL | `createRequire`, `child_process`, `eval()`, `execSync` in configs |
| `GLOBAL_CAMPAIGN_MARKER` | HIGH | `global['...'] =` assignments in config files |
| `FORGED_BOT_IDENTITY` | CRITICAL/HIGH | Scripts with git identity forgery patterns |
| `SUSPICIOUS_BATCH_FILE` | HIGH | Batch files matching attacker toolkit naming |

**Built-in rulesets** (loaded by default, disable with `--no-builtin-rulesets`):

- `supply-chain-iocs` — Campaign-specific wallet addresses, C2 infrastructure IPs, obfuscation seeds, blockchain API indicators, toolkit filenames

## Inline suppression

Suppress findings on specific lines when you have legitimate reasons:

```js
const { createRequire } = require('module'); // guardian-ignore

// guardian-ignore-next-line
global['myPlugin'] = true;
```

## Custom rulesets

Create a JSON file with this structure:

```json
{
  "name": "my-ruleset",
  "description": "Custom threat indicators",
  "rules": [
    {
      "id": "MY_IOC",
      "severity": "CRITICAL",
      "type": "string-match",
      "scope": "all",
      "detail": "Found indicator: '{match}'",
      "patterns": ["suspicious-string-1", "suspicious-string-2"]
    }
  ]
}
```

**Rule types:** `string-match`, `regex-match`, `filename-match`
**Scopes:** `all` (every file), `config` (build config files only), `scripts` (`.bat`, `.sh`, `.cmd`, `.ps1`)

```bash
guardian-config-check --ruleset ./my-ruleset.json
```

## Git hook

```bash
# Auto-installs as pre-commit hook
bash install-hook.sh
```

Or manually — add to `.git/hooks/pre-commit`:

```bash
guardian-config-check --pre-commit
```

## Programmatic API

```js
const { scan, loadRuleset } = require('guardian-config-check');

const ruleset = loadRuleset('supply-chain-iocs');
const { findings, stats } = scan('/path/to/project', { rulesets: [ruleset] });

for (const f of findings) {
  console.log(`[${f.severity}] ${f.rule}: ${f.file}:${f.line} — ${f.detail}`);
}
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No CRITICAL or HIGH findings |
| `1` | CRITICAL or HIGH findings detected |
| `2` | Invalid arguments or missing directory |

## Related

[C2Monitor](https://github.com/wakony/C2Monitor) — Runtime C2 beacon detection for Windows. Catches the same supply chain attacks at the network level (beaconing, blockchain C2 resolution, DGA domains). Use both: guardian-config-check catches compromised configs *before* they run, C2Monitor catches them *if* they run.

## License

MIT
