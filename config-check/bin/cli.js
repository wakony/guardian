#!/usr/bin/env node
'use strict';

const path = require('path');
const fs = require('fs');
const { scan } = require('../scanner');
const { loadRuleset, listBuiltinRulesets } = require('../rules');
const { formatJson, formatText } = require('../formatter');

// ─── CLI Argument Parsing ───────────────────────────────────────────────────

const args = process.argv.slice(2);

function getArg(name, fallback) {
  const idx = args.indexOf(name);
  if (idx === -1) return fallback;
  const val = args[idx + 1];
  if (!val || val.startsWith('--')) return fallback;
  return val;
}

function getArgAll(name) {
  const values = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === name && args[i + 1]) {
      values.push(args[i + 1]);
    }
  }
  return values;
}

if (args.includes('--help') || args.includes('-h')) {
  console.log(`
guardian-config-check — Build configuration integrity scanner

Usage:
  guardian-config-check [options]

Options:
  --dir <path>              Directory to scan (default: current directory)
  --json                    Output results as JSON
  --verbose                 Show scan progress
  --pre-commit              For use in git hooks (exit 1 on CRITICAL or HIGH findings)
  --no-color                Disable colored output
  --ruleset <name|path>     Load a ruleset (repeatable). Built-in: ${listBuiltinRulesets().join(', ') || 'none'}
  --no-builtin-rulesets     Don't load built-in rulesets (generic rules still apply)
  --list-rulesets           List available built-in rulesets
  --help, -h                Show this help

Examples:
  guardian-config-check                           Scan current dir with all defaults
  guardian-config-check --dir ./my-project        Scan a specific directory
  guardian-config-check --json --pre-commit       JSON output, fail on findings
  guardian-config-check --no-builtin-rulesets      Generic rules only, no IOC matching
  guardian-config-check --ruleset ./my-iocs.json  Add a custom ruleset
`);
  process.exit(0);
}

if (args.includes('--list-rulesets')) {
  const builtins = listBuiltinRulesets();
  if (builtins.length === 0) {
    console.log('No built-in rulesets found.');
  } else {
    console.log('Built-in rulesets:');
    for (const name of builtins) {
      try {
        const rs = loadRuleset(name);
        console.log(`  ${name} — ${rs.description || '(no description)'} (${rs.rules.length} rules)`);
      } catch {
        console.log(`  ${name} — (failed to load)`);
      }
    }
  }
  process.exit(0);
}

const OPTIONS = {
  dir: path.resolve(getArg('--dir', '.')),
  json: args.includes('--json'),
  verbose: args.includes('--verbose'),
  preCommit: args.includes('--pre-commit'),
  noColor: args.includes('--no-color'),
  noBuiltinRulesets: args.includes('--no-builtin-rulesets'),
  extraRulesets: getArgAll('--ruleset'),
};

// ─── Load Rulesets ──────────────────────────────────────────────────────────

const rulesets = [];
const rulesetNames = [];

// Load built-in rulesets by default
if (!OPTIONS.noBuiltinRulesets) {
  for (const name of listBuiltinRulesets()) {
    try {
      const rs = loadRuleset(name);
      rulesets.push(rs);
      rulesetNames.push(rs.name);
    } catch (err) {
      if (!OPTIONS.json) {
        console.error(`Warning: Failed to load built-in ruleset '${name}': ${err.message}`);
      }
    }
  }
}

// Load user-specified rulesets
for (const nameOrPath of OPTIONS.extraRulesets) {
  try {
    const rs = loadRuleset(nameOrPath);
    rulesets.push(rs);
    rulesetNames.push(rs.name);
  } catch (err) {
    console.error(`Error: Failed to load ruleset '${nameOrPath}': ${err.message}`);
    process.exit(2);
  }
}

// ─── Validate ───────────────────────────────────────────────────────────────

if (!fs.existsSync(OPTIONS.dir)) {
  console.error(`Error: Directory not found: ${OPTIONS.dir}`);
  process.exit(2);
}

// ─── Scan ───────────────────────────────────────────────────────────────────

const onFile = (OPTIONS.verbose && !OPTIONS.json)
  ? (relPath) => process.stdout.write(`\r  Scanning: ${relPath.slice(0, 60).padEnd(60)}`)
  : null;

if (OPTIONS.verbose && !OPTIONS.json) {
  console.log(`Scanning: ${OPTIONS.dir}`);
  if (rulesetNames.length > 0) {
    console.log(`Rulesets: ${rulesetNames.join(', ')}`);
  }
}

const { findings, stats } = scan(OPTIONS.dir, { rulesets, onFile });

if (OPTIONS.verbose && !OPTIONS.json) {
  process.stdout.write('\r' + ' '.repeat(70) + '\r');
}

// ─── Output ─────────────────────────────────────────────────────────────────

if (OPTIONS.json) {
  console.log(formatJson(findings, stats, OPTIONS.dir));
} else {
  console.log(formatText(findings, stats, OPTIONS.dir, {
    noColor: OPTIONS.noColor,
    rulesetNames,
  }));
}

// ─── Exit Code ──────────────────────────────────────────────────────────────

const critical = findings.filter(f => f.severity === 'CRITICAL').length;
const high = findings.filter(f => f.severity === 'HIGH').length;

if (critical > 0 || high > 0) {
  process.exit(1);
}

process.exit(0);
