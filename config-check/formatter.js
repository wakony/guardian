'use strict';

const { version } = require('./package.json');

const COLORS = {
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  green: '\x1b[32m',
  gray: '\x1b[90m',
  bold: '\x1b[1m',
  reset: '\x1b[0m',
};

const NO_COLORS = {
  red: '', yellow: '', cyan: '', green: '', gray: '', bold: '', reset: '',
};

function formatJson(findings, stats, dir) {
  const critical = findings.filter(f => f.severity === 'CRITICAL').length;
  const high = findings.filter(f => f.severity === 'HIGH').length;
  const warnings = findings.filter(f => f.severity === 'WARNING').length;

  return JSON.stringify({
    version,
    directory: dir,
    filesScanned: stats.filesScanned,
    elapsedMs: stats.elapsed,
    summary: { critical, high, warnings },
    findings,
    result: critical > 0 || high > 0 ? 'FAIL' : 'PASS',
  }, null, 2);
}

function formatText(findings, stats, dir, options) {
  const C = options.noColor ? NO_COLORS : COLORS;
  const lines = [];

  lines.push('');
  lines.push(`${C.bold}guardian-config-check v${version} — Build Configuration Integrity Scanner${C.reset}`);
  lines.push('');
  lines.push(`Scanning: ${dir}`);
  lines.push(`Files scanned: ${stats.filesScanned} (${stats.elapsed}ms)`);

  if (options.rulesetNames && options.rulesetNames.length > 0) {
    lines.push(`Rulesets: ${options.rulesetNames.join(', ')}`);
  }

  if (findings.length === 0) {
    lines.push('');
    lines.push(`${C.green}No issues found. All config files appear clean.${C.reset}`);
    lines.push('');
    return lines.join('\n');
  }

  lines.push('');

  const severityOrder = { CRITICAL: 0, HIGH: 1, WARNING: 2 };
  const sorted = [...findings].sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  for (const f of sorted) {
    const color = f.severity === 'CRITICAL' ? C.red : f.severity === 'HIGH' ? C.yellow : C.cyan;
    const location = f.line ? `${f.file}:${f.line}` : f.file;
    lines.push(`${color}[${f.severity}]${C.reset} ${C.bold}${f.rule}${C.reset}`);
    lines.push(`  File: ${location}`);
    lines.push(`  ${f.detail}`);
    lines.push('');
  }

  const critical = findings.filter(f => f.severity === 'CRITICAL').length;
  const high = findings.filter(f => f.severity === 'HIGH').length;
  const warnings = findings.filter(f => f.severity === 'WARNING').length;
  const result = critical > 0 || high > 0 ? 'FAIL' : 'PASS';
  const resultColor = critical > 0 ? C.red : high > 0 ? C.yellow : C.green;

  lines.push(`${C.bold}RESULT:${C.reset} ${C.red}${critical} critical${C.reset}, ${C.yellow}${high} high${C.reset}, ${C.cyan}${warnings} warnings${C.reset}`);
  lines.push(`Status: ${resultColor}${C.bold}${result}${C.reset}`);
  lines.push('');

  return lines.join('\n');
}

module.exports = { formatJson, formatText };
