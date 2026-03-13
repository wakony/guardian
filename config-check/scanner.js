'use strict';

const fs = require('fs');
const path = require('path');
const generic = require('./rules/generic');
const { applyRulesetFilename, applyRulesetContent } = require('./rules');

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', '.next', '.vercel',
  '.nuxt', '.output', 'coverage', '.cache', '.turbo', '.svelte-kit',
]);

const TEXT_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx',
  '.json', '.yml', '.yaml', '.toml',
  '.bat', '.sh', '.cmd', '.ps1',
  '.md', '.txt', '.cfg', '.ini', '.conf',
]);

const SUPPRESS_PATTERN = /guardian-ignore/;

function walkDir(dir, callback) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      walkDir(path.join(dir, entry.name), callback);
    } else if (entry.isFile()) {
      callback(path.join(dir, entry.name), entry.name);
    }
  }
}

/**
 * Build a set of suppressed line numbers from inline comments.
 * Supports:
 *   // guardian-ignore          (suppresses the current line)
 *   // guardian-ignore-next-line (suppresses the next line)
 *   /* guardian-ignore * /       (same, in block comment form)
 */
function getSuppressedLines(lines) {
  const suppressed = new Set();
  for (let i = 0; i < lines.length; i++) {
    if (SUPPRESS_PATTERN.test(lines[i])) {
      suppressed.add(i + 1); // suppress this line (1-indexed)
      if (lines[i].includes('guardian-ignore-next-line')) {
        suppressed.add(i + 2); // also suppress next line
      }
    }
  }
  return suppressed;
}

/**
 * Filter out findings on suppressed lines.
 */
function filterSuppressed(newFindings, suppressed) {
  if (suppressed.size === 0) return newFindings;
  return newFindings.filter(f => !f.line || !suppressed.has(f.line));
}

/**
 * Scan a directory for supply chain integrity issues.
 *
 * @param {string} dir - Directory to scan
 * @param {object} options
 * @param {Array} options.rulesets - Loaded ruleset objects to apply
 * @param {function} [options.onFile] - Called with (relativePath) for progress reporting
 * @returns {{ findings: Array, stats: { filesScanned: number, elapsed: number } }}
 */
function scan(dir, options) {
  const { rulesets = [], onFile } = options || {};
  const startTime = Date.now();
  const findings = [];
  let filesScanned = 0;

  walkDir(dir, (filePath, filename) => {
    const relPath = path.relative(dir, filePath);

    // ── Filename-only rules (no file read needed) ───────────────
    for (const rule of generic.rules) {
      if (rule.phase === 'filename') {
        findings.push(...rule.fn(relPath, filename));
      }
    }

    // Ruleset filename-match rules
    for (const ruleset of rulesets) {
      findings.push(...applyRulesetFilename(ruleset, relPath, filename));
    }

    // ── Skip large/empty/binary files ────────────────────────────
    let stat;
    try {
      stat = fs.statSync(filePath);
    } catch {
      return;
    }

    if (stat.size > 1024 * 1024 || stat.size === 0) return;

    const ext = path.extname(filename).toLowerCase();
    if (!TEXT_EXTENSIONS.has(ext) && !generic.isConfigFile(filename)) return;

    let content;
    try {
      content = fs.readFileSync(filePath, 'utf8');
    } catch {
      return;
    }

    filesScanned++;
    if (onFile) onFile(relPath);

    const lines = content.split('\n');
    const suppressed = getSuppressedLines(lines);

    // ── Generic rules ────────────────────────────────────────────
    for (const rule of generic.rules) {
      let results = [];
      if (rule.phase === 'content') {
        results = rule.fn(relPath, filename, content);
      } else if (rule.phase === 'lines') {
        results = rule.fn(relPath, filename, lines);
      }
      findings.push(...filterSuppressed(results, suppressed));
    }

    // ── Ruleset rules (string-match, regex-match on content) ────
    for (const ruleset of rulesets) {
      const results = applyRulesetContent(ruleset, relPath, filename, content);
      findings.push(...filterSuppressed(results, suppressed));
    }
  });

  return {
    findings,
    stats: {
      filesScanned,
      elapsed: Date.now() - startTime,
    },
  };
}

module.exports = { scan };
