'use strict';

const fs = require('fs');
const path = require('path');
const generic = require('./generic');

const RULESETS_DIR = path.join(__dirname, '..', 'rulesets');

/**
 * Load a ruleset by name or file path.
 * - Built-in names resolve to rulesets/<name>.json
 * - File paths resolve as-is
 */
function loadRuleset(nameOrPath) {
  let filePath;

  // Check if it's a path (contains slash/backslash or ends in .json)
  if (nameOrPath.includes('/') || nameOrPath.includes('\\') || nameOrPath.endsWith('.json')) {
    filePath = path.resolve(nameOrPath);
  } else {
    filePath = path.join(RULESETS_DIR, `${nameOrPath}.json`);
  }

  const raw = fs.readFileSync(filePath, 'utf8');
  const ruleset = JSON.parse(raw);

  if (!ruleset.name || !Array.isArray(ruleset.rules)) {
    throw new Error(`Invalid ruleset format in ${filePath}: requires "name" and "rules" array`);
  }

  return ruleset;
}

/**
 * List all built-in rulesets.
 */
function listBuiltinRulesets() {
  try {
    return fs.readdirSync(RULESETS_DIR)
      .filter(f => f.endsWith('.json'))
      .map(f => f.replace(/\.json$/, ''));
  } catch {
    return [];
  }
}

/**
 * Apply a loaded ruleset's filename-match rules (no file content needed).
 */
function applyRulesetFilename(ruleset, filePath, filename) {
  const findings = [];
  const lower = filename.toLowerCase();

  for (const rule of ruleset.rules) {
    if (rule.type !== 'filename-match') continue;
    if (!rule.patterns || !Array.isArray(rule.patterns)) continue;

    for (const pattern of rule.patterns) {
      if (lower === pattern.toLowerCase()) {
        findings.push({
          severity: rule.severity || 'HIGH',
          rule: rule.id || ruleset.name,
          file: filePath,
          line: null,
          detail: (rule.detail || "Matched pattern: '{match}'").replace('{match}', pattern),
        });
      }
    }
  }

  return findings;
}

/**
 * Apply a loaded ruleset's content rules (string-match, regex-match).
 */
function applyRulesetContent(ruleset, filePath, filename, content) {
  const findings = [];

  for (const rule of ruleset.rules) {
    if (!rule.patterns || !Array.isArray(rule.patterns)) continue;

    const type = rule.type || 'string-match';
    if (type === 'filename-match') continue; // handled separately

    const scope = rule.scope || 'all';

    // Scope filtering
    if (scope === 'config' && !generic.isConfigFile(filename)) continue;
    if (scope === 'scripts') {
      const lower = filename.toLowerCase();
      if (!lower.endsWith('.bat') && !lower.endsWith('.sh') && !lower.endsWith('.cmd') && !lower.endsWith('.ps1')) continue;
    }

    if (type === 'string-match') {
      for (const pattern of rule.patterns) {
        const idx = content.indexOf(pattern);
        if (idx !== -1) {
          const lineNum = content.substring(0, idx).split('\n').length;
          findings.push({
            severity: rule.severity || 'HIGH',
            rule: rule.id || ruleset.name,
            file: filePath,
            line: lineNum,
            detail: (rule.detail || "Matched pattern: '{match}'").replace('{match}', pattern),
          });
        }
      }
      continue;
    }

    if (type === 'regex-match') {
      for (const pattern of rule.patterns) {
        let re;
        try {
          re = new RegExp(pattern);
        } catch {
          continue;
        }
        const match = re.exec(content);
        if (match) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          findings.push({
            severity: rule.severity || 'HIGH',
            rule: rule.id || ruleset.name,
            file: filePath,
            line: lineNum,
            detail: (rule.detail || "Matched regex: '{match}'").replace('{match}', match[0].slice(0, 80)),
          });
        }
      }
    }
  }

  return findings;
}

module.exports = { loadRuleset, listBuiltinRulesets, applyRulesetFilename, applyRulesetContent };
