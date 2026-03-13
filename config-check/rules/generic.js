'use strict';

// Config file patterns — files that should never contain dynamic imports, eval, etc.
const CONFIG_PATTERNS = [
  /^postcss\.config\./,
  /^next\.config\./,
  /^tailwind\.config\./,
  /^vite\.config\./,
  /^webpack\.config\./,
  /^babel\.config\./,
  /^jest\.config\./,
  /^rollup\.config\./,
  /^\.eslintrc/,
  /^prettier\.config\./,
  /^commitlint\.config\./,
  /^turbo\.json$/,
  /^nx\.json$/,
  /^tsconfig.*\.json$/,
];

function isConfigFile(filename) {
  return CONFIG_PATTERNS.some(p => p.test(filename));
}

// ── Rule: Obfuscated code in config files ───────────────────────────────────

function shannonEntropy(str) {
  if (str.length === 0) return 0;
  const freq = {};
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const key in freq) {
    const p = freq[key] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function checkObfuscation(filePath, filename, content) {
  if (!isConfigFile(filename)) return [];
  const findings = [];
  const lines = content.split('\n');

  // 1. Hex escape sequences: \x41\x42\x43...
  const hexEscapes = (content.match(/\\x[0-9a-fA-F]{2}/g) || []).length;
  if (hexEscapes >= 8) {
    findings.push({
      severity: 'CRITICAL',
      rule: 'OBFUSCATED_CONFIG',
      file: filePath,
      line: null,
      detail: `${hexEscapes} hex escape sequences (\\x..) — config files should not contain encoded strings`,
    });
  }

  // 2. Unicode escape sequences: \u0041\u0042...
  const unicodeEscapes = (content.match(/\\u[0-9a-fA-F]{4}/g) || []).length;
  if (unicodeEscapes >= 8) {
    findings.push({
      severity: 'CRITICAL',
      rule: 'OBFUSCATED_CONFIG',
      file: filePath,
      line: null,
      detail: `${unicodeEscapes} unicode escape sequences (\\u....) — config files should not contain encoded strings`,
    });
  }

  // 3. Obfuscator variable names: _0x4a2b, _$_1e42, _$af163278
  const obfVarNames = (content.match(/_(?:0x|\$_?)[a-fA-F0-9]{4,}/g) || []);
  if (obfVarNames.length >= 3) {
    findings.push({
      severity: 'CRITICAL',
      rule: 'OBFUSCATED_CONFIG',
      file: filePath,
      line: null,
      detail: `${obfVarNames.length} obfuscator-style variable names (${obfVarNames.slice(0, 3).join(', ')}...)`,
    });
  }

  // 4. Excessive bracket notation: obj['prop']['prop2'] used to hide property access
  const bracketAccess = (content.match(/\[['"][a-zA-Z_$][^'"]{0,50}['"]\]/g) || []).length;
  if (bracketAccess >= 15) {
    findings.push({
      severity: 'HIGH',
      rule: 'OBFUSCATED_CONFIG',
      file: filePath,
      line: null,
      detail: `${bracketAccess} bracket-notation property accesses — possible obfuscation to hide API calls`,
    });
  }

  // 5. String concatenation chains: 'c'+'h'+'i'+'l'+'d'+'_'+'p'+'r'+'o'+'c'...
  const concatChains = (content.match(/(['"].\w{0,2}['"]\s*\+\s*){6,}/g) || []).length;
  if (concatChains > 0) {
    findings.push({
      severity: 'CRITICAL',
      rule: 'OBFUSCATED_CONFIG',
      file: filePath,
      line: null,
      detail: `${concatChains} string concatenation chain(s) — character-by-character string building is an obfuscation technique`,
    });
  }

  // 6. Long hex or base64 blobs (encoded payloads)
  const hexBlobs = content.match(/[0-9a-fA-F]{200,}/g);
  if (hexBlobs) {
    findings.push({
      severity: 'CRITICAL',
      rule: 'OBFUSCATED_CONFIG',
      file: filePath,
      line: null,
      detail: `Hex-encoded blob (${hexBlobs[0].length} chars) — possible embedded payload`,
    });
  }

  const b64Blobs = content.match(/[A-Za-z0-9+/]{200,}={0,2}/g);
  if (b64Blobs) {
    // Filter out things that could be legit (long URLs, hashes in lockfiles)
    const suspicious = b64Blobs.filter(b => b.length > 300);
    if (suspicious.length > 0) {
      findings.push({
        severity: 'HIGH',
        rule: 'OBFUSCATED_CONFIG',
        file: filePath,
        line: null,
        detail: `Base64-encoded blob (${suspicious[0].length} chars) — possible embedded payload`,
      });
    }
  }

  // 7. High-entropy lines (Shannon entropy — normal code is ~4.0-4.5, obfuscated is >5.0)
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line.length < 100) continue; // only check substantial lines
    const entropy = shannonEntropy(line);
    if (entropy > 5.5) {
      findings.push({
        severity: 'CRITICAL',
        rule: 'OBFUSCATED_CONFIG',
        file: filePath,
        line: i + 1,
        detail: `Line ${i + 1} has Shannon entropy ${entropy.toFixed(2)} (normal code: ~4.0-4.5, obfuscated: >5.0)`,
      });
      break; // one high-entropy finding per file is enough
    } else if (entropy > 5.0 && line.length > 200) {
      findings.push({
        severity: 'HIGH',
        rule: 'OBFUSCATED_CONFIG',
        file: filePath,
        line: i + 1,
        detail: `Line ${i + 1} has Shannon entropy ${entropy.toFixed(2)} on ${line.length} chars (possible obfuscation)`,
      });
      break;
    }
  }

  return findings;
}

// ── Rule: Trailing whitespace payload (steganographic concealment) ───────────

function checkTrailingWhitespace(filePath, filename, lines) {
  if (!isConfigFile(filename)) return [];
  const findings = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trimEnd();
    const trailing = line.length - trimmed.length;
    if (trailing >= 50) {
      findings.push({
        severity: 'CRITICAL',
        rule: 'TRAILING_WHITESPACE_PAYLOAD',
        file: filePath,
        line: i + 1,
        detail: `Line ${i + 1} has ${trailing} trailing whitespace characters (hidden payload indicator)`,
      });
    }
  }
  return findings;
}

// ── Rule: Suspicious imports in config files ────────────────────────────────

const SUSPICIOUS_IMPORTS = [
  'createRequire',
  'child_process',
  'eval(',
  'Function(',
  'new Function',
  'String.fromCharCode',
  'execSync',
  'spawnSync',
];

function checkSuspiciousImports(filePath, filename, content) {
  if (!isConfigFile(filename)) return [];
  const findings = [];
  for (const pattern of SUSPICIOUS_IMPORTS) {
    const idx = content.indexOf(pattern);
    if (idx !== -1) {
      const lineNum = content.substring(0, idx).split('\n').length;
      findings.push({
        severity: 'CRITICAL',
        rule: 'SUSPICIOUS_IMPORT',
        file: filePath,
        line: lineNum,
        detail: `Found '${pattern}' — should not appear in ${filename}`,
      });
    }
  }
  return findings;
}

// ── Rule: Global variable campaign markers in configs ───────────────────────

const GLOBAL_MARKER_REGEX = /global\[['"][^'"]+['"]\]\s*=/;
const GLOBAL_UNDERSCORE_REGEX = /global\._[A-Za-z]/;

function checkGlobalMarkers(filePath, filename, lines) {
  if (!isConfigFile(filename)) return [];
  const findings = [];
  for (let i = 0; i < lines.length; i++) {
    if (GLOBAL_MARKER_REGEX.test(lines[i]) || GLOBAL_UNDERSCORE_REGEX.test(lines[i])) {
      findings.push({
        severity: 'HIGH',
        rule: 'GLOBAL_CAMPAIGN_MARKER',
        file: filePath,
        line: i + 1,
        detail: 'Global variable assignment in config file (campaign marker pattern)',
      });
    }
  }
  return findings;
}

// ── Rule: Forged bot identity scripts ───────────────────────────────────────

const IDENTITY_FORGERY_PATTERNS = [
  'GIT_COMMITTER_NAME',
  'GIT_AUTHOR_NAME',
  'GIT_COMMITTER_DATE',
  'GIT_AUTHOR_DATE',
  'vercel[bot]',
  'dependabot[bot]',
  'renovate[bot]',
  'w32tm /resync',
  'git push -uf',
  'git commit --amend',
];

function checkForgedBotIdentity(filePath, filename, content) {
  const lower = filename.toLowerCase();
  if (!lower.endsWith('.bat') && !lower.endsWith('.sh') && !lower.endsWith('.cmd')) return [];

  let matchCount = 0;
  for (const pattern of IDENTITY_FORGERY_PATTERNS) {
    if (content.includes(pattern)) matchCount++;
  }

  const findings = [];
  if (matchCount >= 3) {
    findings.push({
      severity: 'CRITICAL',
      rule: 'FORGED_BOT_IDENTITY',
      file: filePath,
      line: null,
      detail: `Script contains ${matchCount} identity forgery patterns (git identity + timestamp manipulation)`,
    });
  } else if (matchCount >= 2) {
    findings.push({
      severity: 'HIGH',
      rule: 'FORGED_BOT_IDENTITY',
      file: filePath,
      line: null,
      detail: `Script contains ${matchCount} identity forgery indicators`,
    });
  }
  return findings;
}

// ── Rule: Suspicious batch file names ───────────────────────────────────────

function checkSuspiciousBatchFile(filePath, filename) {
  const lower = filename.toLowerCase();
  if (!lower.endsWith('.bat')) return [];

  const findings = [];
  if (lower.includes('temp') || lower.includes('auto_push')) {
    findings.push({
      severity: 'HIGH',
      rule: 'SUSPICIOUS_BATCH_FILE',
      file: filePath,
      line: null,
      detail: `Suspicious batch file: ${filename}`,
    });
  }
  return findings;
}

// ── Exports ─────────────────────────────────────────────────────────────────

module.exports = {
  isConfigFile,
  shannonEntropy,
  rules: [
    { name: 'obfuscation', phase: 'content', fn: checkObfuscation },
    { name: 'trailingWhitespace', phase: 'lines', fn: checkTrailingWhitespace },
    { name: 'suspiciousImports', phase: 'content', fn: checkSuspiciousImports },
    { name: 'globalMarkers', phase: 'lines', fn: checkGlobalMarkers },
    { name: 'forgedBotIdentity', phase: 'content', fn: checkForgedBotIdentity },
    { name: 'suspiciousBatchFile', phase: 'filename', fn: checkSuspiciousBatchFile },
  ],
};
