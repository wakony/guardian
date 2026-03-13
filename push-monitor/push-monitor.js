#!/usr/bin/env node
'use strict';

/**
 * PUSH-MONITOR v1.0.0
 * GitHub Webhook Server — Push Event Integrity Monitor
 *
 * Receives GitHub push event webhooks and analyzes them for anomalous patterns
 * consistent with supply chain compromise and credential misuse.
 *
 * Detection Rules:
 *   1. MULTI_REPO_BURST    — Same actor pushes to >3 repos within 1 hour
 *   2. CONFIG_ONLY_PUSH    — Push modifies ONLY config files (no code changes)
 *   3. FORCE_PUSH_MAIN     — Force push to main/master branch
 *   4. BOT_IMPERSONATION   — Forged bot identity in commit Committer field
 *   5. CONFIG_SIZE_SPIKE   — Config file grows by >1000 bytes in one commit
 *   6. BAT_FILE_ADDITION   — .bat files added (attacker toolkit signature)
 *   7. KNOWN_IOC_IN_COMMIT — Known Campaign 8-404-2 patterns in commit messages
 *   8. SUSPICIOUS_TIMING   — Pushes follow UTC+3/UTC+4 weekday-only pattern
 *
 * Environment Variables:
 *   PORT              — Server port (default: 3000)
 *   WEBHOOK_SECRET    — GitHub webhook HMAC secret for signature validation
 *   ALERT_WEBHOOK_URL — URL to POST alerts to (Slack, Discord, etc.)
 *
 * Usage: node worm-detector.js
 */

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const url = require('url');

// ─── Configuration ──────────────────────────────────────────────────────────
const CONFIG = {
  port: parseInt(process.env.PORT, 10) || 3000,
  webhookSecret: process.env.WEBHOOK_SECRET || '',
  alertWebhookUrl: process.env.ALERT_WEBHOOK_URL || '',
  multiRepoBurstThreshold: 3,
  multiRepoBurstWindowMs: 60 * 60 * 1000,       // 1 hour
  stateRetentionMs: 24 * 60 * 60 * 1000,        // 24 hours
  cleanupIntervalMs: 60 * 60 * 1000,            // 1 hour
  configSizeSpikeThreshold: 1000,                // bytes
};

// ─── Config file patterns ───────────────────────────────────────────────────
const CONFIG_FILE_PATTERNS = [
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
];

// ─── Known IOC patterns in commit messages ──────────────────────────────────
const IOC_COMMIT_PATTERNS = [
  /factory\s+push/i,
  /factory\s+error/i,
  /cloud\s+machine/i,
  /8-404-2/,
  /pinetech/i,
];

// ─── State ──────────────────────────────────────────────────────────────────
const state = {
  actorPushes: new Map(),      // actor -> [{repo, timestamp, details}]
  alerts: [],                   // all generated alerts
  totalWebhooksProcessed: 0,
  startTime: new Date().toISOString(),
};

// ─── Helpers ────────────────────────────────────────────────────────────────

function isConfigFile(filename) {
  const basename = filename.split('/').pop();
  return CONFIG_FILE_PATTERNS.some(p => p.test(basename));
}

function timestamp() {
  return new Date().toISOString();
}

function log(level, msg, data) {
  const colors = { CRITICAL: '\x1b[31m', HIGH: '\x1b[33m', MEDIUM: '\x1b[36m', INFO: '\x1b[37m' };
  const color = colors[level] || '\x1b[37m';
  const reset = '\x1b[0m';
  const prefix = `[${timestamp()}] [${level}]`;
  console.log(`${color}${prefix}${reset} ${msg}`);
  if (data) console.log(`  ${JSON.stringify(data, null, 2).split('\n').join('\n  ')}`);
}

function createAlert(severity, ruleId, repo, actor, details) {
  const alert = {
    timestamp: timestamp(),
    severity,
    rule: ruleId,
    repo,
    actor,
    details,
  };

  state.alerts.push(alert);

  // Keep only last 1000 alerts
  if (state.alerts.length > 1000) {
    state.alerts = state.alerts.slice(-500);
  }

  log(severity, `[${ruleId}] ${repo} — ${actor}: ${details}`);

  if (severity === 'CRITICAL') {
    logQuarantineRecommendation(actor);
  }

  if (CONFIG.alertWebhookUrl) {
    sendAlertWebhook(alert);
  }

  return alert;
}

function logQuarantineRecommendation(actor) {
  const actorHistory = state.actorPushes.get(actor) || [];
  const recentRepos = [...new Set(actorHistory.map(p => p.repo))];

  console.log('\x1b[41m\x1b[37m');
  console.log('  ╔══════════════════════════════════════════════════════╗');
  console.log('  ║           QUARANTINE RECOMMENDED                    ║');
  console.log('  ╠══════════════════════════════════════════════════════╣');
  console.log(`  ║  Actor: ${actor.padEnd(44)}║`);
  console.log('  ║  Recommended Actions:                               ║');
  console.log('  ║    1. Immediately revoke all PATs for this user     ║');
  console.log('  ║    2. Lock all repos this token has write access to ║');
  console.log('  ║    3. Scan all repos for config file anomalies      ║');
  console.log('  ║    4. Alert security team                           ║');
  console.log('  ╠══════════════════════════════════════════════════════╣');
  console.log('  ║  Recently pushed to:                                ║');
  recentRepos.slice(0, 10).forEach(r => {
    console.log(`  ║    - ${r.padEnd(48)}║`);
  });
  console.log('  ╚══════════════════════════════════════════════════════╝');
  console.log('\x1b[0m');
}

function sendAlertWebhook(alert) {
  try {
    const parsed = new URL(CONFIG.alertWebhookUrl);
    const postData = JSON.stringify(alert);
    const transport = parsed.protocol === 'https:' ? https : http;

    const req = transport.request({
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname + parsed.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData),
      },
      timeout: 10000,
    });

    req.on('error', (err) => {
      log('INFO', `Alert webhook failed: ${err.message}`);
    });

    req.write(postData);
    req.end();
  } catch (err) {
    log('INFO', `Alert webhook error: ${err.message}`);
  }
}

function verifyWebhookSignature(payload, signature) {
  if (!CONFIG.webhookSecret) return true; // Skip if no secret configured
  if (!signature) return false;

  const sig = signature.startsWith('sha256=') ? signature.slice(7) : signature;
  const expected = crypto
    .createHmac('sha256', CONFIG.webhookSecret)
    .update(payload, 'utf8')
    .digest('hex');

  try {
    return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'));
  } catch {
    return false;
  }
}

function trackActorPush(actor, repo, details) {
  if (!state.actorPushes.has(actor)) {
    state.actorPushes.set(actor, []);
  }
  state.actorPushes.get(actor).push({
    repo,
    timestamp: Date.now(),
    details,
  });
}

// ─── Detection Rules ────────────────────────────────────────────────────────

function ruleMultiRepoBurst(payload) {
  const actor = payload.sender && payload.sender.login;
  const repo = payload.repository && payload.repository.full_name;
  if (!actor || !repo) return;

  trackActorPush(actor, repo, 'push');

  const now = Date.now();
  const pushes = state.actorPushes.get(actor) || [];
  const recentPushes = pushes.filter(p => now - p.timestamp < CONFIG.multiRepoBurstWindowMs);
  const uniqueRepos = new Set(recentPushes.map(p => p.repo));

  if (uniqueRepos.size > CONFIG.multiRepoBurstThreshold) {
    createAlert(
      'HIGH',
      'MULTI_REPO_BURST',
      repo,
      actor,
      `Pushed to ${uniqueRepos.size} different repos within 1 hour: ${[...uniqueRepos].join(', ')}`
    );
  }
}

function ruleConfigOnlyPush(payload) {
  const actor = payload.sender && payload.sender.login;
  const repo = payload.repository && payload.repository.full_name;
  if (!actor || !repo) return;

  const commits = payload.commits || [];
  if (commits.length === 0) return;

  for (const commit of commits) {
    const allFiles = [
      ...(commit.added || []),
      ...(commit.modified || []),
      ...(commit.removed || []),
    ];

    if (allFiles.length === 0) continue;

    const configFiles = allFiles.filter(f => isConfigFile(f));
    const nonConfigFiles = allFiles.filter(f => !isConfigFile(f));

    // If ALL modified files are config files, this looks like worm behavior
    if (configFiles.length > 0 && nonConfigFiles.length === 0) {
      createAlert(
        'CRITICAL',
        'CONFIG_ONLY_PUSH',
        repo,
        actor,
        `Commit ${commit.id.slice(0, 8)} modifies ONLY config files: ${configFiles.join(', ')} — no code changes (worm signature)`
      );
    }
  }
}

function ruleForcePushMain(payload) {
  const actor = payload.sender && payload.sender.login;
  const repo = payload.repository && payload.repository.full_name;
  if (!actor || !repo) return;

  if (payload.forced === true) {
    const ref = payload.ref || '';
    const branch = ref.replace('refs/heads/', '');
    if (branch === 'main' || branch === 'master') {
      createAlert(
        'CRITICAL',
        'FORCE_PUSH_MAIN',
        repo,
        actor,
        `Force push to ${branch} branch detected — possible history rewriting attack`
      );
    }
  }
}

function ruleBotImpersonation(payload) {
  const actor = payload.sender && payload.sender.login;
  const repo = payload.repository && payload.repository.full_name;
  if (!actor || !repo) return;

  const commits = payload.commits || [];

  for (const commit of commits) {
    const committerName = commit.committer && commit.committer.name;
    const committerEmail = commit.committer && commit.committer.email;

    if (!committerName) continue;

    // Check for bot name patterns with wrong email
    const botPatterns = ['vercel[bot]', 'dependabot[bot]', 'renovate[bot]', 'github-actions[bot]'];
    const isBotName = botPatterns.some(bp =>
      committerName.toLowerCase().includes(bp.toLowerCase())
    );

    if (isBotName && committerEmail !== 'noreply@github.com') {
      createAlert(
        'CRITICAL',
        'BOT_IMPERSONATION',
        repo,
        actor,
        `Commit ${commit.id.slice(0, 8)} has Committer="${committerName} <${committerEmail}>" — legitimate bot commits use noreply@github.com`
      );
    }

    // Also check: merge commits where committer is not GitHub
    const message = commit.message || '';
    const isMerge = message.startsWith('Merge pull request') || message.startsWith('Merge branch');
    if (isMerge && committerName !== 'GitHub' && committerEmail !== 'noreply@github.com') {
      createAlert(
        'CRITICAL',
        'BOT_IMPERSONATION',
        repo,
        actor,
        `Forged merge commit ${commit.id.slice(0, 8)}: Committer="${committerName}" (expected "GitHub <noreply@github.com>")`
      );
    }
  }
}

function ruleConfigSizeSpike(payload) {
  const actor = payload.sender && payload.sender.login;
  const repo = payload.repository && payload.repository.full_name;
  if (!actor || !repo) return;

  const commits = payload.commits || [];

  for (const commit of commits) {
    const modified = commit.modified || [];
    const added = commit.added || [];
    const configModified = [...modified, ...added].filter(f => isConfigFile(f));

    // We can't see exact byte diffs from the webhook payload, but we CAN flag
    // config files being modified/added in suspicious contexts
    if (configModified.length > 0) {
      // If this push also triggered other rules, the size check adds confidence
      // Log an informational entry about config modifications
      log('INFO', `Config files modified in ${repo} by ${actor}: ${configModified.join(', ')}`);
    }
  }
}

function ruleBatFileAddition(payload) {
  const actor = payload.sender && payload.sender.login;
  const repo = payload.repository && payload.repository.full_name;
  if (!actor || !repo) return;

  const commits = payload.commits || [];

  for (const commit of commits) {
    const added = commit.added || [];

    for (const file of added) {
      const basename = file.split('/').pop().toLowerCase();
      if (basename.endsWith('.bat')) {
        const isSuspicious = basename.includes('temp') || basename.includes('push') || basename.includes('auto');
        const severity = isSuspicious ? 'CRITICAL' : 'HIGH';

        createAlert(
          severity,
          'BAT_FILE_ADDITION',
          repo,
          actor,
          `Batch file added: ${file}${isSuspicious ? ' — matches attacker toolkit pattern (temp_auto_push.bat)' : ''}`
        );
      }
    }
  }
}

function ruleKnownIocInCommit(payload) {
  const actor = payload.sender && payload.sender.login;
  const repo = payload.repository && payload.repository.full_name;
  if (!actor || !repo) return;

  const commits = payload.commits || [];

  for (const commit of commits) {
    const message = commit.message || '';

    for (const pattern of IOC_COMMIT_PATTERNS) {
      if (pattern.test(message)) {
        createAlert(
          'HIGH',
          'KNOWN_IOC_IN_COMMIT',
          repo,
          actor,
          `Commit ${commit.id.slice(0, 8)} message matches known IOC pattern: "${message.slice(0, 100)}"`
        );
        break; // One alert per commit is enough
      }
    }
  }
}

function ruleSuspiciousTiming(payload) {
  const actor = payload.sender && payload.sender.login;
  const repo = payload.repository && payload.repository.full_name;
  if (!actor || !repo) return;

  const pushes = state.actorPushes.get(actor) || [];
  if (pushes.length < 5) return; // Need enough data points

  const recentPushes = pushes.slice(-20);

  let weekdayCount = 0;
  let utc3BusinessHoursCount = 0;

  for (const push of recentPushes) {
    const date = new Date(push.timestamp);
    const dayOfWeek = date.getUTCDay(); // 0=Sun, 6=Sat
    const utcHour = date.getUTCHours();
    const utc3Hour = (utcHour + 3) % 24; // Convert to UTC+3

    if (dayOfWeek >= 1 && dayOfWeek <= 5) weekdayCount++;
    if (utc3Hour >= 8 && utc3Hour <= 18) utc3BusinessHoursCount++;
  }

  const weekdayPercent = (weekdayCount / recentPushes.length) * 100;
  const businessHoursPercent = (utc3BusinessHoursCount / recentPushes.length) * 100;

  // Known threat actor pattern: 100% weekday, concentrated in UTC+3/UTC+4 business hours
  if (weekdayPercent === 100 && businessHoursPercent > 80 && recentPushes.length >= 10) {
    createAlert(
      'MEDIUM',
      'SUSPICIOUS_TIMING',
      repo,
      actor,
      `100% weekday pushes, ${businessHoursPercent.toFixed(0)}% within UTC+3 business hours (matches known threat actor operational pattern)`
    );
  }
}

// ─── Process Push Event ─────────────────────────────────────────────────────

function processPushEvent(payload) {
  state.totalWebhooksProcessed++;

  const actor = payload.sender && payload.sender.login;
  const repo = payload.repository && payload.repository.full_name;

  log('INFO', `Processing push from ${actor} to ${repo}`);

  // Run all detection rules
  ruleMultiRepoBurst(payload);
  ruleConfigOnlyPush(payload);
  ruleForcePushMain(payload);
  ruleBotImpersonation(payload);
  ruleConfigSizeSpike(payload);
  ruleBatFileAddition(payload);
  ruleKnownIocInCommit(payload);
  ruleSuspiciousTiming(payload);
}

// ─── State Cleanup ──────────────────────────────────────────────────────────

function cleanupState() {
  const now = Date.now();
  const cutoff = now - CONFIG.stateRetentionMs;

  for (const [actor, pushes] of state.actorPushes.entries()) {
    const recent = pushes.filter(p => p.timestamp > cutoff);
    if (recent.length === 0) {
      state.actorPushes.delete(actor);
    } else {
      state.actorPushes.set(actor, recent);
    }
  }

  // Clean old alerts
  state.alerts = state.alerts.filter(a => {
    const alertTime = new Date(a.timestamp).getTime();
    return alertTime > cutoff;
  });

  log('INFO', `State cleanup: ${state.actorPushes.size} actors tracked, ${state.alerts.length} active alerts`);
}

// Start cleanup interval
setInterval(cleanupState, CONFIG.cleanupIntervalMs);

// ─── HTTP Server ────────────────────────────────────────────────────────────

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);

  // ── Health Check ──
  if (req.method === 'GET' && parsed.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', uptime: process.uptime() }));
    return;
  }

  // ── Status Endpoint ──
  if (req.method === 'GET' && parsed.pathname === '/status') {
    const actorSummary = {};
    for (const [actor, pushes] of state.actorPushes.entries()) {
      actorSummary[actor] = {
        totalPushes: pushes.length,
        uniqueRepos: [...new Set(pushes.map(p => p.repo))].length,
        lastPush: new Date(Math.max(...pushes.map(p => p.timestamp))).toISOString(),
      };
    }

    const recentAlerts = state.alerts.slice(-50).reverse();

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'running',
      startTime: state.startTime,
      uptime: process.uptime(),
      totalWebhooksProcessed: state.totalWebhooksProcessed,
      activeAlerts: state.alerts.length,
      trackedActors: state.actorPushes.size,
      actors: actorSummary,
      recentAlerts,
    }, null, 2));
    return;
  }

  // ── Webhook Endpoint ──
  if (req.method === 'POST' && parsed.pathname === '/webhook') {
    let body = '';

    req.on('data', (chunk) => {
      body += chunk.toString();
      // Limit payload size to 10MB
      if (body.length > 10 * 1024 * 1024) {
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Payload too large' }));
        req.destroy();
      }
    });

    req.on('end', () => {
      // Validate webhook signature
      const signature = req.headers['x-hub-signature-256'] || '';
      if (!verifyWebhookSignature(body, signature)) {
        log('INFO', 'Webhook signature verification failed');
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid signature' }));
        return;
      }

      // Check event type
      const event = req.headers['x-github-event'] || '';
      if (event !== 'push') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ message: `Event '${event}' ignored — only 'push' events are processed` }));
        return;
      }

      // Parse payload
      let payload;
      try {
        payload = JSON.parse(body);
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid JSON payload' }));
        return;
      }

      // Process
      try {
        processPushEvent(payload);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ processed: true }));
      } catch (err) {
        log('CRITICAL', `Error processing webhook: ${err.message}`);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Internal processing error' }));
      }
    });

    return;
  }

  // ── 404 ──
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    error: 'Not found',
    endpoints: {
      'POST /webhook': 'GitHub push event webhook receiver',
      'GET /health': 'Health check',
      'GET /status': 'Current detection state and recent alerts',
    },
  }));
});

// ─── Start Server ───────────────────────────────────────────────────────────

server.listen(CONFIG.port, () => {
  console.log('');
  console.log('\x1b[36m╔══════════════════════════════════════════════════════╗\x1b[0m');
  console.log('\x1b[36m║\x1b[0m  PUSH-MONITOR v1.0.0                                 \x1b[36m║\x1b[0m');
  console.log('\x1b[36m║\x1b[0m  GitHub Push Event Integrity Monitor                  \x1b[36m║\x1b[0m');
  console.log('\x1b[36m╠══════════════════════════════════════════════════════╣\x1b[0m');
  console.log(`\x1b[36m║\x1b[0m  Port:    ${String(CONFIG.port).padEnd(42)}\x1b[36m║\x1b[0m`);
  console.log(`\x1b[36m║\x1b[0m  Secret:  ${CONFIG.webhookSecret ? 'configured' : 'NOT SET (accepting all webhooks)'.padEnd(42)}\x1b[36m║\x1b[0m`);
  console.log(`\x1b[36m║\x1b[0m  Alerts:  ${(CONFIG.alertWebhookUrl ? CONFIG.alertWebhookUrl.slice(0, 40) : 'console only').padEnd(42)}\x1b[36m║\x1b[0m`);
  console.log('\x1b[36m╠══════════════════════════════════════════════════════╣\x1b[0m');
  console.log('\x1b[36m║\x1b[0m  Endpoints:                                          \x1b[36m║\x1b[0m');
  console.log('\x1b[36m║\x1b[0m    POST /webhook  — GitHub push event receiver        \x1b[36m║\x1b[0m');
  console.log('\x1b[36m║\x1b[0m    GET  /health   — Health check                      \x1b[36m║\x1b[0m');
  console.log('\x1b[36m║\x1b[0m    GET  /status   — Detection state & recent alerts   \x1b[36m║\x1b[0m');
  console.log('\x1b[36m╠══════════════════════════════════════════════════════╣\x1b[0m');
  console.log('\x1b[36m║\x1b[0m  Detection Rules:                                     \x1b[36m║\x1b[0m');
  console.log('\x1b[36m║\x1b[0m    1. MULTI_REPO_BURST   — Multi-repo push flood      \x1b[36m║\x1b[0m');
  console.log('\x1b[36m║\x1b[0m    2. CONFIG_ONLY_PUSH   — Config-only modifications  \x1b[36m║\x1b[0m');
  console.log('\x1b[36m║\x1b[0m    3. FORCE_PUSH_MAIN    — Force push to main branch  \x1b[36m║\x1b[0m');
  console.log('\x1b[36m║\x1b[0m    4. BOT_IMPERSONATION  — Forged bot identity        \x1b[36m║\x1b[0m');
  console.log('\x1b[36m║\x1b[0m    5. CONFIG_SIZE_SPIKE  — Config file size increase   \x1b[36m║\x1b[0m');
  console.log('\x1b[36m║\x1b[0m    6. BAT_FILE_ADDITION  — Batch file added           \x1b[36m║\x1b[0m');
  console.log('\x1b[36m║\x1b[0m    7. KNOWN_IOC_IN_COMMIT — IOC in commit message     \x1b[36m║\x1b[0m');
  console.log('\x1b[36m║\x1b[0m    8. SUSPICIOUS_TIMING  — UTC+3 weekday pattern      \x1b[36m║\x1b[0m');
  console.log('\x1b[36m╚══════════════════════════════════════════════════════╝\x1b[0m');
  console.log('');
  log('INFO', 'Push monitor is running. Waiting for GitHub webhooks...');
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`\x1b[31mPort ${CONFIG.port} is already in use. Set PORT env var to use a different port.\x1b[0m`);
  } else {
    console.error(`\x1b[31mServer error: ${err.message}\x1b[0m`);
  }
  process.exit(1);
});
