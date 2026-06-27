const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const fetch = require('node-fetch');

const app = express();
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
const port = process.env.PORT || 3000;
const dataRoot = path.join(__dirname, 'data');
const configRoot = path.join(__dirname, 'config');

// ── DEBUG: print resolved roots at startup ──────────────────────────────────
console.log('[DEBUG] __dirname  :', __dirname);
console.log('[DEBUG] dataRoot   :', dataRoot);
console.log('[DEBUG] configRoot :', configRoot);
// ────────────────────────────────────────────────────────────────────────────

// GitHub config — token lives ONLY in environment variables, never in source code
const GITHUB_TOKEN  = process.env.GITHUB_TOKEN  || '';
const GITHUB_OWNER  = process.env.GITHUB_OWNER  || 'nlabib';
const GITHUB_REPO   = process.env.GITHUB_REPO   || 'process-finder';
const GITHUB_BRANCH = process.env.GITHUB_BRANCH || 'main';
// PR target branch — defaults to feature/pre-live during pre-live phase.
// Override via GITHUB_TARGET_BRANCH env var when promoting to production.
const GITHUB_TARGET_BRANCH = process.env.GITHUB_TARGET_BRANCH || 'feature/pre-live';

// JWT secret — set via environment variable in production
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
// Token TTL: 8 hours in seconds
const TOKEN_TTL = 8 * 60 * 60;

// ─── CORS ─────────────────────────────────────────────────────────────────────
// Restrict to your IBM GHE Pages origin in production via CORS_ORIGIN env var.
// Default allows all during local development.
const corsOptions = process.env.CORS_ORIGIN
  ? { origin: process.env.CORS_ORIGIN }
  : {};
app.use(cors(corsOptions));
app.use(bodyParser.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname)));

// ─── Minimal JWT helpers (no external dependency) ────────────────────────────
// Format: base64url(header).base64url(payload).base64url(signature)

function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function signJwt(payload) {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body   = b64url(JSON.stringify(payload));
  const sig    = b64url(
    crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest()
  );
  return `${header}.${body}.${sig}`;
}

function verifyJwt(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [header, body, sig] = parts;
    const expected = b64url(
      crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest()
    );
    if (sig !== expected) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64').toString());
    if (payload.exp && Date.now() / 1000 > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

// ─── Auth middleware ──────────────────────────────────────────────────────────
// Applied to all mutating endpoints. Injects req.user from verified JWT.
// The "user" field in request bodies is IGNORED for identity — only req.user is trusted.

function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) {
    return res.status(401).json({ error: 'Authorization token required' });
  }
  const payload = verifyJwt(token);
  if (!payload) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  req.user = { email: payload.email, role: payload.role };
  next();
}

// ─── Country validation helper ────────────────────────────────────────────────
// Format-only: alphanumeric, hyphen, underscore. No hardcoded whitelist — Admin
// can create new countries dynamically via /api/admin/process-file.
function validateCountry(country) {
  return typeof country === 'string' && /^[a-z0-9_-]+$/i.test(country.trim());
}

// ─── File helpers ─────────────────────────────────────────────────────────────

function readJson(filePath, fallback = null) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    const content = raw.charCodeAt(0) === 0xFEFF ? raw.slice(1) : raw;
    return JSON.parse(content);
  } catch (err) {
    console.error('[DEBUG] readJson FAILED :', filePath);
    console.error('[DEBUG] readJson error  :', err.code || err.message);
    return fallback;
  }
}

function writeJson(filePath, data) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n', 'utf8');
}

/**
 * Appends a structured audit entry to data/ops/admin-audit.json.
 * Supports optional before/after snapshots for full change traceability.
 * Never throws — audit failure must never block the successful response.
 *
 * Entry shape: { action, by, before?, after?, ...extra, timestamp }
 */
function appendAdminAudit(entry) {
  try {
    const auditFile = path.join(dataRoot, 'ops', 'admin-audit.json');
    const log = readJson(auditFile, []);
    log.push({ ...entry, timestamp: new Date().toISOString() });
    writeJson(auditFile, log);
  } catch (err) {
    console.error('Admin audit write failed:', err.message);
  }
}

function readProcessData(country) {
  const file = path.join(dataRoot, 'processes', `${country}.json`);
  console.log('[DEBUG] readProcessData → file   :', file);
  console.log('[DEBUG] readProcessData → exists :', fs.existsSync(file));
  const json = readJson(file, null);
  if (!json) {
    console.error('[DEBUG] readProcessData → readJson returned null for', file);
    return null;
  }
  if (Array.isArray(json)) {
    return { file, data: json, meta: {} };
  }
  const meta = { ...json };
  delete meta.processes;
  return { file, data: Array.isArray(json.processes) ? json.processes : [], meta };
}

function writeProcessData(country, processes, meta = {}) {
  const file = path.join(dataRoot, 'processes', `${country}.json`);
  const payload = { ...meta, processes };
  if (!payload.lastUpdated) payload.lastUpdated = new Date().toISOString();
  writeJson(file, payload);
}

// ─── GitHub API helpers ───────────────────────────────────────────────────────

function ghHeaders() {
  return {
    'Authorization': `token ${GITHUB_TOKEN}`,
    'Accept': 'application/vnd.github.v3+json',
    'Content-Type': 'application/json'
  };
}

async function getGitHubFileContent(filePath) {
  try {
    const res = await fetch(
      `https://api.github.ibm.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${filePath}?ref=${GITHUB_BRANCH}`,
      { headers: ghHeaders() }
    );
    if (!res.ok) return null;
    return res.json();
  } catch (err) {
    console.error('GitHub fetch error:', err);
    return null;
  }
}

async function createGitHubBranch(branchName) {
  try {
    const refRes = await fetch(
      `https://api.github.ibm.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/git/refs/heads/${GITHUB_BRANCH}`,
      { headers: ghHeaders() }
    );
    if (!refRes.ok) throw new Error('Failed to get branch ref');
    const { object: { sha } } = await refRes.json();

    const createRes = await fetch(
      `https://api.github.ibm.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/git/refs`,
      { method: 'POST', headers: ghHeaders(), body: JSON.stringify({ ref: `refs/heads/${branchName}`, sha }) }
    );
    return createRes.ok;
  } catch (err) {
    console.error('GitHub branch creation error:', err);
    return false;
  }
}

async function commitToGitHub(branchName, commits) {
  try {
    for (const { filePath, content, message } of commits) {
      const fileInfo = await getGitHubFileContent(filePath);
      await fetch(
        `https://api.github.ibm.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${filePath}`,
        {
          method: 'PUT',
          headers: ghHeaders(),
          body: JSON.stringify({
            message,
            content: Buffer.from(content).toString('base64'),
            branch: branchName,
            ...(fileInfo ? { sha: fileInfo.sha } : {})
          })
        }
      );
    }
    return true;
  } catch (err) {
    console.error('GitHub commit error:', err);
    return false;
  }
}

async function createGitHubPR(branchName, title, description) {
  try {
    const res = await fetch(
      `https://api.github.ibm.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/pulls`,
      {
        method: 'POST',
        headers: ghHeaders(),
        // PRs always target GITHUB_TARGET_BRANCH (feature/pre-live in pre-live phase)
        body: JSON.stringify({ title, body: description, head: branchName, base: GITHUB_TARGET_BRANCH })
      }
    );
    if (!res.ok) {
      const errBody = await res.text().catch(() => '');
      throw new Error(`Failed to create PR (HTTP ${res.status}): ${errBody}`);
    }
    const data = await res.json();
    return { success: true, prUrl: data.html_url, prNumber: data.number };
  } catch (err) {
    console.error('[OPS PR] GitHub PR creation error:', err.message);
    return { success: false, error: err.message };
  }
}

// ─── Idempotency guard ────────────────────────────────────────────────────────
// Prevents double-processing of the same buffer entry by concurrent requests
// or a scheduler sweep running at the same time as a manual validation.
// Lives in process memory — cleared on restart, which is an acceptable trade-off
// for the single-server deployment model.
const _processingEntries = new Set();

// ─── Shared PR helper ─────────────────────────────────────────────────────────
/**
 * Creates a GitHub branch, commits the country process file, and opens a PR.
 * Designed to be called from both the manual approve-and-merge route and the
 * automatic post-validation trigger.
 *
 * @param {string}   country          — country key (e.g. 'fr')
 * @param {object[]} validatedEntries — history entries with status === 'validated'
 * @param {string}   triggeredBy      — email of the actor (user or 'system@ops')
 * @returns {{ success, prUrl, prNumber, branchName, error? }}
 *   Never throws — all failures are returned as { success: false, error }.
 */
async function _createPRForCountry(country, validatedEntries, triggeredBy) {
  // Build branch name: <country>_YYYYMMDD_HHMM
  const now = new Date();
  const pad  = n => String(n).padStart(2, '0');
  const stamp = `${now.getUTCFullYear()}${pad(now.getUTCMonth() + 1)}${pad(now.getUTCDate())}_${pad(now.getUTCHours())}${pad(now.getUTCMinutes())}`;
  const branchName = `${country}_${stamp}`;

  console.log(`[OPS PR] Creating branch "${branchName}" for country "${country}" triggered by ${triggeredBy}`);

  try {
    if (!GITHUB_TOKEN) {
      console.warn('[OPS PR] GITHUB_TOKEN not configured — PR automation skipped');
      return { success: false, error: 'GITHUB_TOKEN not configured' };
    }

    if (!await createGitHubBranch(branchName)) {
      throw new Error(`Failed to create GitHub branch "${branchName}"`);
    }

    const processesData = readProcessData(country);
    if (!processesData) throw new Error(`No process data found for country "${country}"`);

    const processJson = JSON.stringify(
      { ...processesData.meta, processes: processesData.data },
      null, 2
    );

    const committed = await commitToGitHub(branchName, [{
      filePath: `pre-live/data/processes/${country}.json`,
      content:  processJson,
      message:  `ops: ${country} process updates — ${validatedEntries.length} change(s) by ${triggeredBy}`
    }]);
    if (!committed) throw new Error('Failed to commit process file to GitHub');

    const title = `[OPS] ${country.toUpperCase()} Process Updates — ${stamp}`;
    const trigger = triggeredBy === 'system@ops' ? 'expiry' : 'manual';
    const changeLines = validatedEntries
      .map(h => `- ${h.type.toUpperCase()}: ${h.process?.issue || h.process?.id || '?'}`)
      .join('\n');
    const description =
      `[OPS AUTO PR]\n\n` +
      `Country: ${country.toUpperCase()}\n` +
      `Triggered by: ${trigger}\n` +
      `Entries: ${validatedEntries.length}\n\n` +
      `Changes:\n${changeLines}`;

    const prResult = await createGitHubPR(branchName, title, description);
    if (!prResult.success) throw new Error(prResult.error);

    console.log(`[OPS PR] PR created successfully — #${prResult.prNumber} → ${prResult.prUrl}`);
    return { success: true, prUrl: prResult.prUrl, prNumber: prResult.prNumber, branchName };

  } catch (err) {
    console.error(`[OPS PR] _createPRForCountry failed for "${country}":`, err.message);
    return { success: false, error: err.message, branchName };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// ─── Auth ─────────────────────────────────────────────────────────────────────

/**
 * POST /api/auth/session
 * Called by the frontend immediately after the external OTP service returns success.
 * Validates the email against users.json, then issues a signed JWT.
 * Body: { email }
 */
app.post('/api/auth/session', (req, res) => {
  const { email } = req.body;
  if (!email || typeof email !== 'string') {
    return res.status(400).json({ error: 'email required' });
  }
  const users = readJson(path.join(configRoot, 'users.json'), []);
  const user = users.find(u => u.email.trim().toLowerCase() === email.trim().toLowerCase());
  if (!user || !['OL', 'Manager', 'Admin'].includes(user.role)) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  const now = Math.floor(Date.now() / 1000);
  const token = signJwt({ email: user.email, role: user.role, iat: now, exp: now + TOKEN_TTL });
  res.json({ success: true, token, email: user.email, role: user.role });
});

// ─── Config (read-only, public) ───────────────────────────────────────────────

app.get('/api/config/countries', (req, res) => {
  res.json(readJson(path.join(configRoot, 'countries.json'), []));
});

app.get('/api/config/users', (req, res) => {
  // Return users without any sensitive fields (none currently, but kept explicit)
  const users = readJson(path.join(configRoot, 'users.json'), []);
  res.json(users);
});

// ─── Processes (read-only, public) ───────────────────────────────────────────

app.get('/api/processes/:country', (req, res) => {
  const country = req.params.country.toLowerCase();
  if (!validateCountry(country)) {
    return res.status(400).json({ error: 'Invalid country' });
  }
  const filePath = path.join(dataRoot, 'processes', `${country}.json`);
  console.log('[DEBUG] GET /api/processes/:country');
  console.log('[DEBUG]   country  :', country);
  console.log('[DEBUG]   filePath :', filePath);
  console.log('[DEBUG]   exists   :', fs.existsSync(filePath));
  const json = readJson(filePath, null);
  if (!json) {
    console.error('[DEBUG]   result: 404 — readJson returned null');
    return res.status(404).json({ error: 'Country not found' });
  }
  res.json(json);
});

// ─── OPS reads (public) ───────────────────────────────────────────────────────

app.get('/api/ops/buffer', (req, res) => {
  res.json(readJson(path.join(dataRoot, 'ops', 'buffer.json'), {}));
});

app.get('/api/ops/history', (req, res) => {
  res.json(readJson(path.join(dataRoot, 'ops', 'history.json'), {}));
});

/**
 * POST /api/ops/history/append
 * Appends a pre-formed entry (e.g. a client-cancelled buffer item) to history.
 * Body: { country, entry }
 * Used as a fallback when POST /api/ops/cancel is unavailable (old server version).
 */
app.post('/api/ops/history/append', requireAuth, (req, res) => {
  const { country, entry } = req.body;
  if (!country || !entry || typeof entry !== 'object') {
    return res.status(400).json({ error: 'country and entry are required' });
  }
  if (!validateCountry(country)) {
    return res.status(400).json({ error: 'Invalid country' });
  }
  const historyFile = path.join(dataRoot, 'ops', 'history.json');
  const history = readJson(historyFile, {});
  if (!history[country]) history[country] = [];
  history[country].push(entry);
  writeJson(historyFile, history);
  res.json({ success: true });
});

app.get('/api/ops/settings', (req, res) => {
  res.json(readJson(path.join(dataRoot, 'ops', 'settings.json'), {}));
});

// ─── OPS writes (authenticated) ───────────────────────────────────────────────

/**
 * POST /api/ops/buffer
 * Adds a new pending entry for req.user.email (identity from JWT, not body).
 */
/**
 * Validates a single process entry object.
 * Returns null if valid, or an error string describing the first violation.
 *
 * Required fields: category (string), issue (string), process (string)
 * Optional fields: machineType (string), id (string matching id pattern)
 */
function validateProcessEntry(p) {
  if (!p || typeof p !== 'object') return 'process must be an object';
  if (!p.category || typeof p.category !== 'string' || !p.category.trim()) {
    return 'process.category is required';
  }
  if (!p.issue || typeof p.issue !== 'string' || !p.issue.trim()) {
    return 'process.issue is required';
  }
  if (!p.process || typeof p.process !== 'string' || !p.process.trim()) {
    return 'process.process (description) is required';
  }
  if (p.machineType !== undefined && typeof p.machineType !== 'string') {
    return 'process.machineType must be a string';
  }
  if (p.id !== undefined && typeof p.id !== 'string') {
    return 'process.id must be a string';
  }
  return null;
}

app.post('/api/ops/buffer', requireAuth, (req, res) => {
  const { country, type, process, holdHours = 4 } = req.body;
  const user = req.user.email; // trusted identity from JWT

  if (!country || !type || !process) {
    return res.status(400).json({ error: 'country, type, and process are required' });
  }
  if (!validateCountry(country)) {
    return res.status(400).json({ error: 'Invalid country' });
  }
  if (!['create', 'update', 'delete'].includes(type)) {
    return res.status(400).json({ error: 'type must be create, update, or delete' });
  }
  // Validate process entry schema for create and update (delete only needs an id/issue to identify)
  if (type !== 'delete') {
    const schemaError = validateProcessEntry(process);
    if (schemaError) return res.status(400).json({ error: schemaError });
  } else {
    // delete requires at minimum an id or issue to locate the record
    if (!process.id && !process.issue) {
      return res.status(400).json({ error: 'process.id or process.issue is required for delete' });
    }
  }

  const file = path.join(dataRoot, 'ops', 'buffer.json');
  const buffer = readJson(file, {});
  if (!buffer[country]) buffer[country] = {};
  if (!buffer[country][user]) buffer[country][user] = [];

  const entry = {
    id: process.id || `${country}_${Date.now()}`,
    type,
    process,
    user,
    createdAt: new Date().toISOString(),
    holdHours,
    status: 'pending'
  };

  buffer[country][user].push(entry);
  writeJson(file, buffer);
  res.json({ success: true, entry });
});

/**
 * PUT /api/ops/buffer
 * Replaces the full buffer (used by legacy callers; prefer POST /api/ops/cancel).
 */
app.put('/api/ops/buffer', requireAuth, (req, res) => {
  const { buffer: newBuffer } = req.body;
  if (!newBuffer || typeof newBuffer !== 'object') {
    return res.status(400).json({ error: 'buffer object required' });
  }
  writeJson(path.join(dataRoot, 'ops', 'buffer.json'), newBuffer);
  res.json({ success: true, buffer: newBuffer });
});

/**
 * POST /api/ops/cancel
 * Removes a single buffer entry and archives it to history with status='cancelled'.
 * Body: { country, user, index }
 */
app.post('/api/ops/cancel', requireAuth, (req, res) => {
  const { country, user: targetUser, index } = req.body;
  const canceller = req.user.email;

  if (!country || !targetUser || typeof index !== 'number') {
    return res.status(400).json({ error: 'country, user, and index are required' });
  }
  if (!validateCountry(country)) {
    return res.status(400).json({ error: 'Invalid country' });
  }

  const bufferFile  = path.join(dataRoot, 'ops', 'buffer.json');
  const historyFile = path.join(dataRoot, 'ops', 'history.json');
  const buffer  = readJson(bufferFile, {});
  const history = readJson(historyFile, {});

  const entries = (buffer[country] && buffer[country][targetUser]) || [];
  if (!entries[index]) {
    return res.status(404).json({ error: 'Buffer entry not found' });
  }

  // Splice out and mark cancelled
  const entry = entries.splice(index, 1)[0];
  entry.status      = 'cancelled';
  entry.cancelledAt = new Date().toISOString();
  entry.cancelledBy = canceller;

  // Archive to history so it is visible in History and Logs tabs
  if (!history[country]) history[country] = [];
  history[country].push(entry);

  writeJson(bufferFile, buffer);
  writeJson(historyFile, history);

  appendAdminAudit({
    action:  'buffer-cancelled',
    by:      canceller,
    country,
    entryId: entry.id,
    type:    entry.type,
    process: entry.process
  });

  res.json({ success: true, entry });
});

/**
 * POST /api/ops/validate
 * Applies a buffer entry to the process file and moves it to history.
 * Body: { country, user (ignored — uses JWT), index }
 */
app.post('/api/ops/validate', requireAuth, (req, res) => {
  const { country, index } = req.body;
  const validator = req.user.email; // use JWT identity as the validator

  if (!country || typeof index !== 'number') {
    return res.status(400).json({ error: 'country and index are required' });
  }
  if (!validateCountry(country)) {
    return res.status(400).json({ error: 'Invalid country' });
  }
  // Only Manager and Admin may validate
  if (!['Manager', 'Admin'].includes(req.user.role)) {
    return res.status(403).json({ error: 'Only Manager or Admin can validate entries' });
  }

  const bufferFile  = path.join(dataRoot, 'ops', 'buffer.json');
  const historyFile = path.join(dataRoot, 'ops', 'history.json');
  const buffer  = readJson(bufferFile, {});
  const history = readJson(historyFile, {});

  // The body must specify which user's queue to validate from
  const targetUser = req.body.user;
  if (!targetUser) return res.status(400).json({ error: 'user field required to identify buffer queue' });

  const entries = (buffer[country] && buffer[country][targetUser]) || [];

  // Peek at the entry before splicing — needed for idempotency check
  const entryPeek = entries[index];
  if (!entryPeek) {
    return res.status(404).json({ error: 'Buffer entry not found' });
  }

  // ── Idempotency guard ──────────────────────────────────────────────────────
  if (_processingEntries.has(entryPeek.id)) {
    console.warn(`[OPS validate] Entry "${entryPeek.id}" is already being processed — skipping duplicate`);
    return res.status(409).json({ error: 'Entry is already being processed' });
  }
  _processingEntries.add(entryPeek.id);

  // Splice now that we hold the lock
  const entry = entries.splice(index, 1)[0];

  try {
    const processesData = readProcessData(country);
    if (!processesData) {
      // Put the entry back before returning
      entries.splice(index, 0, entry);
      return res.status(404).json({ error: 'Process file not found for country' });
    }

    const arr = processesData.data;
    const targetIdx = arr.findIndex(p => p.id === entry.process.id || p.issue === entry.process.issue);

    // Canonical snapshot fields written to every history entry:
    //   before — full process object that existed BEFORE this action  (null for create)
    //   after  — full process object that exists  AFTER  this action  (null for delete)
    // previousProcess is kept as a legacy alias so older history entries still
    // display correctly in the UI diff block.
    let before = null;
    let after  = null;

    if (entry.type === 'create') {
      after = { ...entry.process };
      if (targetIdx === -1) arr.push(entry.process);
    } else if (entry.type === 'update') {
      if (targetIdx !== -1) {
        before = { ...arr[targetIdx] };
        arr[targetIdx] = entry.process;
      } else {
        arr.push(entry.process);
      }
      after = { ...entry.process };
    } else if (entry.type === 'delete') {
      if (targetIdx !== -1) {
        before = { ...arr[targetIdx] };
        arr.splice(targetIdx, 1);
      }
    }

    writeProcessData(country, arr, processesData.meta);

    const now             = new Date().toISOString();
    entry.validatedAt     = now;
    entry.validatedBy     = validator;
    // Status is now 'validated' (not 'pending') — unambiguous post-validation state.
    // 'pending' is reserved for buffer entries only.
    // TODO: remove legacy "pending" support in filters after data migration.
    entry.status          = 'validated';
    entry.before          = before;
    entry.after           = after;
    // Legacy alias — kept so history entries already in the JSON file continue
    // to show their diff block in the UI without a data migration.
    entry.previousProcess = before;

    if (!history[country]) history[country] = [];
    history[country].push(entry);

    writeJson(bufferFile, buffer);
    writeJson(historyFile, history);

    appendAdminAudit({
      action:  'buffer-validated',
      by:      validator,
      country,
      entryId: entry.id,
      type:    entry.type,
      before:  entry.before,
      after:   entry.after
    });

    console.log(`[OPS validate] Entry "${entry.id}" validated by ${validator} for country "${country}"`);

    // ── Auto-create PR after validation (STEP 3) ──────────────────────────
    // Collect ALL validated entries for this country to batch into one PR.
    // TODO: remove legacy "pending" filter after data migration.
    const validatedEntries = (history[country] || []).filter(
      h => h.status === 'validated' || h.status === 'pending'
    );

    // PR is fired asynchronously so it never blocks or fails the validate response.
    // Use a self-invoking async IIFE (not setImmediate) for clarity and testability.
    (async () => {
      try {
        console.log(`[OPS PR] Creating PR for country: ${country.toUpperCase()} (${validatedEntries.length} entries)`);
        const prResult = await _createPRForCountry(country, validatedEntries, validator);
        if (prResult.success) {
          console.log(`[OPS PR] Success: ${prResult.prUrl}`);
          const approvedAt = new Date().toISOString();
          // Re-read history to avoid overwriting concurrent writes
          const histFile = path.join(dataRoot, 'ops', 'history.json');
          const hist     = readJson(histFile, {});
          (hist[country] || []).forEach(h => {
            // TODO: remove legacy "pending" check after data migration.
            if (h.status === 'validated' || h.status === 'pending') {
              h.status     = 'approved';
              h.approvedAt = approvedAt;
              h.approvedBy = validator;
              h.prUrl      = prResult.prUrl;
              h.prNumber   = prResult.prNumber;
              h.branchName = prResult.branchName;
            }
          });
          writeJson(histFile, hist);
          appendAdminAudit({
            action:     'pr-auto-created',
            by:         validator,
            country,
            branchName: prResult.branchName,
            prNumber:   prResult.prNumber,
            prUrl:      prResult.prUrl,
            entryCount: validatedEntries.length
          });
        } else {
          console.error(`[OPS PR] Failed: ${prResult.error} — entries remain as "validated" for manual retry via approve-and-merge`);
          appendAdminAudit({
            action:     'pr-auto-failed',
            by:         validator,
            country,
            error:      prResult.error,
            entryCount: validatedEntries.length
          });
        }
      } catch (prErr) {
        console.error(`[OPS PR] Unexpected error for "${country}":`, prErr.message);
      }
    })();

    res.json({ success: true, entry });

  } finally {
    _processingEntries.delete(entry.id);
  }
});

/**
 * POST /api/ops/rollback
 * Restores the previous state from a history entry.
 * Does NOT push back to the buffer — it is a clean undo of the process data only.
 */
app.post('/api/ops/rollback', requireAuth, (req, res) => {
  const { country, historyIndex } = req.body;

  if (!country || typeof historyIndex !== 'number') {
    return res.status(400).json({ error: 'country and historyIndex are required' });
  }
  if (!validateCountry(country)) {
    return res.status(400).json({ error: 'Invalid country' });
  }
  if (req.user.role !== 'Admin') {
    return res.status(403).json({ error: 'Only Admin can rollback entries' });
  }

  const historyFile = path.join(dataRoot, 'ops', 'history.json');
  const history = readJson(historyFile, {});

  if (!history[country] || !history[country][historyIndex]) {
    return res.status(404).json({ error: 'History item not found' });
  }

  // ── Update the original entry in-place — do NOT remove it from history.
  // The original action record (create/update/delete) is preserved for audit
  // purposes; we only stamp it with rolled-back metadata.
  const item = history[country][historyIndex];
  const now  = new Date().toISOString();
  item.rolledBackAt = now;
  item.rolledBackBy = req.user.email;
  item.status       = 'rolled_back';

  const processesData = readProcessData(country);
  if (processesData) {
    const arr = processesData.data;

    // Resolve the canonical before/after snapshots.
    // New entries use item.before / item.after; legacy entries fall back to
    // item.previousProcess (stored before the before/after fields were added).
    const beforeSnap = item.before ?? item.previousProcess ?? null;
    const afterSnap  = item.after  ?? item.process         ?? null;

    if (item.type === 'create') {
      // Undo a create → remove the process that was added.
      const removeIdx = arr.findIndex(
        p => p.id === afterSnap?.id || p.issue === afterSnap?.issue
      );
      if (removeIdx !== -1) arr.splice(removeIdx, 1);

    } else if (item.type === 'update') {
      // Undo an update → restore beforeSnap (the previous version).
      if (beforeSnap) {
        const restoreIdx = arr.findIndex(
          p => p.id === afterSnap?.id || p.issue === afterSnap?.issue
        );
        if (restoreIdx !== -1) arr[restoreIdx] = beforeSnap;
        else arr.push(beforeSnap);
      }

    } else if (item.type === 'delete') {
      // Undo a delete → re-insert beforeSnap (the deleted process).
      if (beforeSnap) {
        const alreadyExists = arr.some(
          p => p.id === beforeSnap.id || p.issue === beforeSnap.issue
        );
        if (!alreadyExists) arr.push(beforeSnap);
      }
    }

    writeProcessData(country, arr, processesData.meta);
  }

  // ── Append a new log entry for the rollback action itself.
  // This is the record that appears in Logs as action='rollback' / status='approved'.
  const rollbackLogEntry = {
    id:          `rollback_${item.id || historyIndex}_${Date.now()}`,
    type:        'rollback',
    status:      'approved',
    user:        req.user.email,
    validatedAt: now,
    validatedBy: req.user.email,
    country,
    referenceId: item.id || null,
    process:     item.process,   // the process that was affected
    before:      item.after  ?? item.process ?? null,
    after:       item.before ?? item.previousProcess ?? null,
  };
  history[country].push(rollbackLogEntry);

  writeJson(historyFile, history);

  appendAdminAudit({
    action:      'rollback-executed',
    by:          req.user.email,
    country,
    historyIndex,
    entryId:     item.id,
    type:        item.type,
    before:      item.after  ?? item.process ?? null,
    after:       item.before ?? item.previousProcess ?? null
  });

  res.json({ success: true, item });
});

/**
 * POST /api/ops/settings
 *
 * Optional body field `previousCategories`: array of category entries
 * (strings or { name } objects) from *before* this save. When supplied the
 * server diffs old vs new names and rewrites every matching process record
 * across all country files so that filter buttons on the main page stay in
 * sync without any browser reload.
 */
app.post('/api/ops/settings', requireAuth, (req, res) => {
  const { settings, previousCategories } = req.body;

  console.log('[settings] SAVE CALLED by', req.user?.email);
  console.log('[settings] previousCategories:', JSON.stringify(previousCategories));
  console.log('[settings] new categories:', JSON.stringify(settings?.categories));
  if (!previousCategories) console.log('[settings] WARNING: no previousCategories received');

  if (!settings || typeof settings !== 'object') {
    return res.status(400).json({ error: 'settings object required' });
  }
  if (!['Manager', 'Admin'].includes(req.user.role)) {
    return res.status(403).json({ error: 'Only Manager or Admin can modify settings' });
  }

  // ── Category rename propagation ──────────────────────────────────────────
  // Extract a plain name string from a category entry (string or object).
  const catName = c => (typeof c === 'string' ? c : c?.name || '').trim();

  // Build { normalised-oldName → newName } using name-based matching:
  // pair each previous entry to the new entry that shares its original name,
  // then record a rename when that name has changed.
  // Using normalised keys (trim + toLowerCase) avoids space/case mismatches.
  const renames = {}; // key: oldName.trim().toLowerCase() → value: newName (canonical)
  if (Array.isArray(previousCategories) && Array.isArray(settings.categories)) {
    const newCats = settings.categories;
    // Build a lookup of new names by their normalised form for O(1) detection
    // of which old names were simply preserved vs which were changed.
    const newNamesNorm = new Set(newCats.map(c => catName(c).toLowerCase()));

    previousCategories.forEach(prev => {
      const oldName     = catName(prev);
      const oldNameNorm = oldName.toLowerCase();
      if (!oldName) return;

      // If the exact normalised name still exists in the new list, no rename.
      if (newNamesNorm.has(oldNameNorm)) return;

      // Old name is gone — find the new entry at the same original position
      // as a best-effort pairing (works for simple renames; insertions/deletions
      // are handled by the newNamesNorm guard above).
      const i       = previousCategories.indexOf(prev);
      const curr    = newCats[i];
      const newName = curr !== undefined ? catName(curr) : null;

      if (newName && newName.toLowerCase() !== oldNameNorm) {
        renames[oldNameNorm] = newName;
        console.log(`[settings] category rename detected: "${oldName}" → "${newName}"`);
      }
    });
  }

  // Apply renames to every country process file that has affected records.
  const renameCount = Object.keys(renames).length;
  if (renameCount > 0) {
    const processDir = path.join(dataRoot, 'processes');
    let files;
    try {
      files = fs.readdirSync(processDir).filter(f => f.endsWith('.json'));
    } catch (err) {
      console.error('[settings] cannot read processes dir:', err.message);
      files = [];
    }

    files.forEach(file => {
      const filePath = path.join(processDir, file);
      try {
        const parsed = readJson(filePath, null);
        if (!parsed) {
          console.error('[settings] skipping unreadable file:', file);
          return;
        }

        const isLegacyArray = Array.isArray(parsed);
        const processes = isLegacyArray ? parsed
                        : Array.isArray(parsed.processes) ? parsed.processes
                        : null;
        if (!processes) return;

        let dirty = false;
        processes.forEach(p => {
          if (!p.category) return;
          const norm = p.category.trim().toLowerCase();
          if (renames[norm]) {
            console.log(`[settings] updated category "${p.category}" → "${renames[norm]}" in ${file}`);
            p.category = renames[norm];
            dirty = true;
          }
        });

        if (dirty) {
          const payload = isLegacyArray
            ? processes
            : { ...parsed, processes, lastUpdated: new Date().toISOString() };
          fs.writeFileSync(filePath, JSON.stringify(payload, null, 2) + '\n', 'utf8');
          console.log(`[settings] wrote updated process file: ${file}`);
        }
      } catch (err) {
        console.error(`[settings] failed to update process file ${file}:`, err.message);
      }
    });
  }
  // ────────────────────────────────────────────────────────────────────────

  writeJson(path.join(dataRoot, 'ops', 'settings.json'), settings);
  res.json({ success: true, settings, renames });
});

/**
 * POST /api/ops/approve-and-merge
 * Manual Admin fallback: creates a PR for all validated-but-not-yet-approved
 * entries for a country. Normally the auto-PR path in /api/ops/validate handles
 * this; this endpoint remains as a manual retry mechanism.
 */
app.post('/api/ops/approve-and-merge', requireAuth, async (req, res) => {
  const { country } = req.body;
  const approver = req.user.email;

  if (!country) {
    return res.status(400).json({ error: 'country is required' });
  }
  if (!validateCountry(country)) {
    return res.status(400).json({ error: 'Invalid country' });
  }
  if (req.user.role !== 'Admin') {
    return res.status(403).json({ error: 'Only Admin can approve and merge' });
  }
  if (!GITHUB_TOKEN) {
    return res.status(500).json({ error: 'GitHub token not configured on server' });
  }

  try {
    const historyFile    = path.join(dataRoot, 'ops', 'history.json');
    const history        = readJson(historyFile, {});
    const countryHistory = history[country] || [];

    // Filter on 'validated' (new) and legacy 'pending' (entries written before this deploy).
    const validatedEntries = countryHistory.filter(
      h => h.status === 'validated' || h.status === 'pending'
    );
    if (!validatedEntries.length) {
      return res.status(400).json({ error: 'No validated changes to approve for this country' });
    }

    console.log(`[OPS approve-and-merge] Manual PR by ${approver} for "${country}" — ${validatedEntries.length} entries`);

    const prResult = await _createPRForCountry(country, validatedEntries, approver);
    if (!prResult.success) throw new Error(prResult.error);

    const approvedAt = new Date().toISOString();
    validatedEntries.forEach(h => {
      h.status     = 'approved';
      h.approvedAt = approvedAt;
      h.approvedBy = approver;
      h.prUrl      = prResult.prUrl;
      h.prNumber   = prResult.prNumber;
      h.branchName = prResult.branchName;
    });

    writeJson(historyFile, history);

    appendAdminAudit({
      action:     'pr-approved',
      by:         approver,
      country,
      branchName: prResult.branchName,
      prNumber:   prResult.prNumber,
      prUrl:      prResult.prUrl,
      entryCount: validatedEntries.length
    });

    res.json({
      success:    true,
      message:    'PR created successfully',
      prUrl:      prResult.prUrl,
      prNumber:   prResult.prNumber,
      branchName: prResult.branchName
    });
  } catch (err) {
    console.error('[OPS approve-and-merge] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─── Admin endpoints ──────────────────────────────────────────────────────────

/**
 * POST /api/admin/users
 * Replaces config/users.json with the provided users array.
 * Body: { users: [ { email, name, role, countries } ] }
 * Requires Admin role.
 *
 * Role-country consistency rules:
 *   - OL      → countries must be a non-empty array
 *   - Manager → countries must be a non-empty array
 *   - Admin   → countries may be ["all"] or omitted (defaulted to ["all"])
 */
/**
 * Validate and normalise a single user object.
 * Returns { ok: true, user } on success or { ok: false, error } on failure.
 */
function validateUserEntry(u) {
  const VALID_ROLES = ['Admin', 'Manager', 'OL'];
  if (!u.email || typeof u.email !== 'string' || !u.email.includes('@')) {
    return { ok: false, error: 'Invalid or missing email for a user entry' };
  }
  if (!VALID_ROLES.includes(u.role)) {
    return { ok: false, error: `Invalid role "${u.role}" for user ${u.email}` };
  }
  if (u.role === 'Admin') {
    return { ok: true, user: { ...u, countries: ['all'] } };
  }
  if (!Array.isArray(u.countries) || u.countries.length === 0) {
    return { ok: false, error: `User ${u.email} (${u.role}) must have at least one country assigned` };
  }
  for (const c of u.countries) {
    if (!validateCountry(c)) {
      return { ok: false, error: `Invalid country key "${c}" for user ${u.email}` };
    }
  }
  return { ok: true, user: { ...u } };
}

/**
 * POST /api/admin/users
 * PATCH-like merge: applies an array of change operations to config/users.json.
 * Body: { users: [ { op: 'add'|'update'|'remove', user: {...} } ] }
 *
 *   op='add'    → add user; reject if email already exists
 *   op='update' → replace user with matching email; reject if not found
 *   op='remove' → delete user by email; reject if not found or self-delete
 *
 * Requires Admin role.
 */
app.post('/api/admin/users', requireAuth, (req, res) => {
  if (req.user.role !== 'Admin') {
    return res.status(403).json({ error: 'Only Admin can manage users' });
  }
  const { users } = req.body;
  if (!Array.isArray(users) || users.length === 0) {
    return res.status(400).json({ error: 'users array of operations required' });
  }

  const usersFile   = path.join(configRoot, 'users.json');
  const before      = readJson(usersFile, []);
  const working     = before.map(u => ({ ...u })); // mutable copy
  const seenEmails  = new Set(working.map(u => u.email.toLowerCase()));
  // Track emails touched within THIS request to catch duplicates inside a single batch
  const batchSeen   = new Set();

  for (const op of users) {
    const opType = op.op;
    const u      = op.user;

    if (!['add', 'update', 'remove'].includes(opType)) {
      return res.status(400).json({ error: `Invalid op "${opType}" — must be add, update, or remove` });
    }
    if (!u || !u.email || typeof u.email !== 'string') {
      return res.status(400).json({ error: 'Each operation must include a user object with email' });
    }

    const emailKey = u.email.toLowerCase();

    // Reject duplicate emails within the same request batch
    if (batchSeen.has(emailKey)) {
      return res.status(400).json({ error: `Duplicate email "${u.email}" in request — each email may appear only once per batch` });
    }
    batchSeen.add(emailKey);

    const existIdx = working.findIndex(x => x.email.toLowerCase() === emailKey);

    if (opType === 'add') {
      if (existIdx !== -1) {
        return res.status(409).json({ error: `User ${u.email} already exists — use op="update" to modify` });
      }
      const result = validateUserEntry(u);
      if (!result.ok) return res.status(400).json({ error: result.error });
      working.push(result.user);
      seenEmails.add(emailKey);

    } else if (opType === 'update') {
      if (existIdx === -1) {
        return res.status(404).json({ error: `User ${u.email} not found — use op="add" to create` });
      }
      const result = validateUserEntry(u);
      if (!result.ok) return res.status(400).json({ error: result.error });
      working[existIdx] = result.user;

    } else if (opType === 'remove') {
      if (existIdx === -1) {
        return res.status(404).json({ error: `User ${u.email} not found` });
      }
      if (emailKey === req.user.email.toLowerCase()) {
        return res.status(400).json({ error: 'You cannot remove your own account' });
      }
      working.splice(existIdx, 1);
      seenEmails.delete(emailKey);
    }
  }

  writeJson(usersFile, working);

  appendAdminAudit({
    action:  'users-updated',
    by:      req.user.email,
    before,
    after:   working,
    opCount: users.length
  });

  res.json({ success: true, count: working.length });
});

/**
 * POST /api/admin/process-file
 * Creates an empty process JSON file for a new country and registers it in
 * config/countries.json so it becomes visible to all users immediately.
 *
 * Body: { country: string, name?: string, code?: string, flag?: string }
 * Requires Admin role.
 *
 * Process file schema (strict):  { lastUpdated, country, processes: [] }
 * countries.json entry schema:   { key, name, code, flag }
 */
app.post('/api/admin/process-file', requireAuth, (req, res) => {
  if (req.user.role !== 'Admin') {
    return res.status(403).json({ error: 'Only Admin can create process files' });
  }
  const rawCountry = req.body.country;
  if (!rawCountry || typeof rawCountry !== 'string') {
    return res.status(400).json({ error: 'country is required' });
  }
  const country = rawCountry.trim().toLowerCase();
  if (!validateCountry(country)) {
    return res.status(400).json({ error: 'Invalid country key — use lowercase letters, digits, hyphen or underscore only' });
  }

  // ── 1. Create process file (idempotent) ──────────────────────────────────
  const filePath = path.join(dataRoot, 'processes', `${country}.json`);
  const fileAlreadyExisted = fs.existsSync(filePath);
  if (!fileAlreadyExisted) {
    const envelope = {
      lastUpdated: new Date().toISOString(),
      country,
      processes: []
    };
    writeJson(filePath, envelope);
  }

  // ── 2. Register in countries.json (idempotent) ───────────────────────────
  const countriesFile = path.join(configRoot, 'countries.json');
  const countries = readJson(countriesFile, []);
  const alreadyRegistered = countries.some(c => c.key === country);
  let countryRegistered = false;

  if (!alreadyRegistered) {
    const { name, code, flag } = req.body;
    const codeUpper = (code || country).toUpperCase();
    const entry = {
      key:  country,
      name: name || country,
      code: codeUpper,
      flag: flag || `https://flagcdn.com/w40/${codeUpper.toLowerCase()}.png`
    };
    countries.push(entry);
    writeJson(countriesFile, countries);
    countryRegistered = true;
  }

  appendAdminAudit({
    action:            'process-file-created',
    by:                req.user.email,
    country,
    fileCreated:       !fileAlreadyExisted,
    countryRegistered
  });

  res.json({
    success:           true,
    created:           !fileAlreadyExisted,
    countryRegistered,
    filePath:          `data/processes/${country}.json`
  });
});

/**
 * POST /api/admin/remove-country
 * Safe country removal with mandatory data archival.
 *
 * Steps:
 *   1. Validate country key and Admin role.
 *   2. Collect counts of processes, history entries, and log entries.
 *   3. Archive processes → data/ops/archive/country_archive.json
 *      Archive history  → data/ops/archive/history_archive.json
 *      Archive logs     → data/ops/archive/logs_archive.json
 *   4. Remove the country's process file (rename to .archived).
 *   5. Remove from config/countries.json.
 *   6. Remove from data/ops/settings.json countries array.
 *   7. Clear the country's buffer entries.
 *   8. Audit log the action.
 *
 * Body: { country: string }
 * Returns: { success, processCount, historyCount, logsCount }
 */
app.post('/api/admin/remove-country', requireAuth, (req, res) => {
  if (req.user.role !== 'Admin') {
    return res.status(403).json({ error: 'Only Admin can remove countries' });
  }

  const rawCountry = req.body.country;
  if (!rawCountry || typeof rawCountry !== 'string') {
    return res.status(400).json({ error: 'country is required' });
  }
  const country = rawCountry.trim().toLowerCase();
  if (!validateCountry(country)) {
    return res.status(400).json({ error: 'Invalid country key' });
  }

  const archivedAt = new Date().toISOString();

  // ── 1. Read all data sources ─────────────────────────────────────────────
  const processFile   = path.join(dataRoot, 'processes', `${country}.json`);
  const historyFile   = path.join(dataRoot, 'ops', 'history.json');
  const bufferFile    = path.join(dataRoot, 'ops', 'buffer.json');
  const settingsFile  = path.join(dataRoot, 'ops', 'settings.json');
  const countriesFile = path.join(configRoot, 'countries.json');

  const processData  = readJson(processFile, null);
  const processes    = processData
    ? (Array.isArray(processData) ? processData : (processData.processes || []))
    : [];

  const history      = readJson(historyFile, {});
  const historyEntries = history[country] || [];

  const logsEntries  = historyEntries.filter(
    e => e.status === 'approved' || e.status === 'rolled_back' || e.rolledBackAt
  );

  // ── 2. Archive processes ──────────────────────────────────────────────────
  const countryArchiveFile = path.join(dataRoot, 'ops', 'archive', 'country_archive.json');
  const countryArchive = readJson(countryArchiveFile, []);
  countryArchive.push({
    country,
    _archivedAt:  archivedAt,
    _archivedBy:  req.user.email,
    processCount: processes.length,
    processes,
    meta: processData && !Array.isArray(processData)
      ? Object.fromEntries(Object.entries(processData).filter(([k]) => k !== 'processes'))
      : {}
  });
  writeJson(countryArchiveFile, countryArchive);

  // ── 3. Archive history entries ────────────────────────────────────────────
  const histArchiveFile = path.join(dataRoot, 'ops', 'archive', 'history_archive.json');
  const histArchive = readJson(histArchiveFile, []);
  historyEntries.forEach(e => {
    histArchive.push({ ...e, _archivedAt: archivedAt, _archivedCountry: country });
  });
  writeJson(histArchiveFile, histArchive);

  // ── 4. Archive logs (approved/rolled-back subset) ─────────────────────────
  const logsArchiveFile = path.join(dataRoot, 'ops', 'archive', 'logs_archive.json');
  const logsArchive = readJson(logsArchiveFile, []);
  logsEntries.forEach(e => {
    logsArchive.push({ ...e, _archivedAt: archivedAt, _archivedCountry: country });
  });
  writeJson(logsArchiveFile, logsArchive);

  // ── 5. Remove from history.json ───────────────────────────────────────────
  delete history[country];
  writeJson(historyFile, history);

  // ── 6. Clear buffer entries for this country ──────────────────────────────
  const buffer = readJson(bufferFile, {});
  delete buffer[country];
  writeJson(bufferFile, buffer);

  // ── 7. Rename process file to .archived (preserves data on disk) ─────────
  if (fs.existsSync(processFile)) {
    try {
      fs.renameSync(processFile, processFile.replace('.json', '.archived.json'));
    } catch (err) {
      console.error('[remove-country] could not rename process file:', err.message);
    }
  }

  // ── 8. Remove from config/countries.json ─────────────────────────────────
  const countries = readJson(countriesFile, []);
  const updatedCountries = countries.filter(c => c.key !== country);
  writeJson(countriesFile, updatedCountries);

  // ── 9. Remove from settings.json countries array ──────────────────────────
  const settings = readJson(settingsFile, {});
  if (Array.isArray(settings.countries)) {
    settings.countries = settings.countries.filter(c => c.key !== country);
    writeJson(settingsFile, settings);
  }

  // ── 10. Audit ─────────────────────────────────────────────────────────────
  appendAdminAudit({
    action:       'country-removed',
    by:           req.user.email,
    country,
    processCount: processes.length,
    historyCount: historyEntries.length,
    logsCount:    logsEntries.length,
    archivedAt
  });

  res.json({
    success:      true,
    processCount: processes.length,
    historyCount: historyEntries.length,
    logsCount:    logsEntries.length
  });
});

// ─── Archive endpoints (Admin only) ──────────────────────────────────────────

/**
 * POST /api/ops/archive/history
 * Moves all history entries to data/ops/archive/history_archive.json (append),
 * then resets history.json to empty country arrays.
 * Admin only.
 */
app.post('/api/ops/archive/history', requireAuth, (req, res) => {
  if (req.user.role !== 'Admin') {
    return res.status(403).json({ error: 'Admin only' });
  }

  const historyFile  = path.join(dataRoot, 'ops', 'history.json');
  const archiveFile  = path.join(dataRoot, 'ops', 'archive', 'history_archive.json');
  const history      = readJson(historyFile, {});
  const archive      = readJson(archiveFile, []);

  // Count total entries being archived
  let archived = 0;
  const archivedAt = new Date().toISOString();

  Object.entries(history).forEach(([ck, entries]) => {
    (entries || []).forEach(e => {
      archive.push({ ...e, _archivedAt: archivedAt, _archivedCountry: ck });
      archived++;
    });
    history[ck] = [];  // clear per-country array
  });

  writeJson(archiveFile, archive);
  writeJson(historyFile, history);

  appendAdminAudit({ action: 'history-archived', by: req.user.email, archived });

  res.json({ success: true, archived });
});

/**
 * POST /api/ops/archive/logs
 * Moves all approved/rolled-back log entries (status==='approved' or rolledBackAt)
 * to data/ops/archive/logs_archive.json (append), then removes them from history.json.
 * Entries with other statuses (pending, cancelled) are left untouched.
 * Admin only.
 */
app.post('/api/ops/archive/logs', requireAuth, (req, res) => {
  if (req.user.role !== 'Admin') {
    return res.status(403).json({ error: 'Admin only' });
  }

  const historyFile = path.join(dataRoot, 'ops', 'history.json');
  const archiveFile = path.join(dataRoot, 'ops', 'archive', 'logs_archive.json');
  const history     = readJson(historyFile, {});
  const archive     = readJson(archiveFile, []);

  let archived = 0;
  const archivedAt = new Date().toISOString();

  Object.entries(history).forEach(([ck, entries]) => {
    if (!Array.isArray(entries)) return;
    const keep = [];
    entries.forEach(e => {
      const isLogEntry = e.status === 'approved' || e.status === 'rolled_back' || e.rolledBackAt;
      if (isLogEntry) {
        archive.push({ ...e, _archivedAt: archivedAt, _archivedCountry: ck });
        archived++;
      } else {
        keep.push(e);
      }
    });
    history[ck] = keep;
  });

  writeJson(archiveFile, archive);
  writeJson(historyFile, history);

  appendAdminAudit({ action: 'logs-archived', by: req.user.email, archived });

  res.json({ success: true, archived });
});

// ─── README (public) ─────────────────────────────────────────────────────────

app.get('/api/readme', (req, res) => {
  const filePath = path.join(__dirname, 'README.md');
  try {
    const text = fs.readFileSync(filePath, 'utf8');
    res.type('text/plain; charset=utf-8').send(text);
  } catch {
    res.status(404).json({ error: 'README not found' });
  }
});

// ─── Expiration Scheduler (Step 5) ───────────────────────────────────────────
/**
 * Runs every 5 minutes. Reads buffer.json and validates any entry whose hold
 * timer has elapsed. Uses the same validation + auto-PR logic as the HTTP route.
 * Identity: 'system@ops' with role 'Manager' (sufficient to validate).
 */
async function _runExpirationSweep() {
  console.log('[OPS scheduler] Running expiration sweep');

  const bufferFile  = path.join(dataRoot, 'ops', 'buffer.json');
  const historyFile = path.join(dataRoot, 'ops', 'history.json');

  // Read buffer ONCE into memory — process entirely in memory, write once per country.
  const buffer  = readJson(bufferFile, {});
  const history = readJson(historyFile, {});
  const now     = Date.now();

  // Group expired entries by country so we can fire one PR per country.
  // Structure: { [country]: [ {userEmail, entry, idx} ] }
  const expiredByCountry = {};

  for (const [country, userMap] of Object.entries(buffer)) {
    if (!userMap || typeof userMap !== 'object') continue;
    for (const [userEmail, entries] of Object.entries(userMap)) {
      if (!Array.isArray(entries)) continue;
      for (let i = entries.length - 1; i >= 0; i--) {
        const entry = entries[i];
        if (!entry || !entry.createdAt) continue;
        const holdHours = entry.holdHours || 4;
        const expiresAt = new Date(entry.createdAt).getTime() + holdHours * 3600000;
        if (now < expiresAt) continue;
        if (_processingEntries.has(entry.id)) {
          console.warn(`[OPS scheduler] Entry "${entry.id}" already in processing — skipping`);
          continue;
        }
        if (!expiredByCountry[country]) expiredByCountry[country] = [];
        expiredByCountry[country].push({ userEmail, entry, idx: i });
      }
    }
  }

  const countryKeys = Object.keys(expiredByCountry);
  if (!countryKeys.length) {
    console.log('[OPS scheduler] No expired entries found');
    return;
  }

  for (const country of countryKeys) {
    const expired = expiredByCountry[country];
    console.log(`[OPS scheduler] Found ${expired.length} expired entries (${country.toUpperCase()})`);

    const processesData = readProcessData(country);
    if (!processesData) {
      console.error(`[OPS scheduler] Process file not found for "${country}" — skipping all entries`);
      continue;
    }
    const arr = processesData.data;

    if (!history[country]) history[country] = [];

    for (const { userEmail, entry, idx } of expired) {
      // Claim the lock
      _processingEntries.add(entry.id);
      try {
        // Verify entry is still in the in-memory buffer (not processed since we read)
        const userEntries = buffer[country][userEmail] || [];
        const bufIdx = userEntries.findIndex(e => e.id === entry.id);
        if (bufIdx === -1) {
          console.log(`[OPS scheduler] Entry "${entry.id}" already removed from buffer — skipping`);
          continue;
        }

        // Splice from in-memory buffer
        const freshEntry = userEntries.splice(bufIdx, 1)[0];

        // Apply the change to the in-memory process array
        const targetIdx = arr.findIndex(
          p => p.id === freshEntry.process.id || p.issue === freshEntry.process.issue
        );
        let before = null;
        let after  = null;

        if (freshEntry.type === 'create') {
          after = { ...freshEntry.process };
          if (targetIdx === -1) arr.push(freshEntry.process);
        } else if (freshEntry.type === 'update') {
          if (targetIdx !== -1) { before = { ...arr[targetIdx] }; arr[targetIdx] = freshEntry.process; }
          else arr.push(freshEntry.process);
          after = { ...freshEntry.process };
        } else if (freshEntry.type === 'delete') {
          if (targetIdx !== -1) { before = { ...arr[targetIdx] }; arr.splice(targetIdx, 1); }
        }

        const validatedAt          = new Date().toISOString();
        freshEntry.validatedAt     = validatedAt;
        freshEntry.validatedBy     = 'system@ops';
        freshEntry.status          = 'validated';
        freshEntry.before          = before;
        freshEntry.after           = after;
        freshEntry.previousProcess = before;
        freshEntry.autoExpired     = true;

        history[country].push(freshEntry);

        appendAdminAudit({
          action:  'buffer-auto-expired',
          by:      'system@ops',
          country,
          entryId: freshEntry.id,
          type:    freshEntry.type,
          before,
          after
        });

        console.log(`[OPS scheduler] Entry "${freshEntry.id}" auto-validated for "${country}"`);

      } catch (entryErr) {
        console.error(`[OPS scheduler] Error processing entry "${entry.id}":`, entryErr.message);
      } finally {
        _processingEntries.delete(entry.id);
      }
    }

    // Write process file and buffer once per country after all entries are processed
    writeProcessData(country, arr, processesData.meta);
    writeJson(bufferFile, buffer);
    writeJson(historyFile, history);

    // One PR per country covering all entries validated in this sweep
    // TODO: remove legacy "pending" filter after data migration.
    const validatedEntries = (history[country] || []).filter(
      h => h.status === 'validated' || h.status === 'pending'
    );
    if (!validatedEntries.length) continue;

    console.log(`[OPS PR] Creating PR for country: ${country.toUpperCase()} (${validatedEntries.length} entries)`);
    const prResult = await _createPRForCountry(country, validatedEntries, 'system@ops');
    if (prResult.success) {
      console.log(`[OPS PR] Success: ${prResult.prUrl}`);
      const approvedAt = new Date().toISOString();
      // Re-read for final write to avoid stale state after async PR call
      const hist2 = readJson(historyFile, {});
      (hist2[country] || []).forEach(h => {
        // TODO: remove legacy "pending" check after data migration.
        if (h.status === 'validated' || h.status === 'pending') {
          h.status     = 'approved';
          h.approvedAt = approvedAt;
          h.approvedBy = 'system@ops';
          h.prUrl      = prResult.prUrl;
          h.prNumber   = prResult.prNumber;
          h.branchName = prResult.branchName;
        }
      });
      writeJson(historyFile, hist2);
      appendAdminAudit({
        action:     'pr-auto-created',
        by:         'system@ops',
        country,
        branchName: prResult.branchName,
        prNumber:   prResult.prNumber,
        prUrl:      prResult.prUrl,
        trigger:    'expiration-scheduler'
      });
    } else {
      console.error(`[OPS PR] Failed: ${prResult.error}`);
    }
  }

  console.log('[OPS scheduler] Sweep complete');
}

// ─── Start ────────────────────────────────────────────────────────────────────

app.listen(port, () => {
  console.log(`Process Finder server listening on http://localhost:${port}`);
  console.log(GITHUB_TOKEN
    ? `[OPS] GitHub automation enabled — target branch: ${GITHUB_TARGET_BRANCH} (${GITHUB_OWNER}/${GITHUB_REPO})`
    : `[OPS] WARNING: GITHUB_TOKEN not configured — PR automation disabled`);

  // Start expiration scheduler — runs every 5 minutes
  const SWEEP_INTERVAL_MS = 5 * 60 * 1000;
  setInterval(() => {
    _runExpirationSweep().catch(err =>
      console.error('[OPS scheduler] Unhandled sweep error:', err.message)
    );
  }, SWEEP_INTERVAL_MS);
  console.log(`[OPS scheduler] Expiration sweep scheduled every ${SWEEP_INTERVAL_MS / 60000} minutes`);
});
