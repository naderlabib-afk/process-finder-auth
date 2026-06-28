const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fetch = require('node-fetch');

const app = express();
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", req.headers.origin || "*");
  res.header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");

  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }

  next();
});

const port = process.env.PORT || 3000;

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

app.use(bodyParser.json({ limit: '10mb' }));
app.use(express.static(__dirname));

// ─── Minimal JWT helpers (no external dependency) ────────────────────────────
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
function validateCountry(country) {
  return typeof country === 'string' && /^[a-z0-9_-]+$/i.test(country.trim());
}

// ─── GitHub API helpers ───────────────────────────────────────────────────────

function ghHeaders() {
  return {
    'Authorization': `token ${GITHUB_TOKEN}`,
    'Accept': 'application/vnd.github.v3+json',
    'Content-Type': 'application/json'
  };
}

/**
 * Fetches a file from the configured GitHub repo/branch.
 * Returns the full API response object (including .content and .sha) or null.
 */
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

/**
 * Fetches a JSON file from GitHub and returns its parsed content.
 * Returns fallback if the file does not exist or cannot be parsed.
 */
async function fetchGitHubJson(filePath, fallback = null) {
  try {
    const fileInfo = await getGitHubFileContent(filePath);
    if (!fileInfo || !fileInfo.content) return fallback;
    const raw = Buffer.from(fileInfo.content, 'base64').toString('utf8');
    const content = raw.charCodeAt(0) === 0xFEFF ? raw.slice(1) : raw;
    return JSON.parse(content);
  } catch (err) {
    console.error(`[GitHub] fetchGitHubJson failed for "${filePath}":`, err.message);
    return fallback;
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

/**
 * Commits a single JSON value to the GITHUB_BRANCH (main data branch).
 * Uses PUT /contents — creates the file if it doesn't exist, updates with sha if it does.
 */
async function commitJsonToMainBranch(filePath, data, message) {
  try {
    const fileInfo = await getGitHubFileContent(filePath);
    const res = await fetch(
      `https://api.github.ibm.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${filePath}`,
      {
        method: 'PUT',
        headers: ghHeaders(),
        body: JSON.stringify({
          message,
          content: Buffer.from(JSON.stringify(data, null, 2) + '\n').toString('base64'),
          branch: GITHUB_BRANCH,
          ...(fileInfo ? { sha: fileInfo.sha } : {})
        })
      }
    );
    return res.ok;
  } catch (err) {
    console.error(`[GitHub] commitJsonToMainBranch failed for "${filePath}":`, err.message);
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

// ─── GitHub-backed process data helpers ──────────────────────────────────────

/**
 * Reads data/processes/{country}.json from GitHub.
 * Returns { ghPath, data: [], meta: {} } or null if not found.
 */
async function readProcessData(country) {
  const ghPath = `data/processes/${country}.json`;
  const json = await fetchGitHubJson(ghPath, null);
  if (!json) {
    console.error(`[GitHub] readProcessData → null for ${ghPath}`);
    return null;
  }
  if (Array.isArray(json)) {
    return { ghPath, data: json, meta: {} };
  }
  const meta = { ...json };
  delete meta.processes;
  return { ghPath, data: Array.isArray(json.processes) ? json.processes : [], meta };
}

/**
 * Writes data/processes/{country}.json back to the main branch on GitHub.
 */
async function writeProcessData(country, processes, meta = {}) {
  const ghPath = `data/processes/${country}.json`;
  const payload = { ...meta, processes };
  if (!payload.lastUpdated) payload.lastUpdated = new Date().toISOString();
  return commitJsonToMainBranch(ghPath, payload, `ops: update ${country} process data`);
}

// ─── GitHub-backed audit log ──────────────────────────────────────────────────
/**
 * Appends an audit entry to data/logs/admin-audit.json on GitHub.
 * Never throws — audit failure must never block the successful response.
 */
async function appendAdminAudit(entry) {
  try {
    const ghPath = 'data/logs/admin-audit.json';
    const log = await fetchGitHubJson(ghPath, []);
    log.push({ ...entry, timestamp: new Date().toISOString() });
    await commitJsonToMainBranch(ghPath, log, `audit: ${entry.action || 'event'}`);
  } catch (err) {
    console.error('Admin audit write failed:', err.message);
  }
}

// ─── Idempotency guard ────────────────────────────────────────────────────────
const _processingEntries = new Set();

// ─── Shared PR helper ─────────────────────────────────────────────────────────
/**
 * Creates a GitHub branch, commits the country process file, and opens a PR.
 */
async function _createPRForCountry(country, validatedEntries, triggeredBy) {
  const now  = new Date();
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

    // Read the current production process file from main branch
    const processesData = await readProcessData(country);
    if (!processesData) throw new Error(`No process data found for country "${country}"`);

    // Apply each validated entry to an in-memory copy of the process array.
    // This produces the desired post-merge state without touching main branch.
    const arr = processesData.data.map(p => ({ ...p })); // shallow-copy each process
    for (const h of validatedEntries) {
      const targetIdx = arr.findIndex(
        p => p.id === h.process?.id || p.issue === h.process?.issue
      );
      if (h.type === 'create') {
        if (targetIdx === -1) arr.push({ ...h.process });
      } else if (h.type === 'update') {
        if (targetIdx !== -1) arr[targetIdx] = { ...h.process };
        else arr.push({ ...h.process });
      } else if (h.type === 'delete') {
        if (targetIdx !== -1) arr.splice(targetIdx, 1);
      }
    }

    const processJson = JSON.stringify(
      { ...processesData.meta, processes: arr, lastUpdated: new Date().toISOString() },
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

// ─── OTP Send Route ──────────────────────────────────────────────────────────

const { Resend } = require("resend");

app.post("/send-otp", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000);

    const resend = new Resend(process.env.RESEND_API_KEY);

    await resend.emails.send({
      from: "Process Finder <noreply@processfinder.xyz>",
      to: email,
      subject: "[Process Finder] Your OTP Code ✅",
      html: `
    <p>Hello,</p>

    <p>Your verification code is:</p>

    <h2 style="letter-spacing:2px;">${otp}</h2>

    <p>This code will expire in 5 minutes.</p>

    <p>If you did not request this, please ignore this email.</p>

    <br>

    <p>Regards,<br>Process Finder Team</p>
  `
    });

    console.log("[OTP SENT]", email, otp);

    res.json({ success: true });

  } catch (err) {
    console.error("OTP ERROR:", err);
    res.status(500).json({ error: "Failed to send OTP" });
  }
});

// ─── OTP Verify Route ────────────────────────────────────────────────────────

app.post("/verify-otp", (req, res) => {
  res.json({ success: true });
});

// ─── Auth ─────────────────────────────────────────────────────────────────────

/**
 * POST /api/auth/session
 * Validates the email against config/users.json (fetched from GitHub), then issues a signed JWT.
 */
app.post('/api/auth/session', async (req, res) => {
  const { email } = req.body;
  if (!email || typeof email !== 'string') {
    return res.status(400).json({ error: 'email required' });
  }
  const users = await fetchGitHubJson('config/users.json', []);
  const user = users.find(u => u.email.trim().toLowerCase() === email.trim().toLowerCase());
  if (!user || !['OL', 'Manager', 'Admin'].includes(user.role)) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  const now = Math.floor(Date.now() / 1000);
  const token = signJwt({ email: user.email, role: user.role, iat: now, exp: now + TOKEN_TTL });
  res.json({ success: true, token, email: user.email, role: user.role });
});

// ─── Config (read-only, public) ───────────────────────────────────────────────

app.get('/api/config/countries', async (req, res) => {
  res.json(await fetchGitHubJson('config/countries.json', []));
});

app.get('/api/config/users', async (req, res) => {
  res.json(await fetchGitHubJson('config/users.json', []));
});

// ─── Processes (read-only, public) ───────────────────────────────────────────

app.get('/api/processes/:country', async (req, res) => {
  const country = req.params.country.toLowerCase();
  if (!validateCountry(country)) {
    return res.status(400).json({ error: 'Invalid country' });
  }
  const json = await fetchGitHubJson(`data/processes/${country}.json`, null);
  if (!json) {
    return res.status(404).json({ error: 'Country not found' });
  }
  res.json(json);
});

// ─── OPS reads (public) ───────────────────────────────────────────────────────

app.get('/api/ops/buffer', async (req, res) => {
  res.json(await fetchGitHubJson('data/ops/buffer.json', {}));
});

app.get('/api/ops/history', async (req, res) => {
  res.json(await fetchGitHubJson('data/ops/history.json', {}));
});

/**
 * POST /api/ops/history/append
 * Appends a pre-formed entry to history (e.g. client-cancelled buffer item).
 */
app.post('/api/ops/history/append', requireAuth, async (req, res) => {
  const { country, entry } = req.body;
  if (!country || !entry || typeof entry !== 'object') {
    return res.status(400).json({ error: 'country and entry are required' });
  }
  if (!validateCountry(country)) {
    return res.status(400).json({ error: 'Invalid country' });
  }
  const history = await fetchGitHubJson('data/ops/history.json', {});
  if (!history[country]) history[country] = [];
  history[country].push(entry);
  await commitJsonToMainBranch('data/ops/history.json', history, `ops: append history entry for ${country}`);
  res.json({ success: true });
});

app.get('/api/ops/settings', async (req, res) => {
  res.json(await fetchGitHubJson('data/ops/settings.json', {}));
});

// ─── OPS writes (authenticated) ───────────────────────────────────────────────

/**
 * Validates a single process entry object.
 * Returns null if valid, or an error string describing the first violation.
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

/**
 * POST /api/ops/buffer
 * Adds a new pending entry for req.user.email (identity from JWT, not body).
 */
app.post('/api/ops/buffer', requireAuth, async (req, res) => {
  const { country, type, process, holdHours = 4 } = req.body;
  const user = req.user.email;

  if (!country || !type || !process) {
    return res.status(400).json({ error: 'country, type, and process are required' });
  }
  if (!validateCountry(country)) {
    return res.status(400).json({ error: 'Invalid country' });
  }
  if (!['create', 'update', 'delete'].includes(type)) {
    return res.status(400).json({ error: 'type must be create, update, or delete' });
  }
  if (type !== 'delete') {
    const schemaError = validateProcessEntry(process);
    if (schemaError) return res.status(400).json({ error: schemaError });
  } else {
    if (!process.id && !process.issue) {
      return res.status(400).json({ error: 'process.id or process.issue is required for delete' });
    }
  }

  const buffer = await fetchGitHubJson('data/ops/buffer.json', {});
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
  await commitJsonToMainBranch('data/ops/buffer.json', buffer, `ops: add buffer entry for ${country} by ${user}`);
  res.json({ success: true, entry });
});

/**
 * PUT /api/ops/buffer
 * Replaces the full buffer (legacy callers; prefer POST /api/ops/cancel).
 */
app.put('/api/ops/buffer', requireAuth, async (req, res) => {
  const { buffer: newBuffer } = req.body;
  if (!newBuffer || typeof newBuffer !== 'object') {
    return res.status(400).json({ error: 'buffer object required' });
  }
  await commitJsonToMainBranch('data/ops/buffer.json', newBuffer, 'ops: replace buffer');
  res.json({ success: true, buffer: newBuffer });
});

/**
 * POST /api/ops/cancel
 * Removes a single buffer entry and archives it to history with status='cancelled'.
 */
app.post('/api/ops/cancel', requireAuth, async (req, res) => {
  const { country, user: targetUser, index } = req.body;
  const canceller = req.user.email;

  if (!country || !targetUser || typeof index !== 'number') {
    return res.status(400).json({ error: 'country, user, and index are required' });
  }
  if (!validateCountry(country)) {
    return res.status(400).json({ error: 'Invalid country' });
  }

  const [buffer, history] = await Promise.all([
    fetchGitHubJson('data/ops/buffer.json', {}),
    fetchGitHubJson('data/ops/history.json', {})
  ]);

  const entries = (buffer[country] && buffer[country][targetUser]) || [];
  if (!entries[index]) {
    return res.status(404).json({ error: 'Buffer entry not found' });
  }

  const entry = entries.splice(index, 1)[0];
  entry.status      = 'cancelled';
  entry.cancelledAt = new Date().toISOString();
  entry.cancelledBy = canceller;

  if (!history[country]) history[country] = [];
  history[country].push(entry);

  await Promise.all([
    commitJsonToMainBranch('data/ops/buffer.json',  buffer,  `ops: cancel buffer entry ${entry.id} for ${country}`),
    commitJsonToMainBranch('data/ops/history.json', history, `ops: archive cancelled entry ${entry.id} for ${country}`)
  ]);

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
 */
app.post('/api/ops/validate', requireAuth, async (req, res) => {
  const { country, index } = req.body;
  const validator = req.user.email;

  if (!country || typeof index !== 'number') {
    return res.status(400).json({ error: 'country and index are required' });
  }
  if (!validateCountry(country)) {
    return res.status(400).json({ error: 'Invalid country' });
  }
  if (!['Manager', 'Admin'].includes(req.user.role)) {
    return res.status(403).json({ error: 'Only Manager or Admin can validate entries' });
  }

  const targetUser = req.body.user;
  if (!targetUser) return res.status(400).json({ error: 'user field required to identify buffer queue' });

  // Fetch buffer only here — history is re-fetched fresh right before its write
  const buffer = await fetchGitHubJson('data/ops/buffer.json', {});

  const entries = (buffer[country] && buffer[country][targetUser]) || [];

  const entryPeek = entries[index];
  if (!entryPeek) {
    return res.status(404).json({ error: 'Buffer entry not found' });
  }

  if (_processingEntries.has(entryPeek.id)) {
    console.warn(`[OPS validate] Entry "${entryPeek.id}" is already being processed — skipping duplicate`);
    return res.status(409).json({ error: 'Entry is already being processed' });
  }
  _processingEntries.add(entryPeek.id);

  const entry = entries.splice(index, 1)[0];

  try {
    // Process data is NOT written here — it is updated only when the PR is merged
    // into main by GitHub. before/after snapshots are derived from the entry itself.
    let before = entry.before ?? null;
    let after  = entry.after  ?? null;

    // For entries that don't carry pre-computed snapshots, derive them from the
    // process payload (mirrors the shape the UI expects in the diff block).
    if (before === null && after === null) {
      if (entry.type === 'create') {
        after = { ...entry.process };
      } else if (entry.type === 'update') {
        after = { ...entry.process };
      }
      // delete: before unknown without reading the file — leave as null
    }

    const now             = new Date().toISOString();
    entry.validatedAt     = now;
    entry.validatedBy     = validator;
    entry.status          = 'validated';
    entry.before          = before;
    entry.after           = after;
    entry.previousProcess = before;

    // Re-fetch history immediately before write to get the latest GitHub SHA
    const history = await fetchGitHubJson('data/ops/history.json', {});
    if (!history[country]) history[country] = [];
    history[country].push(entry);

    // Sequential writes — parallel commits to the same branch cause SHA conflicts
    // where one PUT wins and the other silently fails with 422 (stale sha).
    await commitJsonToMainBranch('data/ops/history.json', history, `ops: add validated entry ${entry.id} for ${country}`);
    await commitJsonToMainBranch('data/ops/buffer.json',  buffer,  `ops: remove validated entry ${entry.id} from buffer`);

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

    // ── Auto-create PR after validation ──────────────────────────────────────
    // Use the history we just committed (already contains the new entry)
    const validatedEntries = (history[country] || []).filter(
      h => h.status === 'validated' || h.status === 'pending'
    );

    (async () => {
      try {
        console.log(`[OPS PR] Creating PR for country: ${country.toUpperCase()} (${validatedEntries.length} entries)`);
        const prResult = await _createPRForCountry(country, validatedEntries, validator);
        if (prResult.success) {
          console.log(`[OPS PR] Success: ${prResult.prUrl}`);
          const approvedAt = new Date().toISOString();
          const hist = await fetchGitHubJson('data/ops/history.json', {});
          (hist[country] || []).forEach(h => {
            if (h.status === 'validated' || h.status === 'pending') {
              h.status     = 'approved';
              h.approvedAt = approvedAt;
              h.approvedBy = validator;
              h.prUrl      = prResult.prUrl;
              h.prNumber   = prResult.prNumber;
              h.branchName = prResult.branchName;
            }
          });
          await commitJsonToMainBranch('data/ops/history.json', hist, `ops: mark entries approved after PR #${prResult.prNumber}`);
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
 */
app.post('/api/ops/rollback', requireAuth, async (req, res) => {
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

  // First fetch: read the entry to validate it exists and capture item metadata
  const historyForRead = await fetchGitHubJson('data/ops/history.json', {});

  if (!historyForRead[country] || !historyForRead[country][historyIndex]) {
    return res.status(404).json({ error: 'History item not found' });
  }

  // Capture a snapshot of the item fields needed for the rollback — do NOT mutate yet
  const itemSnapshot = historyForRead[country][historyIndex];
  const now          = new Date().toISOString();
  const beforeSnap   = itemSnapshot.before ?? itemSnapshot.previousProcess ?? null;
  const afterSnap    = itemSnapshot.after  ?? itemSnapshot.process         ?? null;
  const itemType     = itemSnapshot.type;
  const itemId       = itemSnapshot.id;
  const itemProcess  = itemSnapshot.process;

  // Process data is NOT reverted here — rollback takes effect only when the
  // corresponding PR (restoring the previous state) is merged into main.
  // Re-fetch history immediately before write to get the latest GitHub SHA.
  const history = await fetchGitHubJson('data/ops/history.json', {});

  // Stamp the original entry in-place in the freshly fetched copy
  const item = history[country] && history[country][historyIndex];
  if (item) {
    item.rolledBackAt = now;
    item.rolledBackBy = req.user.email;
    item.status       = 'rolled_back';
  }

  const rollbackLogEntry = {
    id:          `rollback_${itemId || historyIndex}_${Date.now()}`,
    type:        'rollback',
    status:      'approved',
    user:        req.user.email,
    validatedAt: now,
    validatedBy: req.user.email,
    country,
    referenceId: itemId || null,
    process:     itemProcess,
    before:      afterSnap,
    after:       beforeSnap,
  };
  if (!history[country]) history[country] = [];
  history[country].push(rollbackLogEntry);

  await commitJsonToMainBranch('data/ops/history.json', history, `ops: rollback entry ${itemId || historyIndex} for ${country}`);

  appendAdminAudit({
    action:      'rollback-executed',
    by:          req.user.email,
    country,
    historyIndex,
    entryId:     itemId,
    type:        itemType,
    before:      afterSnap,
    after:       beforeSnap
  });

  res.json({ success: true, item: item || itemSnapshot });
});

/**
 * POST /api/ops/settings
 *
 * Saves settings to GitHub. When previousCategories is supplied, diffs old vs new
 * category names and rewrites every affected country process file on GitHub so that
 * filter buttons stay in sync without a browser reload.
 */
app.post('/api/ops/settings', requireAuth, async (req, res) => {
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
  const catName = c => (typeof c === 'string' ? c : c?.name || '').trim();

  const renames = {};
  if (Array.isArray(previousCategories) && Array.isArray(settings.categories)) {
    const newCats = settings.categories;
    const newNamesNorm = new Set(newCats.map(c => catName(c).toLowerCase()));

    previousCategories.forEach(prev => {
      const oldName     = catName(prev);
      const oldNameNorm = oldName.toLowerCase();
      if (!oldName) return;
      if (newNamesNorm.has(oldNameNorm)) return;

      const i       = previousCategories.indexOf(prev);
      const curr    = newCats[i];
      const newName = curr !== undefined ? catName(curr) : null;

      if (newName && newName.toLowerCase() !== oldNameNorm) {
        renames[oldNameNorm] = newName;
        console.log(`[settings] category rename detected: "${oldName}" → "${newName}"`);
      }
    });
  }

  // Apply renames to every country process file on GitHub
  const renameCount = Object.keys(renames).length;
  if (renameCount > 0) {
    // Fetch countries list to know which country files exist
    const countries = await fetchGitHubJson('config/countries.json', []);
    for (const c of countries) {
      const key     = c.key || c;
      const ghPath  = `data/processes/${key}.json`;
      const parsed  = await fetchGitHubJson(ghPath, null);
      if (!parsed) {
        console.error(`[settings] skipping unreadable file: ${ghPath}`);
        continue;
      }

      const isLegacyArray = Array.isArray(parsed);
      const processes = isLegacyArray ? parsed
                      : Array.isArray(parsed.processes) ? parsed.processes
                      : null;
      if (!processes) continue;

      let dirty = false;
      processes.forEach(p => {
        if (!p.category) return;
        const norm = p.category.trim().toLowerCase();
        if (renames[norm]) {
          console.log(`[settings] updated category "${p.category}" → "${renames[norm]}" in ${ghPath}`);
          p.category = renames[norm];
          dirty = true;
        }
      });

      if (dirty) {
        const payload = isLegacyArray
          ? processes
          : { ...parsed, processes, lastUpdated: new Date().toISOString() };
        await commitJsonToMainBranch(ghPath, payload, `ops: rename category in ${key} process file`);
        console.log(`[settings] wrote updated process file: ${ghPath}`);
      }
    }
  }
  // ────────────────────────────────────────────────────────────────────────

  await commitJsonToMainBranch('data/ops/settings.json', settings, 'ops: update settings');
  res.json({ success: true, settings, renames });
});

/**
 * POST /api/ops/approve-and-merge
 * Manual Admin fallback: creates a PR for all validated-but-not-yet-approved entries.
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
    const history        = await fetchGitHubJson('data/ops/history.json', {});
    const countryHistory = history[country] || [];

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

    // Re-fetch history after the PR call — _createPRForCountry involves multiple
    // async GitHub round-trips during which concurrent writes may have landed.
    const latestHistory = await fetchGitHubJson('data/ops/history.json', {});
    (latestHistory[country] || []).forEach(h => {
      if (h.status === 'validated' || h.status === 'pending') {
        h.status     = 'approved';
        h.approvedAt = approvedAt;
        h.approvedBy = approver;
        h.prUrl      = prResult.prUrl;
        h.prNumber   = prResult.prNumber;
        h.branchName = prResult.branchName;
      }
    });

    await commitJsonToMainBranch('data/ops/history.json', latestHistory, `ops: approve entries for ${country} PR #${prResult.prNumber}`);

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
 * Validate and normalise a single user object.
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
 * PATCH-like merge: applies an array of change operations to config/users.json on GitHub.
 */
app.post('/api/admin/users', requireAuth, async (req, res) => {
  if (req.user.role !== 'Admin') {
    return res.status(403).json({ error: 'Only Admin can manage users' });
  }
  const { users } = req.body;
  if (!Array.isArray(users) || users.length === 0) {
    return res.status(400).json({ error: 'users array of operations required' });
  }

  const before     = await fetchGitHubJson('config/users.json', []);
  const working    = before.map(u => ({ ...u }));
  const seenEmails = new Set(working.map(u => u.email.toLowerCase()));
  const batchSeen  = new Set();

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

  await commitJsonToMainBranch('config/users.json', working, `admin: update users (${users.length} op(s)) by ${req.user.email}`);

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
 * Creates an empty process JSON file for a new country on GitHub and registers it
 * in config/countries.json.
 */
app.post('/api/admin/process-file', requireAuth, async (req, res) => {
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

  const ghPath = `data/processes/${country}.json`;

  // ── 1. Create process file (idempotent) ──────────────────────────────────
  const existing = await getGitHubFileContent(ghPath);
  const fileAlreadyExisted = !!existing;
  if (!fileAlreadyExisted) {
    const envelope = {
      lastUpdated: new Date().toISOString(),
      country,
      processes: []
    };
    await commitJsonToMainBranch(ghPath, envelope, `admin: create process file for ${country}`);
  }

  // ── 2. Register in countries.json (idempotent) ───────────────────────────
  const countries = await fetchGitHubJson('config/countries.json', []);
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
    await commitJsonToMainBranch('config/countries.json', countries, `admin: register country ${country}`);
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
 * Safe country removal with mandatory data archival — all via GitHub API.
 */
app.post('/api/admin/remove-country', requireAuth, async (req, res) => {
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

  // ── 1. Read all data sources from GitHub ─────────────────────────────────
  const [processData, history, buffer, settings, countries] = await Promise.all([
    fetchGitHubJson(`data/processes/${country}.json`, null),
    fetchGitHubJson('data/ops/history.json', {}),
    fetchGitHubJson('data/ops/buffer.json', {}),
    fetchGitHubJson('data/ops/settings.json', {}),
    fetchGitHubJson('config/countries.json', [])
  ]);

  const processes = processData
    ? (Array.isArray(processData) ? processData : (processData.processes || []))
    : [];

  const historyEntries = history[country] || [];
  const logsEntries    = historyEntries.filter(
    e => e.status === 'approved' || e.status === 'rolled_back' || e.rolledBackAt
  );

  // ── 2. Archive processes ──────────────────────────────────────────────────
  const countryArchive = await fetchGitHubJson('data/ops/archive/country_archive.json', []);
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

  // ── 3. Archive history entries ────────────────────────────────────────────
  const histArchive = await fetchGitHubJson('data/ops/archive/history_archive.json', []);
  historyEntries.forEach(e => {
    histArchive.push({ ...e, _archivedAt: archivedAt, _archivedCountry: country });
  });

  // ── 4. Archive logs (approved/rolled-back subset) ─────────────────────────
  const logsArchive = await fetchGitHubJson('data/ops/archive/logs_archive.json', []);
  logsEntries.forEach(e => {
    logsArchive.push({ ...e, _archivedAt: archivedAt, _archivedCountry: country });
  });

  // ── 5. Remove country from live data ──────────────────────────────────────
  delete history[country];
  delete buffer[country];

  const updatedCountries = countries.filter(c => c.key !== country);
  if (Array.isArray(settings.countries)) {
    settings.countries = settings.countries.filter(c => c.key !== country);
  }

  // ── 6. Commit everything to GitHub in parallel ────────────────────────────
  await Promise.all([
    commitJsonToMainBranch('data/ops/archive/country_archive.json', countryArchive, `admin: archive processes for ${country}`),
    commitJsonToMainBranch('data/ops/archive/history_archive.json', histArchive,    `admin: archive history for ${country}`),
    commitJsonToMainBranch('data/ops/archive/logs_archive.json',    logsArchive,    `admin: archive logs for ${country}`),
    commitJsonToMainBranch('data/ops/history.json',                 history,        `admin: remove country ${country} from history`),
    commitJsonToMainBranch('data/ops/buffer.json',                  buffer,         `admin: clear buffer for ${country}`),
    commitJsonToMainBranch('config/countries.json',                 updatedCountries, `admin: deregister country ${country}`),
    commitJsonToMainBranch('data/ops/settings.json',                settings,       `admin: remove ${country} from settings`),
    // Overwrite the process file with an archived marker rather than deleting it
    // (GitHub API delete requires the sha and an extra round-trip; a tombstone is simpler)
    processData
      ? commitJsonToMainBranch(`data/processes/${country}.json`,
          { _archived: true, _archivedAt: archivedAt, country, processes },
          `admin: archive process file for ${country}`)
      : Promise.resolve()
  ]);

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
 * Moves all history entries to data/ops/archive/history_archive.json,
 * then resets history.json to empty country arrays.
 */
app.post('/api/ops/archive/history', requireAuth, async (req, res) => {
  if (req.user.role !== 'Admin') {
    return res.status(403).json({ error: 'Admin only' });
  }

  const [history, archive] = await Promise.all([
    fetchGitHubJson('data/ops/history.json', {}),
    fetchGitHubJson('data/ops/archive/history_archive.json', [])
  ]);

  let archived = 0;
  const archivedAt = new Date().toISOString();

  Object.entries(history).forEach(([ck, entries]) => {
    (entries || []).forEach(e => {
      archive.push({ ...e, _archivedAt: archivedAt, _archivedCountry: ck });
      archived++;
    });
    history[ck] = [];
  });

  await Promise.all([
    commitJsonToMainBranch('data/ops/archive/history_archive.json', archive,  `admin: archive ${archived} history entries`),
    commitJsonToMainBranch('data/ops/history.json',                 history,  'admin: clear history after archive')
  ]);

  appendAdminAudit({ action: 'history-archived', by: req.user.email, archived });

  res.json({ success: true, archived });
});

/**
 * POST /api/ops/archive/logs
 * Moves approved/rolled-back log entries to data/ops/archive/logs_archive.json,
 * then removes them from history.json.
 */
app.post('/api/ops/archive/logs', requireAuth, async (req, res) => {
  if (req.user.role !== 'Admin') {
    return res.status(403).json({ error: 'Admin only' });
  }

  const [history, archive] = await Promise.all([
    fetchGitHubJson('data/ops/history.json', {}),
    fetchGitHubJson('data/ops/archive/logs_archive.json', [])
  ]);

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

  await Promise.all([
    commitJsonToMainBranch('data/ops/archive/logs_archive.json', archive, `admin: archive ${archived} log entries`),
    commitJsonToMainBranch('data/ops/history.json',              history, 'admin: remove archived logs from history')
  ]);

  appendAdminAudit({ action: 'logs-archived', by: req.user.email, archived });

  res.json({ success: true, archived });
});

// ─── README (public) ─────────────────────────────────────────────────────────

app.get('/api/readme', async (req, res) => {
  try {
    const fileInfo = await getGitHubFileContent('README.md');
    if (!fileInfo || !fileInfo.content) {
      return res.status(404).json({ error: 'README not found' });
    }
    const text = Buffer.from(fileInfo.content, 'base64').toString('utf8');
    res.type('text/plain; charset=utf-8').send(text);
  } catch {
    res.status(404).json({ error: 'README not found' });
  }
});

// ─── Expiration Scheduler ─────────────────────────────────────────────────────
/**
 * Runs every 5 minutes. Reads buffer.json from GitHub and validates any entry
 * whose hold timer has elapsed. Uses the same validation + auto-PR logic as the
 * HTTP route.
 */
async function _runExpirationSweep() {
  console.log('[OPS scheduler] Running expiration sweep');

  // Fetch only buffer here — history is re-fetched fresh per-country right before each write
  const buffer = await fetchGitHubJson('data/ops/buffer.json', {});
  const now    = Date.now();

  // Group expired entries by country so we fire one PR per country.
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

    // Process data is NOT written here — it is updated only when the PR is merged.
    // Collect validated entry stubs in memory; snapshots derived from entry payload.
    const newlyValidated = [];

    for (const { userEmail, entry } of expired) {
      _processingEntries.add(entry.id);
      try {
        const userEntries = buffer[country][userEmail] || [];
        const bufIdx = userEntries.findIndex(e => e.id === entry.id);
        if (bufIdx === -1) {
          console.log(`[OPS scheduler] Entry "${entry.id}" already removed from buffer — skipping`);
          continue;
        }

        const freshEntry = userEntries.splice(bufIdx, 1)[0];

        // Derive before/after snapshots from the entry payload (no file read)
        let before = freshEntry.before ?? null;
        let after  = freshEntry.after  ?? null;
        if (before === null && after === null) {
          if (freshEntry.type === 'create' || freshEntry.type === 'update') {
            after = { ...freshEntry.process };
          }
        }

        const validatedAt          = new Date().toISOString();
        freshEntry.validatedAt     = validatedAt;
        freshEntry.validatedBy     = 'system@ops';
        freshEntry.status          = 'validated';
        freshEntry.before          = before;
        freshEntry.after           = after;
        freshEntry.previousProcess = before;
        freshEntry.autoExpired     = true;

        newlyValidated.push(freshEntry);

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

    if (!newlyValidated.length) continue;

    // Re-fetch history immediately before write to get the latest GitHub SHA.
    const history = await fetchGitHubJson('data/ops/history.json', {});
    if (!history[country]) history[country] = [];
    newlyValidated.forEach(e => history[country].push(e));

    // Commit buffer and history — process file intentionally excluded
    await Promise.all([
      commitJsonToMainBranch('data/ops/buffer.json',  buffer,  `ops: scheduler — remove expired entries for ${country}`),
      commitJsonToMainBranch('data/ops/history.json', history, `ops: scheduler — add validated entries for ${country}`)
    ]);

    const validatedEntries = (history[country] || []).filter(
      h => h.status === 'validated' || h.status === 'pending'
    );
    if (!validatedEntries.length) continue;

    console.log(`[OPS PR] Creating PR for country: ${country.toUpperCase()} (${validatedEntries.length} entries)`);
    const prResult = await _createPRForCountry(country, validatedEntries, 'system@ops');
    if (prResult.success) {
      console.log(`[OPS PR] Success: ${prResult.prUrl}`);
      const approvedAt = new Date().toISOString();
      // Re-fetch history after the multi-step PR creation round-trips
      const histAfterPr = await fetchGitHubJson('data/ops/history.json', {});
      (histAfterPr[country] || []).forEach(h => {
        if (h.status === 'validated' || h.status === 'pending') {
          h.status     = 'approved';
          h.approvedAt = approvedAt;
          h.approvedBy = 'system@ops';
          h.prUrl      = prResult.prUrl;
          h.prNumber   = prResult.prNumber;
          h.branchName = prResult.branchName;
        }
      });
      await commitJsonToMainBranch('data/ops/history.json', histAfterPr, `ops: scheduler — mark entries approved after PR #${prResult.prNumber}`);
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
  console.log('[STORAGE] GitHub-only mode — no local filesystem used');
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
