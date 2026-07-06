const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fetch = require('node-fetch');
const sharp = require('sharp');
const multer = require('multer');
const sanitizeHtml = require('sanitize-html');

const app = express();
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", req.headers.origin || "*");
  res.header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.header("Access-Control-Allow-Credentials", 'true');

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
// PR target branch — must be "main" in production.
// Set GITHUB_TARGET_BRANCH=main in Render. Server warns on startup if not "main".
const GITHUB_TARGET_BRANCH = process.env.GITHUB_TARGET_BRANCH || 'feature/pre-live';
// Overridable GitHub API base — set GITHUB_API_BASE in env to redirect calls (e.g. for tests).
// Production default: https://api.github.ibm.com
const GITHUB_API_BASE = process.env.GITHUB_API_BASE || 'https://api.github.ibm.com';

// Kill switch: set DISABLE_PR_CREATION=true in Render to block all PR creation,
// branch creation, commits, and buffer-to-history movements. Buffer reads/writes,
// validate/cancel, history reads, and PR schedule undo are unaffected.
const DISABLE_PR_CREATION = process.env.DISABLE_PR_CREATION === 'true';

// JWT secret — set via environment variable in production
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
// Token TTL: 8 hours in seconds
const TOKEN_TTL = 8 * 60 * 60;

app.use(bodyParser.json({ limit: '10mb' }));

// ─── Media proxy: serve process images from GitHub ────────────────────────────
//
// Intercepts GET /assets/process-media/* before express.static so the browser
// can load images that live on GitHub (not on the server's local disk).
//
// Access tiers:
//   _staged/…  — requires a valid OPS JWT (pre-approval images, OPS-only)
//   final/…    — public, no auth (published production images)
//
// Path governance: validated by _isAllowedPRPath() — the same allowlist used
// by PR scope verification. Invalid paths are rejected with 400.
// Cache-Control:
//   staged → no-store (images may be cleaned up at any time)
//   final  → 1-year immutable (UUID-named, content-addressed)
//
app.get('/assets/process-media/*', async (req, res) => {
  const suffix   = req.params[0] || '';
  const filePath = `assets/process-media/${suffix}`;

  // 1. Validate path via existing governance allowlist
  if (!_isAllowedPRPath(filePath)) {
    return res.status(400).json({ error: 'Invalid media path' });
  }

  // 2. Staged images require an authenticated OPS session
  if (_isStagedPath(filePath)) {
    const authHeader = req.headers.authorization || '';
    const cookieToken = (req.headers.cookie || '').match(/(?:^|;\s*)ops_session=([^;]+)/)?.[1] || '';
    const rawToken    = authHeader.startsWith('Bearer ')
      ? authHeader.slice(7)
      : (authHeader || cookieToken);
    const token = rawToken ? decodeURIComponent(rawToken) : '';
    const check = token ? verifyJwt(token) : { ok: false };
    if (!check.ok) {
      return res.status(401).json({ error: 'Authentication required for staged media' });
    }
  }

  // 3. Fetch raw bytes from GitHub
  try {
    const fileInfo = await getGitHubFileContent(filePath);
    if (!fileInfo?.content) {
      return res.status(404).send('Not found');
    }
    const buf = Buffer.from(fileInfo.content, 'base64');
    res.set('Content-Type', 'image/webp');
    res.set('Cache-Control', _isStagedPath(filePath)
      ? 'no-store'
      : 'public, max-age=31536000, immutable');
    return res.send(buf);
  } catch (err) {
    console.warn('[media proxy] fetch failed:', filePath, err.message);
    return res.status(502).json({ error: 'Media fetch failed' });
  }
});

app.use(express.static(__dirname));

// ─── Media upload: memory storage, 2MB raw limit (we validate 1MB after read) ──
const _mediaUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024 }
});

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

/**
 * Verifies a JWT token.
 * Returns { ok: true, payload } on success.
 * Returns { ok: false, expired: true }  when the token is valid but has expired.
 * Returns { ok: false, expired: false } when the token is malformed or the signature is wrong.
 */
function verifyJwt(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return { ok: false, expired: false };
    const [header, body, sig] = parts;
    const expected = b64url(
      crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest()
    );
    if (sig !== expected) return { ok: false, expired: false };
    const payload = JSON.parse(Buffer.from(body, 'base64').toString());
    if (payload.exp && Date.now() / 1000 > payload.exp) {
      return { ok: false, expired: true };
    }
    return { ok: true, payload };
  } catch {
    return { ok: false, expired: false };
  }
}

/** Sends a machine-readable 401 response based on the verifyJwt result. */
function _rejectAuth(res, verifyResult) {
  if (verifyResult.expired) {
    return res.status(401).json({
      error: 'SESSION_EXPIRED',
      message: 'Your OPS session has expired. Please sign in again.'
    });
  }
  return res.status(401).json({
    error: 'INVALID_TOKEN',
    message: 'Authorization token is missing or invalid.'
  });
}

// ─── Auth middleware ──────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) {
    return res.status(401).json({
      error: 'AUTH_REQUIRED',
      message: 'Authorization is required.'
    });
  }
  const result = verifyJwt(token);
  if (!result.ok) {
    return _rejectAuth(res, result);
  }
  req.user = { email: result.payload.email, role: result.payload.role };
  // Hybrid lazy trigger: any authenticated request wakes the PR executor.
  // Defined later in the file; safe to call here because Node hoists function
  // declarations — but _runScheduledPRExecutor is an async function expression,
  // so we guard with typeof to avoid ReferenceError during startup ordering.
  if (typeof _runScheduledPRExecutor === 'function') {
    _runScheduledPRExecutor().catch(() => {});
  }
  next();
}

// ─── Country validation helper ────────────────────────────────────────────────
function validateCountry(country) {
  return typeof country === 'string' && /^[a-z0-9_-]+$/i.test(country.trim());
}

/**
 * Phase 3: Country-scope enforcement helper.
 *
 * Asserts that the authenticated user is permitted to act on `country`.
 * - Admin:   always allowed (unrestricted scope).
 * - Manager: allowed only if `country` is in their `countries` array in config/users.json.
 * - OL:      allowed only if `country` is in their `countries` array in config/users.json.
 *
 * Returns { ok: true } on success.
 * Returns { ok: false, status: 403, error: string } when the user is not assigned to the country.
 * The caller is responsible for sending the HTTP response on failure.
 *
 * `allUsers` is optional — pass a pre-fetched copy to avoid a redundant GitHub read.
 */
async function _assertCountryAllowed(user, country, allUsers = null) {
  if (user.role === 'Admin') return { ok: true };
  const users = allUsers || await fetchGitHubJson('config/users.json', []);
  const norm  = e => (e || '').toLowerCase().trim();
  const rec   = users.find(u => norm(u.email) === norm(user.email));
  const assigned = Array.isArray(rec?.countries) ? rec.countries.map(c => norm(c)) : [];
  if (assigned.includes(norm(country))) return { ok: true };
  return {
    ok:     false,
    status: 403,
    error:  `Not allowed — you are not assigned to country "${country}".`
  };
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
      `${GITHUB_API_BASE}/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${filePath}?ref=${GITHUB_BRANCH}`,
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

/**
 * Reads a JSON file from a specific branch ref (not the default GITHUB_BRANCH).
 * Used by Mode B append to read process data from the active PR branch, not main.
 * Returns { data: parsedJson, meta: metaObject } or null if the file is missing/unreadable.
 */
async function _readProcessDataFromBranch(country, branchName) {
  const ghPath = `data/processes/${country}.json`;
  try {
    const res = await fetch(
      `https://api.github.ibm.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${ghPath}?ref=${encodeURIComponent(branchName)}`,
      { headers: ghHeaders() }
    );
    if (!res.ok) {
      console.warn(`[GitHub] _readProcessDataFromBranch: HTTP ${res.status} for "${ghPath}" on branch "${branchName}"`);
      return null;
    }
    const fileInfo = await res.json();
    if (!fileInfo || !fileInfo.content) return null;
    const raw     = Buffer.from(fileInfo.content, 'base64').toString('utf8');
    const cleaned = raw.charCodeAt(0) === 0xFEFF ? raw.slice(1) : raw;
    const json    = JSON.parse(cleaned);
    if (Array.isArray(json)) {
      return { ghPath, data: json, meta: {} };
    }
    const meta = { ...json };
    delete meta.processes;
    return { ghPath, data: Array.isArray(json.processes) ? json.processes : [], meta };
  } catch (err) {
    console.error(`[GitHub] _readProcessDataFromBranch failed for "${ghPath}" on "${branchName}":`, err.message);
    return null;
  }
}

// ─── OPS PR file allowlist ────────────────────────────────────────────────────
/**
 * The ONLY file paths an automated OPS PR is permitted to modify.
 * Any other file appearing in the PR's changed-file list is a sign of a
 * polluted branch and will cause the PR to be aborted / auto-closed.
 *
 * When GITHUB_TARGET_BRANCH === 'main':
 *   data/processes/{country}.json
 *
 * When GITHUB_TARGET_BRANCH === 'feature/pre-live' (legacy pre-live phase):
 *   data/processes/{country}.json  (still the same — we no longer use pre-live/ prefix)
 */
const OPS_PR_ALLOWED_PATH_PREFIX  = 'data/processes/';

/**
 * Validates whether a file path is allowed to appear in an OPS Publish Request.
 *
 * Allowed:
 *   - data/processes/{country}.json
 *   - assets/process-media/{country}/{processId}/{uuid}.webp  (final, post-promote)
 *   - assets/process-media/_staged/{country}/{processId}/{uuid}.webp  (staged, pre-approve)
 *
 * Blocked:
 *   - arbitrary assets/**
 *   - non-WebP media outputs
 *   - path traversal (..)
 *   - unsupported extensions
 *   - files outside governed country/process folders
 */
function _isAllowedPRPath(filePath) {
  if (typeof filePath !== 'string') return false;
  // Process data files
  if (filePath.startsWith(OPS_PR_ALLOWED_PATH_PREFIX)) {
    // Must be data/processes/{country}.json (no subdirectories)
    const rel = filePath.slice(OPS_PR_ALLOWED_PATH_PREFIX.length);
    return /^[a-z0-9_-]+\.json$/.test(rel);
  }
  // Media files — only .webp, no path traversal, governed structure
  if (!filePath.endsWith('.webp')) return false;
  if (filePath.includes('..')) return false;
  if (!/^[a-zA-Z0-9/_.\-]+$/.test(filePath)) return false;
  // Final media: assets/process-media/{country}/{processId}/{uuid}.webp
  // Staged media: assets/process-media/_staged/{country}/{processId}/{uuid}.webp
  // Both accepted in PR (promote step may include both old staged and new final)
  if (filePath.startsWith('assets/process-media/_staged/')) {
    const rel = filePath.slice('assets/process-media/_staged/'.length);
    const parts = rel.split('/');
    return parts.length === 3 &&
      /^[a-z0-9_-]+$/.test(parts[0]) &&    // country
      /^[a-zA-Z0-9_-]+$/.test(parts[1]) &&  // processId
      /^[a-f0-9-]{36}\.webp$/.test(parts[2]); // uuid.webp
  }
  if (filePath.startsWith('assets/process-media/')) {
    const rel = filePath.slice('assets/process-media/'.length);
    const parts = rel.split('/');
    return parts.length === 3 &&
      /^[a-z0-9_-]+$/.test(parts[0]) &&    // country
      /^[a-zA-Z0-9_-]+$/.test(parts[1]) &&  // processId
      /^[a-f0-9-]{36}\.webp$/.test(parts[2]); // uuid.webp
  }
  return false;
}

// ─── GitHub branch helpers ────────────────────────────────────────────────────

/**
 * Returns the latest commit SHA for a given branch, or null if not found.
 * Always reads from the live GitHub ref — never from a cached local state.
 */
async function _getLatestBranchSha(branchName) {
  try {
    const res = await fetch(
      `https://api.github.ibm.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/git/refs/heads/${encodeURIComponent(branchName)}`,
      { headers: ghHeaders() }
    );
    if (!res.ok) return null;
    const data = await res.json();
    // refs/heads/<branch> may return an array for prefix matches — find exact
    if (Array.isArray(data)) {
      const exact = data.find(r => r.ref === `refs/heads/${branchName}`);
      return exact ? exact.object.sha : null;
    }
    return data.object ? data.object.sha : null;
  } catch (err) {
    console.error(`[GitHub] _getLatestBranchSha("${branchName}") error:`, err.message);
    return null;
  }
}

/**
 * Returns true if a branch already exists on origin.
 */
async function _branchExists(branchName) {
  const sha = await _getLatestBranchSha(branchName);
  return sha !== null;
}

/**
 * Creates a new branch from the exact latest SHA of baseBranch.
 * Returns { ok: true, sha } or { ok: false, error }.
 *
 * CRITICAL: baseBranch must be GITHUB_TARGET_BRANCH so the new branch and the
 * PR share the same ancestry — preventing the "221 commits / 77 files" problem
 * that occurred when the branch was created from main but PR targeted feature/pre-live.
 */
async function createOPSBranch(branchName, baseBranch) {
  console.log(`[OPS branch] Creating "${branchName}" from "${baseBranch}"`);
  try {
    const sha = await _getLatestBranchSha(baseBranch);
    if (!sha) {
      return { ok: false, error: `Base branch "${baseBranch}" not found or has no commits` };
    }
    console.log(`[OPS branch] Base SHA for "${baseBranch}": ${sha}`);

    const createRes = await fetch(
      `https://api.github.ibm.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/git/refs`,
      {
        method: 'POST',
        headers: ghHeaders(),
        body: JSON.stringify({ ref: `refs/heads/${branchName}`, sha })
      }
    );
    if (!createRes.ok) {
      const errBody = await createRes.text().catch(() => '');
      return { ok: false, error: `Branch creation failed (HTTP ${createRes.status}): ${errBody}` };
    }
    return { ok: true, sha };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

/**
 * Commits a single file to an OPS PR branch via the GitHub Contents API.
 * Only whitelisted paths are accepted — returns { ok: false } for blocked paths.
 * Reads the current file SHA from the OPS branch itself (not from main) to
 * produce a proper file-update diff rather than a creation.
 */
async function commitFileToOPSBranch(branchName, filePath, content, message) {
  if (!_isAllowedPRPath(filePath)) {
    console.error(`[OPS branch] BLOCKED: "${filePath}" is not in the allowed path list`);
    return { ok: false, error: `Path "${filePath}" is not in the OPS PR allowed list` };
  }

  try {
    // Read existing file SHA from the OPS branch (not from main or target branch)
    // so GitHub produces a correct update diff, not a file-creation diff.
    const fileInfoRes = await fetch(
      `https://api.github.ibm.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${filePath}?ref=${branchName}`,
      { headers: ghHeaders() }
    );
    const fileInfo = fileInfoRes.ok ? await fileInfoRes.json() : null;
    const existingSha = fileInfo && !Array.isArray(fileInfo) ? fileInfo.sha : undefined;

    const putRes = await fetch(
      `https://api.github.ibm.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${filePath}`,
      {
        method: 'PUT',
        headers: ghHeaders(),
        body: JSON.stringify({
          message,
          content: Buffer.from(content).toString('base64'),
          branch: branchName,
          ...(existingSha ? { sha: existingSha } : {})
        })
      }
    );
    if (!putRes.ok) {
      const errBody = await putRes.text().catch(() => '');
      return { ok: false, error: `Commit failed (HTTP ${putRes.status}): ${errBody}` };
    }
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

/**
 * Legacy helper kept for non-OPS-PR uses (commitToGitHub was used by older
 * server.js routes). Marked internal — do not use for new OPS PR generation.
 * @deprecated Use commitFileToOPSBranch for OPS PR commits.
 */
async function commitToGitHub(branchName, commits) {
  try {
    for (const { filePath, content, message } of commits) {
      const fileInfoRes = await fetch(
        `https://api.github.ibm.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${filePath}?ref=${branchName}`,
        { headers: ghHeaders() }
      );
      const fileInfo = fileInfoRes.ok ? await fileInfoRes.json() : null;

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
async function commitJsonToMainBranch(filePath, data, message, _retries = 3) {
  for (let attempt = 1; attempt <= _retries; attempt++) {
    try {
      const fileInfo = await getGitHubFileContent(filePath);
      const res = await fetch(
        `${GITHUB_API_BASE}/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${filePath}`,
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
      if (res.ok) return true;
      // 409/422 = SHA conflict — re-fetch and retry
      if (res.status === 409 || res.status === 422) {
        const body = await res.text().catch(() => '');
        console.warn(`[GitHub] commitJsonToMainBranch SHA conflict for "${filePath}" (attempt ${attempt}): ${res.status} ${body}`);
        if (attempt < _retries) {
          await new Promise(r => setTimeout(r, 300 * attempt)); // back-off
          continue;
        }
      }
      const errBody = await res.text().catch(() => '');
      console.error(`[GitHub] commitJsonToMainBranch failed for "${filePath}": ${res.status} ${errBody}`);
      return false;
    } catch (err) {
      console.error(`[GitHub] commitJsonToMainBranch threw for "${filePath}" (attempt ${attempt}):`, err.message);
      if (attempt < _retries) {
        await new Promise(r => setTimeout(r, 300 * attempt));
        continue;
      }
      return false;
    }
  }
  return false;
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

// ─── Assignment history helper ───────────────────────────────────────────────
const ASSIGNMENT_HISTORY_PATH = 'data/ops/assignment_history.json';

/**
 * Appends one or more assignment-history events.
 * Never throws — must never block the calling operation.
 *
 * eventType: 'added' | 'removed' | 'changed' | 'promoted' | 'demoted'
 * Each event shape (Part F):
 *   eventId, userEmail, userName?, role, country/scope, action,
 *   effectiveAt, changedBy, reason?, previousRole?, previousCountries?,
 *   newRole?, newCountries?
 */
async function appendAssignmentHistory(events) {
  try {
    const history = await fetchGitHubJson(ASSIGNMENT_HISTORY_PATH, []);
    const now = new Date().toISOString();
    for (const ev of events) {
      history.push({
        eventId:    `asgn_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
        effectiveAt: now,
        ...ev
      });
    }
    await commitJsonToMainBranch(
      ASSIGNMENT_HISTORY_PATH, history,
      `ops: assignment history — ${events.map(e => e.action || 'event').join(', ')}`
    );
  } catch (err) {
    console.error('[assignment history] write failed:', err.message);
  }
}

/**
 * Resolves operational ownership of orphaned OL or Manager entries for a country
 * when a user is removed from a country-role assignment.
 *
 * Rules (Part D):
 *   - Find the OL/Manager who was already active for the same country at the
 *     time of departure — they inherit the orphaned work.
 *   - If no peer was active, the next assigned OL/Manager for that country
 *     inherits the orphaned work.
 *   - If no one is available, entries remain in buffer with original owner
 *     and are flagged as orphaned for Admin resolution.
 *
 * @param {string} departedEmail - email of user being removed/changed
 * @param {string} role          - 'OL' | 'Manager'
 * @param {string} country       - country key
 * @param {Array}  allUsers      - current users.json AFTER the update is applied
 * @returns {{ inheritedBy: string|null, orphaned: boolean }}
 */
function _resolveInheritance(departedEmail, role, country, allUsers) {
  const norm = e => (e || '').toLowerCase().trim();
  const normDeparted = norm(departedEmail);

  // Find other active users with the same role in the same country
  // (excluding the departed user)
  const peers = allUsers.filter(u =>
    norm(u.email) !== normDeparted &&
    u.role === role &&
    Array.isArray(u.countries) &&
    u.countries.some(c => norm(c) === norm(country))
  );

  if (peers.length > 0) {
    // Return the first peer (oldest assignment assumed by array order in users.json)
    return { inheritedBy: peers[0].email, orphaned: false };
  }
  return { inheritedBy: null, orphaned: true };
}

/**
 * Transfers orphaned buffer entries from a departed user to an inheritor.
 * Only transfers entries that are not locked by an active/pending PR.
 * Records an ownership-transfer audit event.
 * Never throws.
 *
 * @param {string} departedEmail  - original owner
 * @param {string} inheritedBy    - new operational owner
 * @param {string} country        - country key
 * @param {string} changedBy      - Admin email who made the change
 */
async function _transferOrphanedBufferEntries(departedEmail, inheritedBy, country, changedBy) {
  try {
    const norm = e => (e || '').toLowerCase().trim();
    const [buffer, history] = await Promise.all([
      fetchGitHubJson('data/ops/buffer.json', {}),
      fetchGitHubJson('data/ops/history.json', {})
    ]);

    const entries = (buffer[country] && buffer[country][departedEmail]) || [];
    if (!entries.length) return;

    // Entries locked by open PR must not be transferred
    const lockedIds = new Set(
      (history[country] || [])
        .filter(h => h.pr_status === 'pending_merge' && h.user && norm(h.user) === norm(departedEmail))
        .map(h => h.id)
    );

    const transferable = entries.filter(e => !lockedIds.has(e.id));
    const kept         = entries.filter(e =>  lockedIds.has(e.id));

    if (!transferable.length) return;

    // Move to inheritor's queue
    if (!buffer[country][inheritedBy]) buffer[country][inheritedBy] = [];
    for (const e of transferable) {
      buffer[country][inheritedBy].push({
        ...e,
        _originalOwner:       departedEmail,
        _ownershipTransferAt: new Date().toISOString(),
        _ownershipTransferBy: changedBy,
        _inheritedBy:         inheritedBy
      });
    }

    // Keep locked entries under departed user (Admin must resolve via Logs)
    buffer[country][departedEmail] = kept;

    await commitJsonToMainBranch(
      'data/ops/buffer.json', buffer,
      `ops: transfer ${transferable.length} entries from ${departedEmail} to ${inheritedBy} for ${country}`
    );

    appendActivityLog({
      event:            'ownership-transferred',
      country,
      departedUser:     departedEmail,
      inheritedBy,
      transferCount:    transferable.length,
      lockedCount:      lockedIds.size,
      changedBy,
      effectiveAt:      new Date().toISOString()
    });

    console.log(`[Inheritance] Transferred ${transferable.length} entries from ${departedEmail} → ${inheritedBy} for ${country}`);
  } catch (err) {
    console.error('[Inheritance] _transferOrphanedBufferEntries failed:', err.message);
  }
}

// ─── Idempotency guard ────────────────────────────────────────────────────────
const _processingEntries = new Set();

// ─── OPS PR creation ──────────────────────────────────────────────────────────

/**
 * Generates a unique OPS branch name for the given country.
 * Pattern: ops/<country>/<YYYYMMDD>-<HHMM>
 * If the generated name already exists, appends a seconds suffix to ensure
 * uniqueness without reusing any old generated branch.
 */
async function _generateOPSBranchName(country) {
  const now  = new Date();
  const pad  = n => String(n).padStart(2, '0');
  const date = `${now.getUTCFullYear()}${pad(now.getUTCMonth() + 1)}${pad(now.getUTCDate())}`;
  const time = `${pad(now.getUTCHours())}${pad(now.getUTCMinutes())}`;
  let name   = `ops/${country}/${date}-${time}`;

  // Uniqueness guard — append seconds if name already taken
  if (await _branchExists(name)) {
    name = `${name}-${pad(now.getUTCSeconds())}`;
    // Second collision is astronomically unlikely but guard anyway
    if (await _branchExists(name)) {
      name = `${name}-${Date.now()}`;
    }
  }
  return name;
}

/**
 * Verifies that the generated PR only modified allowed files.
 * Fetches the PR's file list from the GitHub API and checks each path against
 * the OPS allowlist.  Returns { clean: true } or { clean: false, blockedFiles }.
 */
async function _verifyPRFileScope(prNumber) {
  try {
    const res = await fetch(
      `${GITHUB_API_BASE}/repos/${GITHUB_OWNER}/${GITHUB_REPO}/pulls/${prNumber}/files`,
      { headers: ghHeaders() }
    );
    if (!res.ok) {
      console.warn(`[OPS PR] Could not fetch file list for PR #${prNumber}: HTTP ${res.status}`);
      return { clean: false, blockedFiles: [], error: `GitHub API returned ${res.status}` };
    }
    const files = await res.json();
    const blockedFiles = (Array.isArray(files) ? files : [])
      .map(f => f.filename)
      .filter(f => !_isAllowedPRPath(f));

    if (blockedFiles.length > 0) {
      console.error(`[OPS PR] PR #${prNumber} contains BLOCKED files: ${blockedFiles.join(', ')}`);
      return { clean: false, blockedFiles };
    }
    return { clean: true, fileCount: files.length };
  } catch (err) {
    console.error(`[OPS PR] _verifyPRFileScope error for PR #${prNumber}:`, err.message);
    return { clean: false, blockedFiles: [], error: err.message };
  }
}

/**
 * Attempts to close (auto-reject) a PR that was created but failed scope verification.
 * Best-effort — never throws.
 */
async function _closePR(prNumber, reason) {
  try {
    await fetch(
      `https://api.github.ibm.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/pulls/${prNumber}`,
      {
        method: 'PATCH',
        headers: ghHeaders(),
        body: JSON.stringify({
          state: 'closed',
          body: `[AUTO-CLOSED] PR creation aborted by safety check.\nReason: ${reason}`
        })
      }
    );
    console.log(`[OPS PR] Auto-closed PR #${prNumber} — reason: ${reason}`);
  } catch (err) {
    console.error(`[OPS PR] Failed to auto-close PR #${prNumber}:`, err.message);
  }
}

/**
 * Pre-flight check before creating any OPS PR.
 * Returns { ok: true } or { ok: false, error: string, httpStatus: number }.
 *
 * Validates:
 *   1. GITHUB_TOKEN configured
 *   2. Target base branch exists
 *   3. At least one validated entry provided
 *   4. No PR already open for this country (pending entries do NOT block — see governance §11)
 */
async function _preflightPRCheck(country, validatedEntries) {
  if (!GITHUB_TOKEN) {
    return { ok: false, httpStatus: 500, error: 'GITHUB_TOKEN not configured on server' };
  }

  const baseSha = await _getLatestBranchSha(GITHUB_TARGET_BRANCH);
  if (!baseSha) {
    return {
      ok: false, httpStatus: 500,
      error: `Target base branch "${GITHUB_TARGET_BRANCH}" could not be found`
    };
  }

  if (!validatedEntries || validatedEntries.length === 0) {
    return { ok: false, httpStatus: 400, error: 'No validated entries are ready for PR creation' };
  }

  // Governance: pending entries do NOT block PR creation.
  // Only validated entries are included; pending entries remain in Buffer untouched.
  // No pendingCount check here — see governance rule §11.3-5.

  // _hasOpenPRForCountry now returns { ok, hasOpen?, error? }.
  // If ok===false (GitHub unreachable / non-2xx), block the operation — fail safe.
  const prCheck = await _hasOpenPRForCountry(country);
  if (!prCheck.ok) {
    return {
      ok: false, httpStatus: 502,
      error: `Cannot verify open PRs on GitHub: ${prCheck.error}`
    };
  }
  if (prCheck.hasOpen) {
    return {
      ok: false, httpStatus: 409,
      error: 'A PR package is already pending approval for this country'
    };
  }

  return { ok: true };
}

/**
 * Filters buffer entries to those the triggering user is authorised to include
 * in a Publish Request, based on role and ownership.
 *
 * Scope rules:
 *   Admin   : all entries, unrestricted.
 *   Manager : own entries (any status) + entries owned by OL users only.
 *             Peer Manager entries are NEVER included.
 *             Country scope is caller-enforced — this function receives only the
 *             flat entry list for the requested country, which is already bounded
 *             by the Manager's assigned countries at the route level.
 *   OL      : own entries only. No other user's entries regardless of role.
 *
 * This is the AUTHORITATIVE scope filter for Publish Request eligibility.
 * The frontend canValidateEntry() mirrors this logic for button-visibility purposes only.
 * The backend always re-applies this filter server-side — frontend entry selection is never trusted.
 *
 * @param {Array}  entries      - flat array of buffer entries for the country
 * @param {Array}  allUsers     - users array from config/users.json
 * @param {string} triggeredBy  - email of the user triggering the PR
 * @returns {Array} filtered entries
 */
function _filterEntriesByPRScope(entries, allUsers, triggeredBy) {
  const norm = e => (e || '').toLowerCase().trim();
  const triggerUser = allUsers.find(u => norm(u.email) === norm(triggeredBy));
  const triggerRole = triggerUser?.role || 'OL';

  if (triggerRole === 'Admin') {
    return entries; // unrestricted
  }
  if (triggerRole === 'Manager') {
    return entries.filter(e => {
      if (norm(e.user) === norm(triggeredBy)) return true; // own entries
      const owner = allUsers.find(u => norm(u.email) === norm(e.user));
      return owner?.role === 'OL'; // OL entries only — not other Managers
    });
  }
  // OL: own entries only
  return entries.filter(e => norm(e.user) === norm(triggeredBy));
}

/**
 * Creates a clean, data-only automated OPS PR for one country.
 *
 * Safety guarantees:
 *   - Branch is created from the LATEST SHA of GITHUB_TARGET_BRANCH (same as PR base).
 *     This is the root fix for the "221 commits / 77 files" problem: the old code
 *     branched from GITHUB_BRANCH (main) but PR'd into GITHUB_TARGET_BRANCH
 *     (feature/pre-live), forcing git to include every diverged commit.
 *   - Only data/processes/{country}.json is ever committed (allowlist enforced twice:
 *     once at commit time and once via post-creation GitHub API file-list check).
 *   - Branch name follows ops/<country>/<timestamp> and is verified unique.
 *   - Buffer entries are only moved to History AFTER the PR scope is verified clean.
 *   - If scope verification fails, the PR is auto-closed and an error is returned.
 *
 * @returns {{ success, prUrl?, prNumber?, branchName?, error? }}
 */
async function _createPRForCountry(country, validatedEntries, triggeredBy) {
  // Phase 1 kill switch — no GitHub API calls of any kind when disabled.
  if (DISABLE_PR_CREATION) {
    console.warn(`[OPS PR] DISABLE_PR_CREATION=true — PR creation blocked for "${country}" (triggered by ${triggeredBy})`);
    return { success: false, error: 'PR creation is disabled on this server (DISABLE_PR_CREATION=true)' };
  }

  const branchName = await _generateOPSBranchName(country);
  const allowedFilePath = `data/processes/${country}.json`;

  console.log(`[OPS PR] ── Starting PR creation ──────────────────────────`);
  console.log(`[OPS PR]   country      : ${country}`);
  console.log(`[OPS PR]   base branch  : ${GITHUB_TARGET_BRANCH}`);
  console.log(`[OPS PR]   new branch   : ${branchName}`);
  console.log(`[OPS PR]   target file  : ${allowedFilePath}`);
  console.log(`[OPS PR]   entries      : ${validatedEntries.length}`);
  console.log(`[OPS PR]   triggered by : ${triggeredBy}`);

  let createdPRNumber = null;

  try {
    // ── Step 1: Create branch from target base branch SHA ──────────────────
    const branchResult = await createOPSBranch(branchName, GITHUB_TARGET_BRANCH);
    if (!branchResult.ok) {
      throw new Error(`Branch creation failed: ${branchResult.error}`);
    }
    console.log(`[OPS PR] Branch created at SHA: ${branchResult.sha}`);

    // ── Step 2: Build updated process JSON in memory ────────────────────────
    // Read from GITHUB_BRANCH (main) — this is the live production data source.
    // The branch was created from GITHUB_TARGET_BRANCH so the diff will be minimal
    // (only the actual process changes), but we compute the target state from main.
    const processesData = await readProcessData(country);
    if (!processesData) throw new Error(`No process data found for country "${country}"`);

    const arr = processesData.data.map(p => ({ ...p }));
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
    ) + '\n';

    // ── Step 3: Commit ONLY the allowed process file ────────────────────────
    const commitResult = await commitFileToOPSBranch(
      branchName,
      allowedFilePath,
      processJson,
      `ops: ${country} process updates — ${validatedEntries.length} change(s) by ${triggeredBy}`
    );
    if (!commitResult.ok) {
      throw new Error(`Commit failed: ${commitResult.error}`);
    }
    console.log(`[OPS PR] Committed ${allowedFilePath} to ${branchName}`);

    // ── Step 4: Open PR ─────────────────────────────────────────────────────
    const now = new Date();
    const pad = n => String(n).padStart(2, '0');
    const stamp = `${now.getUTCFullYear()}${pad(now.getUTCMonth() + 1)}${pad(now.getUTCDate())}_${pad(now.getUTCHours())}${pad(now.getUTCMinutes())}`;
    const title = `[OPS] ${country.toUpperCase()} Process Updates — ${stamp}`;
    const changeLines = validatedEntries
      .map(h => `- ${h.type.toUpperCase()}: ${h.process?.issue || h.process?.id || '?'}`)
      .join('\n');
    const description =
      `[OPS AUTO PR]\n\n` +
      `Country: ${country.toUpperCase()}\n` +
      `Base branch: ${GITHUB_TARGET_BRANCH}\n` +
      `Triggered by: ${triggeredBy}\n` +
      `Entries: ${validatedEntries.length}\n\n` +
      `Changes:\n${changeLines}\n\n` +
      `Files modified: ${allowedFilePath}`;

    const prResult = await createGitHubPR(branchName, title, description);
    if (!prResult.success) throw new Error(prResult.error);
    createdPRNumber = prResult.prNumber;
    console.log(`[OPS PR] PR #${prResult.prNumber} created → ${prResult.prUrl}`);

    // ── Step 5: Post-creation file scope verification ───────────────────────
    const scopeCheck = await _verifyPRFileScope(prResult.prNumber);
    if (!scopeCheck.clean) {
      const blockedList = scopeCheck.blockedFiles.join(', ') || scopeCheck.error || 'unknown';
      console.error(`[OPS PR] SCOPE VIOLATION on PR #${prResult.prNumber}: ${blockedList}`);
      await _closePR(prResult.prNumber,
        `PR creation aborted because unexpected repository files would be modified: ${blockedList}`);
      return {
        success: false,
        error: `PR creation aborted because unexpected repository files would be modified: ${blockedList}`,
        branchName,
        prNumber: prResult.prNumber,
        scopeViolation: true,
        blockedFiles: scopeCheck.blockedFiles
      };
    }
    console.log(`[OPS PR] Scope verified clean — ${scopeCheck.fileCount} file(s), all allowed`);

    return {
      success:  true,
      prUrl:    prResult.prUrl,
      prNumber: prResult.prNumber,
      branchName
    };

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

// ─── Email send mode ──────────────────────────────────────────────────────────
// EMAIL_SEND_MODE=real  → calls Resend API (production on Render)
// EMAIL_SEND_MODE=mock  → logs only, never calls Resend (local dev / tests)
// Unset defaults to mock so local runs never consume quota accidentally.
const EMAIL_SEND_MODE = (process.env.EMAIL_SEND_MODE || 'mock').toLowerCase();
console.log(`[OTP] Email send mode: ${EMAIL_SEND_MODE}`);

// ─── OTP send safety constants ────────────────────────────────────────────────
// Fixed sender — never overrideable by frontend input.
const OTP_FROM_ADDRESS = "Process Finder <noreply@processfinder.xyz>";
// Fixed subject — never overrideable by frontend input.
const OTP_SUBJECT      = "[Process Finder] Your OTP Code";

// ─── OTP challenge store ──────────────────────────────────────────────────────
// Keyed by normalized email. Entry shape: { code, expiry, attempts }
// Intentionally in-memory: challenges expire in 5 minutes and must not survive
// server restarts (a restart invalidates all in-flight OTPs by design).
const _otpChallenges = new Map();
const OTP_TTL_MS       = 5 * 60 * 1000;  // 5 minutes
const OTP_MAX_ATTEMPTS = 5;

// ─── OTP send rate-limit store ────────────────────────────────────────────────
// Keyed by normalized email.
// Entry shape: { lastSentAt: number, hourlySends: number[], globalHourlySends: number[] }
const _otpSendLog = new Map();
// Throttle: minimum seconds between consecutive sends to the same email.
const OTP_COOLDOWN_S     = 60;        // 60 s between sends per email
// Per-email hourly cap: max sends per email per rolling 60-minute window.
const OTP_HOURLY_CAP     = 5;
// Global hourly cap: max total OTP sends across all emails per rolling 60-minute window.
const OTP_GLOBAL_HOURLY_CAP = 20;
// Global send log (timestamps only, shared across all emails).
const _otpGlobalSendLog  = [];

// ─── Consumed otpToken jti set ────────────────────────────────────────────────
// One-time-use tokens: once a jti has been used to create a session it is
// placed here and rejected on any subsequent attempt.
const _usedOtpJtis  = new Set();
const OTP_TOKEN_TTL = 5 * 60; // 5 minutes in seconds

app.post("/send-otp", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email || typeof email !== 'string') {
      return res.status(400).json({ error: "Email is required" });
    }

    const normalized = email.trim().toLowerCase();

    // ── 1. Allowlist: recipient must be a registered user in config/users.json ──
    // This is the primary abuse-prevention guard. Only registered process-finder
    // users may receive OTP emails. Arbitrary email addresses are rejected.
    const allUsers = await fetchGitHubJson('config/users.json', []);
    const registeredUser = allUsers.find(
      u => (u.email || '').trim().toLowerCase() === normalized
    );
    if (!registeredUser) {
      // Return a generic 400 — do not reveal whether the email is registered.
      console.warn("[OTP BLOCKED] unregistered email:", normalized);
      return res.status(400).json({ error: "Email not authorized" });
    }

    // ── 2. Per-email cooldown ─────────────────────────────────────────────────
    const now = Date.now();
    const sendLog = _otpSendLog.get(normalized) || { lastSentAt: 0, hourlySends: [] };

    const cooldownRemainS = Math.ceil((sendLog.lastSentAt + OTP_COOLDOWN_S * 1000 - now) / 1000);
    if (cooldownRemainS > 0) {
      console.warn("[OTP THROTTLED] cooldown:", normalized, `${cooldownRemainS}s remaining`);
      return res.status(429).json({
        error: "Please wait before requesting another code.",
        retryAfterSeconds: cooldownRemainS
      });
    }

    // ── 3. Per-email hourly cap ───────────────────────────────────────────────
    const oneHourAgo = now - 60 * 60 * 1000;
    const recentSends = sendLog.hourlySends.filter(t => t > oneHourAgo);
    if (recentSends.length >= OTP_HOURLY_CAP) {
      console.warn("[OTP THROTTLED] hourly cap:", normalized, `${recentSends.length}/${OTP_HOURLY_CAP}`);
      return res.status(429).json({
        error: "Too many OTP requests. Please try again later.",
        retryAfterSeconds: 3600
      });
    }

    // ── 4. Global hourly cap ──────────────────────────────────────────────────
    // Prune old timestamps in place
    while (_otpGlobalSendLog.length && _otpGlobalSendLog[0] <= oneHourAgo) {
      _otpGlobalSendLog.shift();
    }
    if (_otpGlobalSendLog.length >= OTP_GLOBAL_HOURLY_CAP) {
      console.warn("[OTP THROTTLED] global hourly cap:", _otpGlobalSendLog.length, "sends in last hour");
      return res.status(429).json({
        error: "OTP service temporarily at capacity. Please try again later.",
        retryAfterSeconds: 3600
      });
    }

    // ── 5. Generate challenge (not stored until send confirmed) ───────────────
    const code = String(Math.floor(100000 + Math.random() * 900000));
    const challenge = {
      code,
      expiry: now + OTP_TTL_MS,
      attempts: 0
    };

    // ── 6. Send email (or mock) ───────────────────────────────────────────────
    if (EMAIL_SEND_MODE === 'mock') {
      // Mock mode: log only — never calls Resend. Safe for local dev and tests.
      // Code is logged to console ONLY in mock mode so local validation can proceed.
      console.log(
        "[OTP MOCK SENT]", normalized,
        "from:", OTP_FROM_ADDRESS,
        "subject:", OTP_SUBJECT,
        "(mock — Resend not called)"
      );
      console.log(`[OTP MOCK CODE] ${normalized} code: ${code}`);
    } else {
      // Real mode: call Resend API. from/subject are fixed constants — never
      // derived from request body or any user-supplied input.
      const resend = new Resend(process.env.RESEND_API_KEY);

      const result = await resend.emails.send({
        from:    OTP_FROM_ADDRESS,
        to:      normalized,       // allowlisted registered user only
        subject: OTP_SUBJECT,      // fixed — never user-supplied
        html: `
    <p>Hello,</p>
    <p>Your verification code is:</p>
    <h2 style="letter-spacing:2px;">${code}</h2>
    <p>This code will expire in 5 minutes.</p>
    <p>If you did not request this, please ignore this email.</p>
    <br>
    <p>Regards,<br>Process Finder Team</p>
  `
      });

      // Resend SDK v2+ returns { data: { id }, error }.
      // Challenge is NOT stored if Resend rejects — avoids a valid challenge
      // existing server-side for an email the user never received.
      if (result.error) {
        console.error(
          "[OTP SEND FAILED]", normalized,
          "from:", OTP_FROM_ADDRESS,
          "resendError:", result.error.name,
          "message:", result.error.message,
          "statusCode:", result.error.statusCode
        );
        return res.status(502).json({ error: "Failed to deliver OTP email. Please try again." });
      }

      console.log(
        "[OTP SENT]", normalized,
        "from:", OTP_FROM_ADDRESS,
        "messageId:", result.data?.id || "unknown"
      );
    }

    // ── 7. Commit challenge and update rate-limit state ───────────────────────
    _otpChallenges.set(normalized, challenge);
    sendLog.lastSentAt   = now;
    sendLog.hourlySends  = [...recentSends, now]; // pruned window + new timestamp
    _otpSendLog.set(normalized, sendLog);
    _otpGlobalSendLog.push(now);

    res.json({ success: true });

  } catch (err) {
    console.error("[OTP ERROR]", err.message || err);
    res.status(500).json({ error: "Failed to send OTP" });
  }
});

// ─── OTP Verify Route ────────────────────────────────────────────────────────
//
// Validates the submitted OTP code against the server-stored challenge.
// On success: deletes the challenge (one-time use) and returns a short-lived
// signed otpToken that /api/auth/session requires as proof of OTP verification.
// On failure: increments the attempt counter; after OTP_MAX_ATTEMPTS the
// challenge is locked (all further attempts rejected regardless of code).

app.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ error: 'EMAIL_AND_OTP_REQUIRED', message: 'Email and OTP code are required.' });
  }

  const normalized = email.trim().toLowerCase();
  const challenge  = _otpChallenges.get(normalized);

  if (!challenge) {
    return res.status(400).json({ error: 'OTP_NOT_FOUND', message: 'No OTP challenge found. Please request a new code.' });
  }

  if (Date.now() > challenge.expiry) {
    _otpChallenges.delete(normalized);
    return res.status(400).json({ error: 'OTP_EXPIRED', message: 'The OTP code has expired. Please request a new code.' });
  }

  if (challenge.attempts >= OTP_MAX_ATTEMPTS) {
    _otpChallenges.delete(normalized);
    return res.status(429).json({ error: 'TOO_MANY_ATTEMPTS', message: 'Too many incorrect attempts. Please request a new code.' });
  }

  const submitted = String(otp).trim();
  if (submitted !== challenge.code) {
    challenge.attempts += 1;
    const remaining = OTP_MAX_ATTEMPTS - challenge.attempts;
    return res.status(400).json({
      error: 'INVALID_OTP',
      // remainingAttempts is a typed numeric field for frontend rendering.
      // message is a human-readable fallback — frontend should use remainingAttempts
      // rather than parsing this string.
      remainingAttempts: remaining,
      message: remaining > 0
        ? `Incorrect code. ${remaining} attempt${remaining === 1 ? '' : 's'} remaining.`
        : 'Incorrect code. No attempts remaining. Please request a new code.'
    });
  }

  // ── Success: consume the challenge ──────────────────────────────────────────
  _otpChallenges.delete(normalized);

  // Issue a short-lived, single-use otpToken as proof of OTP verification.
  // /api/auth/session will require this token before issuing a session JWT.
  const now = Math.floor(Date.now() / 1000);
  const jti = crypto.randomBytes(16).toString('hex');
  const otpToken = signJwt({
    type: 'otp-verified',
    email: normalized,
    jti,
    iat: now,
    exp: now + OTP_TOKEN_TTL
  });

  console.log("[OTP VERIFIED]", normalized);
  res.json({ success: true, otpToken });
});

// ─── Auth ─────────────────────────────────────────────────────────────────────

/**
 * POST /api/auth/session
 * Requires a valid otpToken (issued by /verify-otp) as proof that the OTP
 * challenge was successfully completed. Only then validates the email against
 * config/users.json and issues a signed session JWT.
 *
 * Security guarantees:
 *  - otpToken must be a valid JWT signed with JWT_SECRET
 *  - otpToken type must be 'otp-verified'
 *  - otpToken email must match the session email
 *  - otpToken must not be expired
 *  - otpToken jti must not have been used before (single-use)
 *  - Role is always derived from the trusted server-side users config
 */
app.post('/api/auth/session', async (req, res) => {
  const { email, otpToken } = req.body;
  if (!email || typeof email !== 'string') {
    return res.status(400).json({ error: 'email required' });
  }
  if (!otpToken || typeof otpToken !== 'string') {
    return res.status(401).json({ error: 'OTP_TOKEN_REQUIRED', message: 'OTP verification token is required.' });
  }

  // Validate the otpToken
  const otpResult = verifyJwt(otpToken);
  if (!otpResult.ok) {
    const msg = otpResult.expired
      ? 'OTP verification has expired. Please request a new code.'
      : 'Invalid OTP verification token.';
    return res.status(401).json({ error: 'INVALID_OTP_TOKEN', message: msg });
  }

  const otpPayload = otpResult.payload;

  if (otpPayload.type !== 'otp-verified') {
    return res.status(401).json({ error: 'INVALID_OTP_TOKEN', message: 'Invalid OTP verification token.' });
  }

  const normalizedEmail = email.trim().toLowerCase();
  if (otpPayload.email !== normalizedEmail) {
    return res.status(401).json({ error: 'OTP_EMAIL_MISMATCH', message: 'OTP token does not match the requested email.' });
  }

  // Enforce single-use: reject if this jti has already been consumed
  if (_usedOtpJtis.has(otpPayload.jti)) {
    return res.status(401).json({ error: 'OTP_TOKEN_REUSED', message: 'OTP verification token has already been used.' });
  }

  // Mark this jti as consumed before issuing the session
  _usedOtpJtis.add(otpPayload.jti);

  // Role is always derived from the trusted server-side users config
  const users = await fetchGitHubJson('config/users.json', []);
  const user = users.find(u => u.email.trim().toLowerCase() === normalizedEmail);
  if (!user || !['OL', 'Manager', 'Admin'].includes(user.role)) {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const now = Math.floor(Date.now() / 1000);
  const token = signJwt({ email: user.email, role: user.role, iat: now, exp: now + TOKEN_TTL });
  console.log("[SESSION ISSUED]", user.email, user.role);
  res.setHeader('Set-Cookie', `ops_session=${encodeURIComponent(token)}; Path=/; Max-Age=${TOKEN_TTL}; HttpOnly; SameSite=None; Secure`);
  res.json({ success: true, token, email: user.email, role: user.role });
});

// ─── Config (read-only, public) ───────────────────────────────────────────────

app.get('/api/config/countries', async (req, res) => {
  res.json(await fetchGitHubJson('config/countries.json', []));
});

app.get('/api/config/users', async (req, res) => {
  // Phase 2: strip the `countries` array — public route must not expose country
  // assignment details. Returns email + role only for each user.
  const users = await fetchGitHubJson('config/users.json', []);
  res.json(users.map(u => ({ email: u.email, role: u.role })));
});

/**
 * GET /api/ops/users
 * Returns full user objects (email, role, countries) for authenticated OPS UI use.
 * Phase 2: new authenticated endpoint. Replaces the unguarded /api/config/users
 * for internal OPS calls that need the full user record.
 */
app.get('/api/ops/users', requireAuth, async (req, res) => {
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

// ─── OPS reads (authenticated — Phase 2) ────────────────────────────────────

app.get('/api/ops/buffer', requireAuth, async (req, res) => {
  res.json(await fetchGitHubJson('data/ops/buffer.json', {}));
});

app.get('/api/ops/history', requireAuth, async (req, res) => {
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

app.get('/api/ops/settings', requireAuth, async (req, res) => {
  res.json(await fetchGitHubJson('data/ops/settings.json', {}));
});

// ─── OPS writes (authenticated) ───────────────────────────────────────────────

// ─── Rich-content HTML sanitizer (parser-based via sanitize-html) ─────────────
/**
 * Server-side HTML sanitizer for process.process content.
 * Uses the `sanitize-html` library (parser-based, not regex) for robust
 * protection against malformed HTML, nested injection, uppercase/mixed-case
 * tags, unquoted attributes, and adversarial input.
 *
 * Allowed tag set: p, br, strong, b, em, i, u, ul, ol, li, h2, h3,
 *                  a (safe href only), img (internal media src only),
 *                  blockquote, span, pre
 *
 * Blocked entirely (subtree removed): script, style, iframe, object, embed,
 *   form, input, button, svg, math, link, base, noscript, template,
 *   and ALL unknown tags (text content preserved for most; subtree removed
 *   for the dangerous set above).
 *
 * img rules:
 *   - src must start with assets/process-media/ or /assets/process-media/
 *   - src must NOT be data:, javascript:, or any external URL
 *   - Only allowed attrs: src, alt, data-width (200-800), loading
 *   - loading is always forced to "lazy"
 *
 * a rules:
 *   - href must be http:, https:, or mailto: only
 *   - rel="noopener noreferrer" and target="_blank" always added
 *
 * All on* event attributes blocked globally.
 * All style attributes blocked globally.
 * Plain text (no leading '<') is returned unchanged — caller handles escaping.
 */

/**
 * Validates an internal media src.
 * Allows: assets/process-media/... or /assets/process-media/...
 * Rejects: anything else (data:, http:, //, relative paths outside media).
 */
function _safeMediaSrc(src) {
  if (!src || typeof src !== 'string') return null;
  const s = src.trim();
  // Reject any protocol-containing value
  if (/^(javascript|data|vbscript):/i.test(s)) return null;
  // Allow staged paths (during Buffer preview)
  if (s.startsWith('assets/process-media/_staged/')) return s;
  // Allow final paths (after approval)
  if (s.startsWith('assets/process-media/')) return s;
  // Allow root-relative forms
  if (s.startsWith('/assets/process-media/')) return s;
  return null;
}

/**
 * The sanitize-html options object — defined once and reused.
 * Parser-based: handles malformed HTML, uppercase tags, unquoted attrs, etc.
 */
const _SANITIZE_OPTIONS = {
  // Tags whose entire subtree is removed (content not preserved)
  nonTextTags: ['script','style','iframe','object','embed','form','input',
                'button','svg','math','link','base','noscript','template'],

  allowedTags: [
    'p','br','strong','b','em','i','u',
    'ul','ol','li',
    'h2','h3',
    'a','img',
    'blockquote','span','pre'
  ],

  allowedAttributes: {
    // img: only src, alt, data-width, loading — all others stripped
    'img': ['src','alt','data-width','loading'],
    // a: href, rel, target — rel and target are forced below
    'a':   ['href','rel','target'],
    // All other allowed tags: no attributes (strips class, id, style, on*)
    '*':   []
  },

  // Validate img src: internal media paths only
  allowedSchemesByTag: {
    // a uses explicit transform below; img uses exclusiveFilter
  },

  // Force safe values on allowed attributes
  transformTags: {
    'a': (tagName, attribs) => {
      const href = (attribs.href || '').trim();
      const lh = href.toLowerCase();
      const safeHref = (
        lh.startsWith('http://') ||
        lh.startsWith('https://') ||
        lh.startsWith('mailto:')
      ) ? href : '';
      return {
        tagName: 'a',
        attribs: safeHref
          ? { href: safeHref, rel: 'noopener noreferrer', target: '_blank' }
          : { rel: 'noopener noreferrer' } // no href if unsafe
      };
    },
    'img': (tagName, attribs) => {
      const src = attribs.src || '';
      const safeSrc = _safeMediaSrc(src);
      if (!safeSrc) {
        // Return an empty span — sanitize-html will render text only
        return { tagName: false };
      }
      const w = parseInt(attribs['data-width'] || '', 10);
      const safeW = (w >= 200 && w <= 800) ? w : null;
      return {
        tagName: 'img',
        attribs: {
          src: safeSrc,
          ...(attribs.alt ? { alt: String(attribs.alt).replace(/"/g, '&quot;') } : {}),
          ...(safeW ? { 'data-width': String(safeW) } : {}),
          loading: 'lazy'
        }
      };
    }
  },

  // disallowedTagsMode: 'discard' means unknown tags' text content is kept
  // (non-text subtree tags are handled via nonTextTags above)
  disallowedTagsMode: 'discard',

  // Extra safety: strip data: and javascript: from any attribute value
  allowedSchemes: ['http','https','mailto'],
  allowedSchemesAppliedToAttributes: ['href','src','action'],
  allowedSchemesAllowRelative: false,

  // Prevent URL encoding bypass
  parseStyleAttributes: false
};

/**
 * Parser-based HTML sanitizer for process.process content.
 * Uses sanitize-html (underlying htmlparser2) — handles malformed/adversarial HTML.
 * Plain text (no leading '<') is returned unchanged.
 */
function sanitizeProcessHtml(html) {
  if (!html || typeof html !== 'string') return '';
  const t = html.trim();
  if (!t) return '';
  // Plain text — return as-is; callers handle escaping
  if (!t.startsWith('<')) return html;
  return sanitizeHtml(t, _SANITIZE_OPTIONS);
}

// Keep helpers accessible for tests
function _safeLinkHref(href) {
  if (!href) return null;
  const h = href.trim().toLowerCase();
  if (h.startsWith('http://') || h.startsWith('https://') || h.startsWith('mailto:')) {
    return href.trim();
  }
  return null;
}

/**
 * Validates a single process entry object.
 * Returns null if valid, or an error string describing the first violation.
 * Also sanitizes process.process HTML content in-place.
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
  // Sanitize rich HTML content before accepting into Buffer
  if (p.process && p.process.trim().startsWith('<')) {
    p.process = sanitizeProcessHtml(p.process);
    if (!p.process.trim()) {
      return 'process.process content was fully stripped by sanitization — unsafe content detected';
    }

    // MOD-5: backend enforcement — max 3 images per process (matches MEDIA_MAX_IMAGES_PER_PROCESS)
    const _imgRe = /<img\b[^>]*>/gi;
    const imgMatches = p.process.match(_imgRe) || [];
    if (imgMatches.length > 3) {
      return `Maximum 3 images allowed per process (${imgMatches.length} found after sanitization)`;
    }

    // MOD-5: backend enforcement — no external or data: image srcs allowed
    // After sanitization, all img tags must have internal assets/process-media/ src only.
    // This catches any smuggled external src that survived the sanitizer (belt-and-suspenders).
    const _srcRe = /<img\b[^>]*\bsrc="([^"]*)"[^>]*>/gi;
    let m;
    while ((m = _srcRe.exec(p.process)) !== null) {
      const src = m[1];
      if (!src.startsWith('assets/process-media/') && !src.startsWith('/assets/process-media/')) {
        return `Invalid image source detected — only internal media paths are allowed (found: ${src.slice(0, 80)})`;
      }
    }
  }
  return null;
}

// ── Process edit-lock constants (used by POST /api/ops/buffer and the lock endpoints) ──
const PROCESS_EDIT_LOCKS_PATH = 'data/ops/process_edit_locks.json';
const PROC_LOCK_TTL_MS        = 15 * 60 * 1000;
const MIN_ADMIN_ERROR_MESSAGE = 'This change cannot be saved because Process Finder must always have at least one Admin. Assign another Admin first, then you may change this role.';

function _normalizeIssue(issue) {
  return String(issue || '').trim();
}

function _getProcessLockKey(entryOrProcess) {
  return entryOrProcess?.originalProcessId || entryOrProcess?.process?.originalProcessId || entryOrProcess?.process?.id || entryOrProcess?.id || null;
}

function _getDuplicateProcessIdentity(entryOrProcess) {
  return entryOrProcess?.originalProcessId || entryOrProcess?.process?.originalProcessId || entryOrProcess?.process?.id || entryOrProcess?.id || null;
}

function _buildDuplicateError(country, issue) {
  return {
    error: `This Issue/Subject already exists in ${country.toUpperCase()}. Please change the Issue/Subject or modify the existing process instead.`,
    code: 'DUPLICATE_ISSUE_SUBJECT',
    opsMessage: `This Issue/Subject already exists in ${country.toUpperCase()}. Please change the Issue/Subject or modify the existing process instead.`,
    country,
    issue
  };
}

async function _findDuplicateIssueInCountry(country, issue, excludedIdentity = null, excludedEntryId = null) {
  const normalizedIssue = _normalizeIssue(issue);
  if (!normalizedIssue) return null;

  const [production, buffer, history, schedule] = await Promise.all([
    readProcessData(country),
    fetchGitHubJson('data/ops/buffer.json', {}),
    fetchGitHubJson('data/ops/history.json', {}),
    fetchGitHubJson(PR_SCHEDULE_PATH, {})
  ]);

  const excluded = excludedIdentity || null;
  const excludedBufferEntryId = excludedEntryId || null;
  const matchesIdentity = candidate => excluded && candidate && candidate === excluded;

  for (const proc of (production?.data || [])) {
    if (_normalizeIssue(proc.issue) !== normalizedIssue) continue;
    if (matchesIdentity(proc.id)) continue;
    return { source: 'production', issue: proc.issue, identity: proc.id || null };
  }

  const countryBuffer = buffer[country] || {};
  const scheduleEntryIds = new Set(Array.isArray(schedule[country]?.entry_ids) ? schedule[country].entry_ids : []);
  for (const entries of Object.values(countryBuffer)) {
    for (const entry of (entries || [])) {
      if (_normalizeIssue(entry.process?.issue) !== normalizedIssue) continue;
      if (excludedBufferEntryId && entry.id === excludedBufferEntryId) continue;
      const identity = _getDuplicateProcessIdentity(entry);
      if (matchesIdentity(identity)) continue;
      return {
        source: scheduleEntryIds.has(entry.id) ? 'scheduled' : `buffer_${entry.status || 'pending'}`,
        issue: entry.process?.issue,
        identity: identity || null,
        entryId: entry.id
      };
    }
  }

  for (const histEntry of (history[country] || [])) {
    if (_normalizeIssue(histEntry.process?.issue) !== normalizedIssue) continue;
    if (!['pending_merge'].includes(histEntry.pr_status)) continue;
    const identity = _getDuplicateProcessIdentity(histEntry);
    if (matchesIdentity(identity)) continue;
    return {
      source: 'active_publish_request',
      issue: histEntry.process?.issue,
      identity: identity || null,
      entryId: histEntry.id,
      prNumber: histEntry.prNumber || null
    };
  }

  return null;
}

async function _findActiveWorkflowLock(country, originalProcessId, excludedEntryId = null) {
  if (!originalProcessId) return null;

  const [buffer, history, schedule] = await Promise.all([
    fetchGitHubJson('data/ops/buffer.json', {}),
    fetchGitHubJson('data/ops/history.json', {}),
    fetchGitHubJson(PR_SCHEDULE_PATH, {})
  ]);

  const countryBuffer = buffer[country] || {};
  const scheduleEntryIds = new Set(Array.isArray(schedule[country]?.entry_ids) ? schedule[country].entry_ids : []);

  for (const entries of Object.values(countryBuffer)) {
    for (const entry of (entries || [])) {
      if (excludedEntryId && entry.id === excludedEntryId) continue;
      if (_getProcessLockKey(entry) !== originalProcessId) continue;
      return {
        source: scheduleEntryIds.has(entry.id) ? 'scheduled' : `buffer_${entry.status || 'pending'}`,
        entryId: entry.id,
        originalProcessId
      };
    }
  }

  for (const histEntry of (history[country] || [])) {
    if (excludedEntryId && histEntry.id === excludedEntryId) continue;
    if (histEntry.pr_status !== 'pending_merge') continue;
    if (_getProcessLockKey(histEntry) !== originalProcessId) continue;
    return {
      source: 'active_publish_request',
      entryId: histEntry.id,
      originalProcessId,
      prNumber: histEntry.prNumber || null
    };
  }

  return null;
}

/**
 * POST /api/ops/buffer
 * Adds a new pending entry for req.user.email (identity from JWT, not body).
 */
app.post('/api/ops/buffer', requireAuth, async (req, res) => {
  const { country, type, process } = req.body;
  const user = req.user.email;

  if (!country || !type || !process) {
    return res.status(400).json({ error: 'country, type, and process are required' });
  }
  if (!validateCountry(country)) {
    return res.status(400).json({ error: 'Invalid country' });
  }
  // Phase 3: country-scope enforcement
  const _bufScope = await _assertCountryAllowed(req.user, country);
  if (!_bufScope.ok) return res.status(_bufScope.status).json({ error: _bufScope.error });
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

  const processIdentity = process.originalProcessId || process.id || null;

  // ── Process edit-lock guard (update only) ────────────────────────────────────
  // Reject update submissions if another user holds a live process edit lock.
  // This prevents a race where two users save simultaneously; the second save
  // (which won the lock check on the frontend) is blocked here as the canonical guard.
  if (type === 'update' && processIdentity) {
    const procLocks = await fetchGitHubJson(PROCESS_EDIT_LOCKS_PATH, {});
    const lock = (procLocks[country] || {})[processIdentity];
    if (lock && lock.editingBy) {
      const norm = e => (e || '').toLowerCase().trim();
      const lockAge = lock.editingLastActivityAt
        ? Date.now() - new Date(lock.editingLastActivityAt).getTime()
        : Infinity;
      if (
        norm(lock.editingBy) !== norm(user) &&
        lockAge < PROC_LOCK_TTL_MS
      ) {
        return res.status(409).json({
          error: `This process is currently being edited by ${lock.editingBy}`,
          editingBy: lock.editingBy,
          editingLastActivityAt: lock.editingLastActivityAt
        });
      }
    }
  }

  if (type === 'update' || type === 'delete') {
    if (!processIdentity) {
      return res.status(400).json({ error: 'originalProcessId or process.id is required for update/delete' });
    }
    const activeLock = await _findActiveWorkflowLock(country, processIdentity);
    if (activeLock) {
      return res.status(409).json({
        error: 'This process already has an active workflow and remains locked until that request is resolved.',
        code: 'PROCESS_WORKFLOW_LOCKED',
        originalProcessId: processIdentity,
        ...activeLock
      });
    }
  }

  if (type !== 'delete') {
    const duplicate = await _findDuplicateIssueInCountry(
      country,
      process.issue,
      type === 'update' ? processIdentity : null
    );
    if (duplicate) {
      return res.status(409).json({
        ..._buildDuplicateError(country, process.issue),
        duplicate
      });
    }
  }

  // ── Ownership guard for update/delete ────────────────────────────────────────
  // If the target process (by issue) already has a pending buffer entry owned by
  // another user, check that the caller has the rights to act on that user's entry.
  // This mirrors the frontend canActOnProcess() rule and prevents privilege bypass.
  if (type === 'update' || type === 'delete') {
    const targetIssue = process.issue || '';
    if (targetIssue) {
      const allUsers   = await fetchGitHubJson('config/users.json', []);
      const norm       = e => (e || '').toLowerCase().trim();
      const callerRole = req.user.role;

      // Find any existing pending entry for this issue across all users
      let existingOwner = null;
      let existingOwnerRole = 'OL';
      outer: for (const [entryUser, entries] of Object.entries(buffer[country] || {})) {
        for (const e of (entries || [])) {
          if (e.process?.issue === targetIssue) {
            existingOwner = norm(entryUser);
            const ownerRec  = allUsers.find(u => norm(u.email) === existingOwner);
            existingOwnerRole = ownerRec?.role || 'OL';
            break outer;
          }
        }
      }

      if (existingOwner && norm(existingOwner) !== norm(user)) {
        // There is a pending entry for this process owned by someone else.
        // Apply the same role-scoped permission model as /api/ops/cancel.
        let allowed = false;
        if (callerRole === 'Admin') {
          allowed = true;
        } else if (callerRole === 'Manager') {
          allowed = existingOwnerRole === 'OL';
        }
        // OL: not allowed to act on another user's entry
        if (!allowed) {
          return res.status(403).json({
            error: `Not allowed — process "${targetIssue}" already has a pending entry owned by another user.`
          });
        }
      }
    }
  }

  const entry = {
    id: process.id || `${country}_${Date.now()}`,
    type,
    process: {
      ...process,
      ...(type === 'update' || type === 'delete'
        ? { originalProcessId: processIdentity }
        : {})
    },
    ...(type === 'update' || type === 'delete'
      ? { originalProcessId: processIdentity }
      : {}),
    user,
    createdAt: new Date().toISOString(),
    status: 'pending'
  };

  buffer[country][user].push(entry);
  await commitJsonToMainBranch('data/ops/buffer.json', buffer, `ops: add buffer entry for ${country} by ${user}`);
  res.json({ success: true, entry });
});

/**
 * PUT /api/ops/buffer
 * Replaces the full buffer (legacy callers; prefer POST /api/ops/cancel).
 * Rejects the write if the entry being modified is locked by another user's active edit session.
 */
app.put('/api/ops/buffer', requireAuth, async (req, res) => {
  const { buffer: newBuffer, editEntryId } = req.body;
  if (!newBuffer || typeof newBuffer !== 'object') {
    return res.status(400).json({ error: 'buffer object required' });
  }

  // Phase 3: country-scope enforcement — check every country key in the incoming buffer
  for (const ck of Object.keys(newBuffer)) {
    if (!validateCountry(ck)) continue; // malformed keys rejected downstream
    const _putScope = await _assertCountryAllowed(req.user, ck);
    if (!_putScope.ok) return res.status(_putScope.status).json({ error: _putScope.error });
  }

  // ── Edit-lock check ──────────────────────────────────────────────────────────
  // If the caller passes the entry id they are saving, check whether another user
  // holds a valid (non-expired) edit lock on that entry.
  if (editEntryId) {
    const liveBuffer = await fetchGitHubJson('data/ops/buffer.json', {});
    const EDIT_LOCK_TTL_MS = 15 * 60 * 1000; // 15 minutes
    const now = Date.now();
    outer: for (const ck of Object.keys(liveBuffer)) {
      for (const userEntries of Object.values(liveBuffer[ck] || {})) {
        const locked = (userEntries || []).find(e => e.id === editEntryId);
        if (!locked) continue;
        const { editingBy, editingLastActivityAt } = locked;
        if (
          editingBy &&
          editingBy.toLowerCase().trim() !== req.user.email.toLowerCase().trim() &&
          editingLastActivityAt &&
          (now - new Date(editingLastActivityAt).getTime()) < EDIT_LOCK_TTL_MS
        ) {
          return res.status(409).json({
            error: `This entry is currently being edited by ${editingBy}`,
            editingBy,
            editingLastActivityAt
          });
        }
        break outer;
      }
    }
  }

  const liveBuffer = await fetchGitHubJson('data/ops/buffer.json', {});
  for (const ck of Object.keys(newBuffer)) {
    const countryEntries = newBuffer[ck] || {};
    const liveEntries = liveBuffer[ck] || {};
    for (const [owner, entries] of Object.entries(countryEntries)) {
      const liveUserEntries = liveEntries[owner] || [];
      for (let index = 0; index < (entries || []).length; index++) {
        const entry = entries[index];
        const liveEntry = liveUserEntries.find(e => e.id === entry.id) || null;
        const isExistingWorkflow = entry?.type === 'update' || liveEntry?.type === 'update' || entry?.type === 'delete' || liveEntry?.type === 'delete';
        const originalProcessId = entry?.originalProcessId || entry?.process?.originalProcessId || liveEntry?.originalProcessId || liveEntry?.process?.originalProcessId || entry?.process?.id || liveEntry?.process?.id || null;
        if (!entry?.process) continue;
        if (isExistingWorkflow && !originalProcessId) {
          return res.status(400).json({
            error: 'originalProcessId must be preserved for existing process workflows.',
            code: 'MISSING_ORIGINAL_PROCESS_ID',
            details: {
              country: ck,
              owner,
              entryId: entry.id,
              type: entry.type || liveEntry?.type || null,
              processId: entry.process?.id || liveEntry?.process?.id || null,
              issue: entry.process?.issue || liveEntry?.process?.issue || null
            }
          });
        }
        if (liveEntry?.originalProcessId && originalProcessId !== liveEntry.originalProcessId) {
          return res.status(400).json({
            error: 'originalProcessId cannot be changed for an existing process workflow.',
            code: 'CHANGED_ORIGINAL_PROCESS_ID',
            details: {
              country: ck,
              owner,
              entryId: entry.id,
              type: entry.type || liveEntry?.type || null,
              processId: entry.process?.id || liveEntry?.process?.id || null,
              issue: entry.process?.issue || liveEntry?.process?.issue || null
            }
          });
        }
        if (entry.type === 'create' || entry.type === 'update') {
          const duplicate = await _findDuplicateIssueInCountry(
            ck,
            entry.process.issue,
            entry.type === 'update' ? originalProcessId : null,
            entry.id || null
          );
          if (duplicate) {
            return res.status(409).json({ ..._buildDuplicateError(ck, entry.process.issue), duplicate });
          }
        }
        if (originalProcessId) {
          entry.originalProcessId = originalProcessId;
          entry.process.originalProcessId = originalProcessId;
        }
      }
    }
  }

  await commitJsonToMainBranch('data/ops/buffer.json', newBuffer, 'ops: replace buffer');
  res.json({ success: true, buffer: newBuffer });
});

// ─── Edit-lock heartbeat ──────────────────────────────────────────────────────

/**
 * PATCH /api/ops/buffer/edit-lock
 * Acquires, refreshes, or releases an edit lock on a single buffer entry.
 *
 * Body:
 *   { country, user, index, action: "acquire" | "heartbeat" | "release" }
 *
 * Lock fields written to the entry:
 *   editingBy              — email of the user holding the lock
 *   editingLastActivityAt  — ISO timestamp, updated on every heartbeat/acquire
 *
 * Lock expiry: 15 minutes of inactivity (enforced by PUT /api/ops/buffer on save).
 *
 * Anyone can call acquire; if another user holds a non-expired lock the call
 * returns 409 so the frontend can show "Being edited by X".
 */
app.patch('/api/ops/buffer/edit-lock', requireAuth, async (req, res) => {
  const { country, user: targetUser, index, action } = req.body;
  const requester = req.user.email;

  if (!country || !targetUser || typeof index !== 'number' || !action) {
    return res.status(400).json({ error: 'country, user, index, and action are required' });
  }
  if (!validateCountry(country)) {
    return res.status(400).json({ error: 'Invalid country' });
  }
  if (!['acquire', 'heartbeat', 'release'].includes(action)) {
    return res.status(400).json({ error: 'action must be acquire, heartbeat, or release' });
  }
  // Phase 3: country-scope enforcement
  const _elScope = await _assertCountryAllowed(req.user, country);
  if (!_elScope.ok) return res.status(_elScope.status).json({ error: _elScope.error });

  const EDIT_LOCK_TTL_MS = 15 * 60 * 1000;
  const now = new Date();

  const buffer  = await fetchGitHubJson('data/ops/buffer.json', {});
  const entries = (buffer[country] && buffer[country][targetUser]) || [];
  const entry   = entries[index];

  if (!entry) return res.status(404).json({ error: 'Buffer entry not found' });

  const { editingBy, editingLastActivityAt } = entry;
  const lockAge = editingLastActivityAt
    ? now.getTime() - new Date(editingLastActivityAt).getTime()
    : Infinity;
  const lockHeldByOther = editingBy &&
    editingBy.toLowerCase().trim() !== requester.toLowerCase().trim() &&
    lockAge < EDIT_LOCK_TTL_MS;

  if (action === 'release') {
    // Only the lock holder or Admin may release
    if (editingBy && editingBy.toLowerCase().trim() !== requester.toLowerCase().trim() &&
        req.user.role !== 'Admin') {
      return res.status(403).json({ error: 'Only the lock holder or Admin can release this lock' });
    }
    delete entry.editingBy;
    delete entry.editingLastActivityAt;
    await commitJsonToMainBranch('data/ops/buffer.json', buffer,
      `ops: release edit lock on entry ${entry.id} by ${requester}`);
    return res.json({ success: true, action: 'released', entryId: entry.id });
  }

  if (action === 'acquire' && lockHeldByOther) {
    return res.status(409).json({
      error: `This entry is currently being edited by ${editingBy}`,
      editingBy,
      editingLastActivityAt,
      lockExpiresAt: new Date(new Date(editingLastActivityAt).getTime() + EDIT_LOCK_TTL_MS).toISOString()
    });
  }

  // acquire or heartbeat — set/refresh the lock
  entry.editingBy             = requester;
  entry.editingLastActivityAt = now.toISOString();

  await commitJsonToMainBranch('data/ops/buffer.json', buffer,
    `ops: ${action} edit lock on entry ${entry.id} by ${requester}`);

  res.json({
    success:              true,
    action,
    entryId:              entry.id,
    editingBy:            requester,
    editingLastActivityAt: now.toISOString(),
    lockExpiresAt:        new Date(now.getTime() + EDIT_LOCK_TTL_MS).toISOString()
  });
});

// ─── Process edit-lock endpoints ─────────────────────────────────────────────

/**
 * GET /api/ops/process/edit-lock
 * Returns the full process_edit_locks.json so the frontend can render
 * "being edited by X" indicators on process cards.
 * Phase 2: requireAuth added.
 */
app.get('/api/ops/process/edit-lock', requireAuth, async (req, res) => {
  const locks = await fetchGitHubJson(PROCESS_EDIT_LOCKS_PATH, {});
  res.json(locks);
});

/**
 * PATCH /api/ops/process/edit-lock
 * Acquires, refreshes, or releases a pre-save edit lock on a process item.
 * Stored in data/ops/process_edit_locks.json — completely separate from the
 * buffer edit lock which is stored on the buffer entry itself.
 *
 * Body: { country, processId, action: "acquire" | "heartbeat" | "release" }
 *
 * Lock fields written:
 *   editingBy              — email of the lock holder
 *   editingLastActivityAt  — ISO timestamp, refreshed on heartbeat / acquire
 *
 * Expiry: 15 minutes of inactivity (same TTL as buffer edit lock).
 */
/**
 * requireAuthBeacon — scoped variant of requireAuth that also accepts a JWT
 * from req.body.token. Used only on this endpoint so that navigator.sendBeacon
 * (which cannot set custom headers) can authenticate the release call on logout.
 * All other endpoints continue to use requireAuth (header-only).
 */
function requireAuthBeacon(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7)
    : (req.body?.token || null);
  if (!token) {
    return res.status(401).json({
      error: 'AUTH_REQUIRED',
      message: 'Authorization is required.'
    });
  }
  const result = verifyJwt(token);
  if (!result.ok) {
    return _rejectAuth(res, result);
  }
  req.user = { email: result.payload.email, role: result.payload.role };
  if (typeof _runScheduledPRExecutor === 'function') {
    _runScheduledPRExecutor().catch(() => {});
  }
  next();
}

app.patch('/api/ops/process/edit-lock', requireAuthBeacon, async (req, res) => {
  const { country, processId, action } = req.body;
  const requester = req.user.email;

  if (!country || !processId || !action) {
    return res.status(400).json({ error: 'country, processId, and action are required' });
  }
  if (!validateCountry(country)) {
    return res.status(400).json({ error: 'Invalid country' });
  }
  if (!['acquire', 'heartbeat', 'release'].includes(action)) {
    return res.status(400).json({ error: 'action must be acquire, heartbeat, or release' });
  }
  // Phase 3: country-scope enforcement
  const _pelScope = await _assertCountryAllowed(req.user, country);
  if (!_pelScope.ok) return res.status(_pelScope.status).json({ error: _pelScope.error });

  const now   = new Date();
  const locks = await fetchGitHubJson(PROCESS_EDIT_LOCKS_PATH, {});
  if (!locks[country]) locks[country] = {};

  const lock    = locks[country][processId] || {};
  const { editingBy, editingLastActivityAt } = lock;
  const lockAge = editingLastActivityAt
    ? now.getTime() - new Date(editingLastActivityAt).getTime()
    : Infinity;
  const norm = e => (e || '').toLowerCase().trim();
  const lockHeldByOther = editingBy &&
    norm(editingBy) !== norm(requester) &&
    lockAge < PROC_LOCK_TTL_MS;

  if (action === 'release') {
    // Only the lock holder or Admin may release
    if (editingBy && norm(editingBy) !== norm(requester) && req.user.role !== 'Admin') {
      return res.status(403).json({ error: 'Only the lock holder or Admin can release this lock' });
    }
    delete locks[country][processId];
    // Clean up empty country key
    if (!Object.keys(locks[country]).length) delete locks[country];
    await commitJsonToMainBranch(PROCESS_EDIT_LOCKS_PATH, locks,
      `ops: release process edit lock on ${processId} by ${requester}`);
    return res.json({ success: true, action: 'released', processId });
  }

  if (action === 'acquire' && lockHeldByOther) {
    return res.status(409).json({
      error: `This process is currently being edited by ${editingBy}`,
      editingBy,
      editingLastActivityAt,
      lockExpiresAt: new Date(new Date(editingLastActivityAt).getTime() + PROC_LOCK_TTL_MS).toISOString()
    });
  }

  // acquire or heartbeat — set/refresh the lock
  locks[country][processId] = {
    editingBy:             requester,
    editingLastActivityAt: now.toISOString()
  };

  await commitJsonToMainBranch(PROCESS_EDIT_LOCKS_PATH, locks,
    `ops: ${action} process edit lock on ${processId} by ${requester}`);

  res.json({
    success:               true,
    action,
    processId,
    editingBy:             requester,
    editingLastActivityAt: now.toISOString(),
    lockExpiresAt:         new Date(now.getTime() + PROC_LOCK_TTL_MS).toISOString()
  });
});

/**
 * POST /api/ops/cancel
 * Hard-deletes a single buffer entry. No history write, no audit log.
 *
 * Governance (Phase 8.6 correction): this endpoint can only ever succeed for
 * pre-PR draft entries — entries locked by a scheduled job or an open GitHub PR
 * are rejected (409) before reaching the splice. Pre-PR Buffer cleanup is NOT a
 * production lifecycle event and must not be logged as audit/rollback trail.
 * History/Logs audit begins when a real GitHub PR is created (see Reject Request
 * workflow — future phase).
 *
 * Permission rules:
 *   OL      → can only remove their OWN entries with status="pending"
 *   Manager → can remove any entry (pending or validated)
 *   Admin   → can remove any entry (pending or validated)
 */
app.post('/api/ops/cancel', requireAuth, async (req, res) => {
  const { country, user: targetUser, index } = req.body;
  const canceller     = req.user.email;
  const cancellerRole = req.user.role;

  if (!country || !targetUser || typeof index !== 'number') {
    return res.status(400).json({ error: 'country, user, and index are required' });
  }
  if (!validateCountry(country)) {
    return res.status(400).json({ error: 'Invalid country' });
  }
  // Phase 3: country-scope enforcement
  const _cancelScope = await _assertCountryAllowed(req.user, country);
  if (!_cancelScope.ok) return res.status(_cancelScope.status).json({ error: _cancelScope.error });

  const buffer  = await fetchGitHubJson('data/ops/buffer.json', {});
  const entries = (buffer[country] && buffer[country][targetUser]) || [];

  if (!entries[index]) {
    return res.status(404).json({ error: 'Buffer entry not found' });
  }

  const entry = entries[index];

  // ── Role-scoped permission check ─────────────────────────────────────────────
  // OL: own pending entries only; Manager: own OR OL-owned; Admin: all
  if (cancellerRole === 'OL') {
    const ownerEmail = (entry.user || targetUser || '').toLowerCase().trim();
    if (ownerEmail !== canceller.toLowerCase().trim()) {
      return res.status(403).json({ error: 'OL can only remove their own entries' });
    }
    if (entry.status === 'validated') {
      return res.status(403).json({ error: 'OL cannot remove a validated entry' });
    }
  } else if (cancellerRole === 'Manager') {
    const isOwnEntry = (entry.user || '').toLowerCase().trim() === canceller.toLowerCase().trim();
    if (!isOwnEntry) {
      const usersForCancel = await fetchGitHubJson('config/users.json', []);
      const entryOwnerUser = usersForCancel.find(
        u => u.email.toLowerCase().trim() === (entry.user || '').toLowerCase().trim()
      );
      const entryOwnerRole = entryOwnerUser?.role || 'OL';
      if (entryOwnerRole !== 'OL') {
        return res.status(403).json({ error: 'Manager can only remove own entries or OL entries' });
      }
    }
  }
  // Admin: no restriction

  // ── Validated-entry guard (all roles) ────────────────────────────────────────
  // Validated entries must not be cancelled regardless of caller role.
  if (entry.status === 'validated') {
    return res.status(403).json({ error: 'Validated entries cannot be cancelled. Unvalidate the entry first.' });
  }

  // ── Scheduled-PR lock guard ──────────────────────────────────────────────────
  const cancelSchedule = await fetchGitHubJson(PR_SCHEDULE_PATH, {});
  const cancelSchedJob = cancelSchedule[country];
  if (cancelSchedJob && Array.isArray(cancelSchedJob.entry_ids) && cancelSchedJob.entry_ids.includes(entry.id)) {
    return res.status(409).json({
      error: 'This entry is locked by a scheduled PR. Undo the scheduled PR before making changes.'
    });
  }

  // ── Open-PR lock guard ───────────────────────────────────────────────────────
  const cancelHistory = await fetchGitHubJson('data/ops/history.json', {});
  const cancelIsInOpenPR = (cancelHistory[country] || []).some(
    h => h.pr_status === 'pending_merge' && h.id === entry.id
  );
  if (cancelIsInOpenPR) {
    return res.status(409).json({
      error: 'This entry is locked by a scheduled or open PR. Undo the scheduled PR before making changes.'
    });
  }

  // Splice out — no history write, no audit log.
  // Pre-PR Buffer cleanup is not a production lifecycle event (see JSDoc above).
  entries.splice(index, 1);

  await commitJsonToMainBranch('data/ops/buffer.json', buffer, `ops: remove buffer entry ${entry.id} for ${country}`);

  res.json({ success: true, entry });
});

/**
 * POST /api/ops/validate
 * Toggles a buffer entry between status="pending" and status="validated".
 * The entry STAYS IN THE BUFFER — no history write, no PR trigger.
 * Entries only move to history after the 10-minute scheduled PR executor fires.
 *
 * "validated" is a Buffer READINESS state, not an approval state.
 * It means the entry has passed operational/readiness checks and is eligible
 * to be included in a Publish Request. It does not mean Admin-approved or
 * production-approved. The approval lifecycle starts only after a real GitHub
 * PR / Publish Request is created.
 *
 * Available to: OL, Manager, Admin (all three roles).
 * OL can validate any entry within their allowed countries.
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
  if (!['OL', 'Manager', 'Admin'].includes(req.user.role)) {
    return res.status(403).json({ error: 'Only OL, Manager or Admin can validate entries' });
  }
  // Phase 3: country-scope enforcement
  const _valScope = await _assertCountryAllowed(req.user, country);
  if (!_valScope.ok) return res.status(_valScope.status).json({ error: _valScope.error });

  const targetUser = req.body.user;
  if (!targetUser) return res.status(400).json({ error: 'user field required to identify buffer queue' });

  const buffer  = await fetchGitHubJson('data/ops/buffer.json', {});
  const entries = (buffer[country] && buffer[country][targetUser]) || [];
  const entry   = entries[index];

  if (!entry) {
    return res.status(404).json({ error: 'Buffer entry not found' });
  }

  // ── Role-scoped permission check ─────────────────────────────────────────────
  // OL: only own entries; Manager: own OR entries owned by an OL; Admin: all
  if (req.user.role !== 'Admin') {
    const usersForValidate = await fetchGitHubJson('config/users.json', []);
    const entryOwnerUser   = usersForValidate.find(
      u => u.email.toLowerCase().trim() === (entry.user || '').toLowerCase().trim()
    );
    const entryOwnerRole   = entryOwnerUser?.role || 'OL';

    if (req.user.role === 'OL') {
      if ((entry.user || '').toLowerCase().trim() !== validator.toLowerCase().trim()) {
        return res.status(403).json({ error: 'OL can only validate their own entries' });
      }
    } else if (req.user.role === 'Manager') {
      const isOwnEntry = (entry.user || '').toLowerCase().trim() === validator.toLowerCase().trim();
      if (!isOwnEntry && entryOwnerRole !== 'OL') {
        return res.status(403).json({ error: 'Manager can only validate own entries or OL entries' });
      }
    }
  }

  // ── Cross-validator override guard ───────────────────────────────────────────
  // If the entry is already validated by a DIFFERENT user, only Admin may
  // toggle it (unvalidate). This prevents Manager B from silently reversing
  // Manager A's validation decision.
  if (
    entry.status === 'validated' &&
    req.user.role !== 'Admin' &&
    (entry.validatedBy || '').toLowerCase().trim() !== validator.toLowerCase().trim()
  ) {
    return res.status(403).json({
      error: `This entry was validated by ${entry.validatedBy}. Only an Admin can reverse it.`
    });
  }

  if (_processingEntries.has(entry.id)) {
    return res.status(409).json({ error: 'Entry is already being processed' });
  }

  // ── Scheduled-PR lock guard ──────────────────────────────────────────────────
  // Reject modifications to entries that are already frozen by a scheduled PR.
  const schedule = await fetchGitHubJson(PR_SCHEDULE_PATH, {});
  const schedJob = schedule[country];
  if (schedJob && Array.isArray(schedJob.entry_ids) && schedJob.entry_ids.includes(entry.id)) {
    return res.status(409).json({
      error: 'This entry is locked by a scheduled PR. Undo the scheduled PR before making changes.'
    });
  }

  // ── Open-PR lock guard ───────────────────────────────────────────────────────
  // Reject modifications to entries already submitted into an open PR.
  const history = await fetchGitHubJson('data/ops/history.json', {});
  const isInOpenPR = (history[country] || []).some(
    h => h.pr_status === 'pending_merge' && h.id === entry.id
  );
  if (isInOpenPR) {
    return res.status(409).json({
      error: 'This entry is locked by a scheduled or open PR. Undo the scheduled PR before making changes.'
    });
  }

  _processingEntries.add(entry.id);

  try {
    const now = new Date().toISOString();

    if (entry.status === 'pending') {
      // pending → validated
      entry.status      = 'validated';
      entry.validatedAt = now;
      entry.validatedBy = validator;
    } else {
      // validated → pending (unvalidate)
      entry.status = 'pending';
      delete entry.validatedAt;
      delete entry.validatedBy;
    }

    // Single write — entry stays in buffer, status toggled in-place
    const committed = await commitJsonToMainBranch(
      'data/ops/buffer.json', buffer,
      `ops: ${entry.status === 'validated' ? 'validate' : 'unvalidate'} entry ${entry.id} for ${country}`
    );

    if (!committed) {
      console.error(`[OPS validate] GitHub write failed for entry "${entry.id}" — reverting in-memory change`);
      // Revert the in-memory status change so state is consistent on retry
      if (entry.status === 'validated') {
        entry.status = 'pending';
        delete entry.validatedAt;
        delete entry.validatedBy;
      } else {
        entry.status = 'validated';
      }
      return res.status(503).json({ error: 'GitHub write failed — please retry in a moment.' });
    }

    // Log validation events only (not unvalidations — only impactful events go to logs)
    if (entry.status === 'validated') {
      appendActivityLog({
        event:   'validation',
        by:      validator,
        country,
        entryId: entry.id,
        type:    entry.type,
        issue:   entry.process?.issue || entry.process?.id || '?'
      });
    }

    console.log(`[OPS validate] Entry "${entry.id}" → ${entry.status} by ${validator} for "${country}"`);
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
    status:      'approved',   // internal: 'approved' here means the rollback was actioned (not Buffer-validated)
    user:        req.user.email,
    validatedAt: now,          // internal: reuses validatedAt/By fields to record when/by whom rollback was confirmed
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

  appendActivityLog({
    event:       'rollback',
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
  if (req.user.role !== 'Admin') {
    return res.status(403).json({ error: 'Admin only — settings require Admin role' });
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
 * ⚠️  EMERGENCY OVERRIDE — Admin only.
 * Bypasses the normal 10-minute scheduled PR flow and immediately creates a PR
 * from all currently validated buffer entries for the given country.
 * Use only when the scheduled executor has failed or been skipped.
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
    return res.status(403).json({ error: 'Emergency override is Admin only' });
  }

  // Phase 1 kill switch — block emergency PR creation when disabled.
  if (DISABLE_PR_CREATION) {
    return res.status(503).json({ error: 'PR creation is currently disabled on this server.' });
  }

  try {
    // Read all buffer entries for this country
    const buffer       = await fetchGitHubJson('data/ops/buffer.json', {});
    const countryBuf   = buffer[country] || {};
    const allEntries   = Object.values(countryBuf).flat();
    // Admin-only route: scope is always unrestricted, but run through filter
    // for consistency so future role changes only need one place updated.
    const mergeUsers       = await fetchGitHubJson('config/users.json', []);
    const scopedForMerge   = _filterEntriesByPRScope(allEntries, mergeUsers, approver);
    const validatedEntries = scopedForMerge.filter(e => e.status === 'validated');
    // Pending entries are not passed — governance: pending does not block.

    // Run the same pre-flight check used by the scheduled executor
    const preflight = await _preflightPRCheck(country, validatedEntries);
    if (!preflight.ok) {
      return res.status(preflight.httpStatus || 400).json({ error: preflight.error });
    }

    console.log(`[OPS emergency-override] PR by ${approver} for "${country}" — ${validatedEntries.length} entries`);

    const prResult = await _createPRForCountry(country, validatedEntries, approver);

    if (!prResult.success) {
      // Scope violation: PR was auto-closed; return clear user-facing message
      if (prResult.scopeViolation) {
        return res.status(500).json({
          error: `PR creation was stopped because unexpected files would be included. Please contact an Admin.\nDetails: ${prResult.error}`
        });
      }
      throw new Error(prResult.error);
    }

    // Buffer entries only move to History after verified-clean PR creation
    await _moveBufToHistoryAfterPR(country, validatedEntries, prResult, approver);

    appendActivityLog({
      event:      'pr-created',
      by:         approver,
      country,
      branchName: prResult.branchName,
      prNumber:   prResult.prNumber,
      prUrl:      prResult.prUrl,
      entryCount: validatedEntries.length,
      trigger:    'emergency-override'
    });

    res.json({
      success:    true,
      message:    'Emergency PR created successfully',
      prUrl:      prResult.prUrl,
      prNumber:   prResult.prNumber,
      branchName: prResult.branchName
    });
  } catch (err) {
    console.error('[OPS emergency-override] Error:', err.message);
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
 * Parts D, E, F: also handles replacement/inheritance, promotion/demotion detection,
 * and assignment history recording.
 */
app.post('/api/admin/users', requireAuth, async (req, res) => {
  if (req.user.role !== 'Admin') {
    return res.status(403).json({ error: 'Only Admin can manage users' });
  }
  const { users, reason } = req.body;
  if (!Array.isArray(users) || users.length === 0) {
    return res.status(400).json({ error: 'users array of operations required' });
  }

  const before     = await fetchGitHubJson('config/users.json', []);
  const working    = before.map(u => ({ ...u }));
  const seenEmails = new Set(working.map(u => u.email.toLowerCase()));
  const batchSeen  = new Set();

  // Collect assignment events for post-save processing
  const assignmentEvents = [];
  // Collect inheritance transfers to fire after the users.json write
  const pendingInheritance = [];

  const norm = e => (e || '').toLowerCase().trim();

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

      // Record add events per country
      const newCountries = result.user.role === 'Admin' ? ['all'] : (result.user.countries || []);
      for (const c of newCountries) {
        assignmentEvents.push({
          action:       'added',
          userEmail:    result.user.email,
          userName:     result.user.name || null,
          role:         result.user.role,
          country:      c,
          changedBy:    req.user.email,
          reason:       reason || null
        });
      }

    } else if (opType === 'update') {
      if (existIdx === -1) {
        return res.status(404).json({ error: `User ${u.email} not found — use op="add" to create` });
      }
      const oldUser = working[existIdx];
      const result  = validateUserEntry(u);
      if (!result.ok) return res.status(400).json({ error: result.error });

      const oldRole      = oldUser.role;
      const newRole      = result.user.role;
      const oldCountries = Array.isArray(oldUser.countries) ? oldUser.countries : [];
      const newCountries = Array.isArray(result.user.countries) ? result.user.countries : [];

      working[existIdx] = result.user;

      // ── Part E: Promotion / demotion detection ──────────────────────────────
      // A user cannot hold two roles simultaneously.
      // Detect role change and record appropriate event.
      if (norm(oldRole) !== norm(newRole)) {
        const isPromotion = (oldRole === 'OL' && newRole === 'Manager') ||
                            (oldRole === 'Manager' && newRole === 'Admin') ||
                            (oldRole === 'OL' && newRole === 'Admin');
        const isDemotion  = !isPromotion;
        const eventAction = isPromotion ? 'promoted' : 'demoted';

        // Record the role change per affected country
        const allAffected = new Set([...oldCountries, ...newCountries]);
        for (const c of allAffected) {
          assignmentEvents.push({
            action:           eventAction,
            userEmail:        result.user.email,
            userName:         result.user.name || null,
            role:             newRole,
            country:          c,
            previousRole:     oldRole,
            previousCountries: oldCountries,
            newRole,
            newCountries,
            changedBy:        req.user.email,
            reason:           reason || null
          });
        }

        // Part D/E: OL assignment ends — trigger inheritance for countries they
        // are leaving (countries in old role but not new role, or all if role changed)
        const leavingCountries = oldRole !== 'Admin'
          ? oldCountries.filter(c => !newCountries.includes(c) || oldRole !== newRole)
          : [];

        for (const c of leavingCountries) {
          // working already has the updated user — resolve inheritance from post-update state
          const inheritance = _resolveInheritance(result.user.email, oldRole, c, working);
          if (inheritance.inheritedBy) {
            pendingInheritance.push({
              departedEmail: result.user.email,
              inheritedBy:   inheritance.inheritedBy,
              country:       c,
              changedBy:     req.user.email
            });
            assignmentEvents.push({
              action:        'ownership-inherited',
              userEmail:     inheritance.inheritedBy,
              previousOwner: result.user.email,
              role:          oldRole,
              country:       c,
              changedBy:     req.user.email,
              reason:        `${eventAction} — operational ownership transferred`
            });
          } else {
            // No inheritor: flag as orphaned in audit
            assignmentEvents.push({
              action:    'ownership-orphaned',
              userEmail: result.user.email,
              role:      oldRole,
              country:   c,
              changedBy: req.user.email,
              reason:    `${eventAction} — no peer available to inherit, Admin resolution required`
            });
          }
        }

      } else {
        // Same role — record country scope changes
        const removedCountries = oldCountries.filter(c => !newCountries.some(nc => norm(nc) === norm(c)));
        const addedCountries   = newCountries.filter(c => !oldCountries.some(oc => norm(oc) === norm(c)));

        for (const c of removedCountries) {
          assignmentEvents.push({
            action:       'removed',
            userEmail:    result.user.email,
            userName:     result.user.name || null,
            role:         newRole,
            country:      c,
            changedBy:    req.user.email,
            reason:       reason || null
          });
          // Trigger inheritance for removed country-role
          const inheritance = _resolveInheritance(result.user.email, newRole, c, working);
          if (inheritance.inheritedBy) {
            pendingInheritance.push({
              departedEmail: result.user.email,
              inheritedBy:   inheritance.inheritedBy,
              country:       c,
              changedBy:     req.user.email
            });
            assignmentEvents.push({
              action:        'ownership-inherited',
              userEmail:     inheritance.inheritedBy,
              previousOwner: result.user.email,
              role:          newRole,
              country:       c,
              changedBy:     req.user.email,
              reason:        'country removed from user assignment'
            });
          }
        }
        for (const c of addedCountries) {
          assignmentEvents.push({
            action:       'added',
            userEmail:    result.user.email,
            userName:     result.user.name || null,
            role:         newRole,
            country:      c,
            changedBy:    req.user.email,
            reason:       reason || null
          });
        }
      }

    } else if (opType === 'remove') {
      if (existIdx === -1) {
        return res.status(404).json({ error: `User ${u.email} not found` });
      }
      if (emailKey === req.user.email.toLowerCase()) {
        return res.status(400).json({ error: 'You cannot remove your own account' });
      }
      const removedUser = working[existIdx];
      working.splice(existIdx, 1);
      seenEmails.delete(emailKey);

      // Record removed events per country and trigger inheritance
      const removedCountries = removedUser.role === 'Admin'
        ? ['all']
        : (Array.isArray(removedUser.countries) ? removedUser.countries : []);

      for (const c of removedCountries) {
        assignmentEvents.push({
          action:       'removed',
          userEmail:    removedUser.email,
          userName:     removedUser.name || null,
          role:         removedUser.role,
          country:      c,
          changedBy:    req.user.email,
          reason:       reason || null
        });
        if (removedUser.role === 'OL' || removedUser.role === 'Manager') {
          const inheritance = _resolveInheritance(removedUser.email, removedUser.role, c, working);
          if (inheritance.inheritedBy) {
            pendingInheritance.push({
              departedEmail: removedUser.email,
              inheritedBy:   inheritance.inheritedBy,
              country:       c,
              changedBy:     req.user.email
            });
            assignmentEvents.push({
              action:        'ownership-inherited',
              userEmail:     inheritance.inheritedBy,
              previousOwner: removedUser.email,
              role:          removedUser.role,
              country:       c,
              changedBy:     req.user.email,
              reason:        'user removed from system'
            });
          } else {
            assignmentEvents.push({
              action:    'ownership-orphaned',
              userEmail: removedUser.email,
              role:      removedUser.role,
              country:   c,
              changedBy: req.user.email,
              reason:    'user removed — no peer available to inherit, Admin resolution required'
            });
          }
        }
      }
    }
  }

  const activeAdminCount = working.filter(u => u.role === 'Admin').length;
  if (activeAdminCount === 0) {
    return res.status(400).json({
      error: MIN_ADMIN_ERROR_MESSAGE,
      opsMessage: MIN_ADMIN_ERROR_MESSAGE
    });
  }

  await commitJsonToMainBranch('config/users.json', working, `admin: update users (${users.length} op(s)) by ${req.user.email}`);

  appendAdminAudit({
    action:  'users-updated',
    by:      req.user.email,
    before,
    after:   working,
    opCount: users.length
  });

  // Fire-and-forget: assignment history and inheritance transfers
  if (assignmentEvents.length > 0) {
    appendAssignmentHistory(assignmentEvents).catch(() => {});
  }
  for (const t of pendingInheritance) {
    _transferOrphanedBufferEntries(t.departedEmail, t.inheritedBy, t.country, t.changedBy).catch(() => {});
  }

  res.json({ success: true, count: working.length, assignmentEvents: assignmentEvents.length });
});

/**
 * GET /api/ops/assignment-history
 * Returns assignment_history.json — Admin only.
 * Supports the inheritance audit trail (Part F).
 */
app.get('/api/ops/assignment-history', requireAuth, async (req, res) => {
  if (req.user.role !== 'Admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  res.json(await fetchGitHubJson(ASSIGNMENT_HISTORY_PATH, []));
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

// ─── Activity Log helper ──────────────────────────────────────────────────────
/**
 * Appends an entry to data/logs/activity_logs.json on GitHub.
 * Called for impactful events: validation, PR scheduled, PR schedule cancelled,
 * PR created, PR merged, PR refused, rollback.
 * Never throws — log failure must never block the successful response.
 */
async function appendActivityLog(entry) {
  try {
    const ghPath = 'data/logs/activity_logs.json';
    const log    = await fetchGitHubJson(ghPath, []);
    log.push({ ...entry, timestamp: new Date().toISOString() });
    await commitJsonToMainBranch(ghPath, log, `log: ${entry.event || 'event'}`);
  } catch (err) {
    console.error('[activity log] write failed:', err.message);
  }
}

// ─── Shared helper: move validated buffer entries → history after PR ──────────
/**
 * After a PR is successfully created, removes the validated entries from the
 * buffer and writes them to history with pr_status="pending_merge".
 * Re-fetches both files fresh immediately before writing to avoid SHA conflicts.
 */
async function _moveBufToHistoryAfterPR(country, validatedEntries, prResult, triggeredBy) {
  const entryIds = new Set(validatedEntries.map(e => e.id));
  const now      = new Date().toISOString();

  // Re-fetch both files fresh — the PR creation round-trips took time
  const [buffer, history] = await Promise.all([
    fetchGitHubJson('data/ops/buffer.json',  {}),
    fetchGitHubJson('data/ops/history.json', {})
  ]);

  // Remove matched entries from buffer
  if (buffer[country]) {
    for (const userEmail of Object.keys(buffer[country])) {
      buffer[country][userEmail] = (buffer[country][userEmail] || []).filter(
        e => !entryIds.has(e.id)
      );
    }
  }

  // Append to history as pending_merge
  if (!history[country]) history[country] = [];
  for (const entry of validatedEntries) {
    history[country].push({
      ...entry,
      pr_status:   'pending_merge',
      prUrl:       prResult.prUrl,
      prNumber:    prResult.prNumber,
      branchName:  prResult.branchName,
      prCreatedAt: now,
      prCreatedBy: triggeredBy,
      submittedAt: now,   // fix: was missing — now always populated on PR creation
      submittedBy: triggeredBy
    });
  }

  // Sequential writes to avoid SHA conflicts on the same branch
  await commitJsonToMainBranch('data/ops/buffer.json',  buffer,  `ops: clear ${country} buffer after PR #${prResult.prNumber}`);
  await commitJsonToMainBranch('data/ops/history.json', history, `ops: add ${country} entries as pending_merge for PR #${prResult.prNumber}`);
}

// ─── PR Schedule helpers ──────────────────────────────────────────────────────
// In production this is always 2 minutes.
// Set PR_DELAY_MS_OVERRIDE (milliseconds) in the environment only for test/staging
// environments where you need the countdown to fire immediately.
// Example: PR_DELAY_MS_OVERRIDE=5000  → 5-second countdown.
const PR_DELAY_MS = process.env.PR_DELAY_MS_OVERRIDE
  ? Math.max(0, parseInt(process.env.PR_DELAY_MS_OVERRIDE, 10))
  : 2 * 60 * 1000; // 2 minutes
const PR_SCHEDULE_PATH = 'data/ops/pr_schedule.json';

/**
 * Checks whether an open (not merged, not closed) PR exists for the given
 * country by searching GitHub for PRs from branches matching the OPS branch
 * naming patterns.
 *
 * Returns a structured result — NEVER returns a permissive result on error:
 *   { ok: true,  hasOpen: boolean, activePR?: { prNumber, branchName, prUrl } }
 *   { ok: false, error: string }      — GitHub unreachable or non-2xx; callers MUST block
 *
 * Matches both the current pattern  ops/<country>/<timestamp>
 * and the legacy pattern            <country>_<timestamp>
 * so that open PRs created before the naming change are still detected.
 *
 * Safety rule: any caller that receives ok===false must block the operation.
 * Failing open (allowing PR creation when GitHub is unreachable) risks creating
 * duplicate PRs. Failing safe (blocking when uncertain) is always correct.
 */
async function _hasOpenPRForCountry(country) {
  try {
    const res = await fetch(
      `https://api.github.ibm.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/pulls?state=open&per_page=50`,
      { headers: ghHeaders() }
    );
    if (!res.ok) {
      return { ok: false, error: `GitHub PR list returned HTTP ${res.status}` };
    }
    const prs = await res.json();
    const match = prs.find(pr => {
      const ref = pr.head && pr.head.ref ? pr.head.ref : '';
      // Current naming: ops/<country>/...
      if (ref.startsWith(`ops/${country}/`)) return true;
      // Legacy naming: <country>_YYYYMMDD_HHMM
      if (ref.startsWith(`${country}_`)) return true;
      return false;
    });
    if (!match) return { ok: true, hasOpen: false };
    return {
      ok: true,
      hasOpen: true,
      activePR: {
        prNumber:   match.number,
        branchName: match.head.ref,
        prUrl:      match.html_url
      }
    };
  } catch (err) {
    return { ok: false, error: err.message || 'Network error contacting GitHub PR API' };
  }
}

/**
 * Appends a new batch of validated entries to an existing open PR branch.
 *
 * Mode B — Append to Active PR:
 *   - Reads the current process JSON from the live target branch (GITHUB_BRANCH / main).
 *   - Applies the new validated entries on top.
 *   - Fetches the latest commit SHA of the existing PR branch (not HEAD of main).
 *   - Commits the updated process JSON to that existing PR branch.
 *   - Posts a comment to the PR with a batch summary.
 *
 * Serialization: the caller must ensure only one append runs per country at a
 * time (the schedule job mechanism already guarantees this — the executor is
 * single-threaded per country via the _executorRunning guard).
 *
 * @param {string} country          - country key
 * @param {Array}  newEntries       - validated entries to append
 * @param {string} triggeredBy      - email of user who triggered the append
 * @param {{ prNumber, branchName, prUrl }} activePR - the open PR to append to
 * @param {string} batchId          - unique batch identifier for audit
 * @returns {{ success, prNumber?, prUrl?, branchName?, batchId?, error? }}
 */
/**
 * Pre-flight checks for Mode B (append to active PR) executed at executor time.
 *
 * Validates:
 *   1. GITHUB_TOKEN configured
 *   2. Active PR branch still exists on GitHub
 *   3. The PR is still open (not merged / not closed between schedule and execution)
 *   4. No validated entries are empty
 *   5. All allowed file paths — only data/processes/{country}.json
 *   6. Executor-time duplicate check: reads existing issues from the PR branch
 *      content and from history, blocking any overlap with the new batch
 *
 * Returns { ok: true } or { ok: false, error: string }
 */
async function _preflightAppendCheck(country, newEntries, activePR) {
  if (!GITHUB_TOKEN) {
    return { ok: false, error: 'GITHUB_TOKEN not configured on server' };
  }

  const { prNumber, branchName } = activePR;
  const allowedFilePath = `data/processes/${country}.json`;

  // 1. All entries must target the allowed file path only
  const badEntries = newEntries.filter(e => {
    // entries write to data/processes/{country}.json — verify the country matches
    return !_isAllowedPRPath(allowedFilePath);
  });
  if (badEntries.length > 0) {
    return { ok: false, error: `Append entries target a disallowed file path` };
  }

  // 2. Branch must exist
  const branchSha = await _getLatestBranchSha(branchName);
  if (!branchSha) {
    return { ok: false, error: `PR branch "${branchName}" no longer exists on GitHub` };
  }

  // 3. PR must still be open
  try {
    const prRes = await fetch(
      `https://api.github.ibm.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/pulls/${prNumber}`,
      { headers: ghHeaders() }
    );
    if (!prRes.ok) {
      return { ok: false, error: `GitHub returned HTTP ${prRes.status} checking PR #${prNumber}` };
    }
    const pr = await prRes.json();
    if (pr.state !== 'open') {
      return { ok: false, error: `PR #${prNumber} is no longer open (state: ${pr.state}) — cannot append` };
    }
  } catch (err) {
    return { ok: false, error: `Could not verify PR #${prNumber} state: ${err.message}` };
  }

  // 4. At least one entry
  if (!newEntries || newEntries.length === 0) {
    return { ok: false, error: 'No validated entries for append batch' };
  }

  // 5. Executor-time duplicate check against PR branch content
  // Read the process JSON from the PR branch (authoritative) and build a Set of
  // existing issue/id values. Also cross-check against history pending_merge entries
  // for this PR (covers batches already moved from buffer).
  const newIssues = new Set(
    newEntries.map(e => e.process?.issue || e.process?.id).filter(Boolean)
  );

  // 5a. Check PR branch content
  const branchData = await _readProcessDataFromBranch(country, branchName);
  if (branchData) {
    const branchIssues = new Set(
      branchData.data.map(p => p.issue || p.id).filter(Boolean)
    );
    // Compare against main branch to find net-new issues already on the PR branch
    // that weren't there before (i.e. added by previous batches).
    // We do this by comparing against main content.
    const mainData = await readProcessData(country);
    const mainIssues = new Set(
      (mainData?.data || []).map(p => p.issue || p.id).filter(Boolean)
    );
    // Issues present on the PR branch but NOT on main were added by batch 1
    const addedByPR = new Set([...branchIssues].filter(i => !mainIssues.has(i)));
    // Also issues on main that are missing from PR branch were deleted by batch 1
    // (they shouldn't be re-added/re-deleted in batch 2 — flag as conflict)
    const deletedByPR = new Set([...mainIssues].filter(i => !branchIssues.has(i)));

    const conflictCreate = newEntries.filter(e =>
      e.type === 'create' && (e.process?.issue || e.process?.id) &&
      addedByPR.has(e.process?.issue || e.process?.id)
    );
    const conflictDelete = newEntries.filter(e =>
      e.type === 'delete' && (e.process?.issue || e.process?.id) &&
      deletedByPR.has(e.process?.issue || e.process?.id)
    );
    const conflictUpdate = newEntries.filter(e =>
      e.type === 'update' && (e.process?.issue || e.process?.id) &&
      addedByPR.has(e.process?.issue || e.process?.id)
    );

    const conflicts = [...conflictCreate, ...conflictDelete, ...conflictUpdate];
    if (conflicts.length > 0) {
      const list = conflicts.map(e => `${e.type.toUpperCase()}:${e.process?.issue || e.process?.id}`).join(', ');
      return {
        ok: false,
        error: `Executor-time conflict: the following issues already have changes on PR branch "${branchName}": ${list}`
      };
    }
  }

  // 5b. Check history for pending_merge entries for this PR (belt-and-suspenders)
  try {
    const history = await fetchGitHubJson('data/ops/history.json', {});
    const activePRHistory = (history[country] || []).filter(
      h => h.prNumber === prNumber && h.pr_status === 'pending_merge'
    );
    const historyIssues = new Set(
      activePRHistory.map(h => h.process?.issue || h.process?.id).filter(Boolean)
    );
    const histDuplicates = [...newIssues].filter(i => historyIssues.has(i));
    if (histDuplicates.length > 0) {
      return {
        ok: false,
        error: `Executor-time duplicate: issue(s) already in PR #${prNumber} history: ${histDuplicates.join(', ')}`
      };
    }
  } catch (err) {
    // Non-fatal — log and continue; branch-content check above is the primary guard
    console.warn(`[PR append preflight] History duplicate check failed: ${err.message}`);
  }

  return { ok: true };
}

async function _appendToActivePR(country, newEntries, triggeredBy, activePR, batchId) {
  if (DISABLE_PR_CREATION) {
    return { success: false, error: 'PR creation is disabled on this server (DISABLE_PR_CREATION=true)' };
  }

  const { prNumber, branchName, prUrl } = activePR;
  const allowedFilePath = `data/processes/${country}.json`;

  console.log(`[OPS PR append] ── Starting append to PR #${prNumber} ──────────────────`);
  console.log(`[OPS PR append]   country    : ${country}`);
  console.log(`[OPS PR append]   branch     : ${branchName}`);
  console.log(`[OPS PR append]   entries    : ${newEntries.length}`);
  console.log(`[OPS PR append]   batchId    : ${batchId}`);
  console.log(`[OPS PR append]   triggered  : ${triggeredBy}`);

  try {
    // ── Step 1: Read current process data from the PR branch (not main) ───────
    // CRITICAL: we must read from branchName, not from GITHUB_BRANCH (main).
    // If batch 1 already committed changes to the PR branch, reading from main
    // would lose those changes and batch 2 would overwrite them.
    const processesData = await _readProcessDataFromBranch(country, branchName);
    if (!processesData) throw new Error(`No process data found on PR branch "${branchName}" for country "${country}"`);
    console.log(`[OPS PR append] Read ${processesData.data.length} processes from branch "${branchName}"`);

    // ── Step 2: Apply new entries on top of the PR branch content ─────────────
    const arr = processesData.data.map(p => ({ ...p }));
    for (const h of newEntries) {
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
    ) + '\n';

    // ── Step 3: Commit to the existing PR branch ──────────────────────────────
    // commitFileToOPSBranch reads the file SHA from `?ref=branchName` so the
    // new commit stacks correctly on top of the previous batch.
    const commitResult = await commitFileToOPSBranch(
      branchName,
      allowedFilePath,
      processJson,
      `ops: append batch ${batchId} to ${country} PR #${prNumber} — ${newEntries.length} change(s) by ${triggeredBy}`
    );
    if (!commitResult.ok) {
      throw new Error(`Commit to PR branch failed: ${commitResult.error}`);
    }
    console.log(`[OPS PR append] Committed batch ${batchId} to branch ${branchName}`);

    // ── Step 4: Post a comment to the PR with batch summary ───────────────────
    const now = new Date();
    const changeLines = newEntries
      .map(h => `- ${h.type.toUpperCase()}: ${h.process?.issue || h.process?.id || '?'}`)
      .join('\n');
    const commentBody =
      `**[OPS Append — Batch ${batchId}]**\n\n` +
      `Country: ${country.toUpperCase()}\n` +
      `Added by: ${triggeredBy}\n` +
      `Added at: ${now.toISOString()}\n` +
      `Entries: ${newEntries.length}\n\n` +
      `Changes:\n${changeLines}`;

    try {
      await fetch(
        `https://api.github.ibm.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/issues/${prNumber}/comments`,
        {
          method: 'POST',
          headers: ghHeaders(),
          body: JSON.stringify({ body: commentBody })
        }
      );
      console.log(`[OPS PR append] Posted batch summary comment to PR #${prNumber}`);
    } catch (commentErr) {
      // Non-fatal — comment failure must not abort the append
      console.warn(`[OPS PR append] Could not post comment to PR #${prNumber}: ${commentErr.message}`);
    }

    return { success: true, prNumber, prUrl, branchName, batchId };

  } catch (err) {
    console.error(`[OPS PR append] _appendToActivePR failed for "${country}" PR #${prNumber}:`, err.message);
    return { success: false, error: err.message, prNumber, branchName, batchId };
  }
}

/**
 * Moves buffer entries to history after a successful append to an active PR.
 * Identical contract to _moveBufToHistoryAfterPR but marks entries with
 * append-specific metadata: batchId, appendedAt, appendedBy.
 */
async function _moveBufToHistoryAfterAppend(country, appendedEntries, activePR, triggeredBy, batchId) {
  const entryIds = new Set(appendedEntries.map(e => e.id));
  const now      = new Date().toISOString();

  const [buffer, history] = await Promise.all([
    fetchGitHubJson('data/ops/buffer.json',  {}),
    fetchGitHubJson('data/ops/history.json', {})
  ]);

  // Remove matched entries from buffer
  if (buffer[country]) {
    for (const userEmail of Object.keys(buffer[country])) {
      buffer[country][userEmail] = (buffer[country][userEmail] || []).filter(
        e => !entryIds.has(e.id)
      );
    }
  }

  // Append to history as pending_merge (inheriting the same active PR)
  if (!history[country]) history[country] = [];
  for (const entry of appendedEntries) {
    history[country].push({
      ...entry,
      pr_status:   'pending_merge',
      prUrl:       activePR.prUrl,
      prNumber:    activePR.prNumber,
      branchName:  activePR.branchName,
      batchId,
      appendedAt:  now,
      appendedBy:  triggeredBy,
      submittedAt: now,
      submittedBy: triggeredBy
    });
  }

  await commitJsonToMainBranch('data/ops/buffer.json',  buffer,  `ops: clear ${country} buffer after append to PR #${activePR.prNumber} (batch ${batchId})`);
  await commitJsonToMainBranch('data/ops/history.json', history, `ops: add ${country} batch ${batchId} as pending_merge for PR #${activePR.prNumber}`);
}

// ─── PR Schedule routes ───────────────────────────────────────────────────────

/**
 * GET /api/ops/pr/schedule
 * Returns the full pr_schedule.json so the frontend can render countdown timers.
 * Phase 2: requireAuth added.
 */
app.get('/api/ops/pr/schedule', requireAuth, async (req, res) => {
  await _maybeTriggerScheduledPRs(); // lazy hybrid trigger
  res.json(await fetchGitHubJson(PR_SCHEDULE_PATH, {}));
});

/**
 * POST /api/ops/pr/schedule
 * Schedules a PR for a country (2-minute delayed creation).
 * All roles (OL, Manager, Admin) may call this.
 *
 * Mode A — Create PR (no active PR exists):
 *   - Blocked if any scoped entry is still "pending"
 *   - Blocked if a job is already scheduled for this country
 *   - Creates a new scheduled PR job
 *
 * Mode B — Append to Active PR (open PR already exists):
 *   - NOT blocked by the open PR
 *   - Blocked if any scoped entry is still "pending"
 *   - Blocked if a job is already scheduled for this country
 *   - Blocks duplicate process issues already present in the active PR's history
 *   - Creates a scheduled append job referencing the active PR
 */
app.post('/api/ops/pr/schedule', requireAuth, async (req, res) => {
  await _maybeTriggerScheduledPRs(); // lazy hybrid trigger

  const { country } = req.body;
  if (!country || !validateCountry(country)) {
    return res.status(400).json({ error: 'Valid country is required' });
  }
  if (!['OL', 'Manager', 'Admin'].includes(req.user.role)) {
    return res.status(403).json({ error: 'Only OL, Manager or Admin can schedule a PR' });
  }
  // Phase 3: country-scope enforcement
  const _schedScope = await _assertCountryAllowed(req.user, country);
  if (!_schedScope.ok) return res.status(_schedScope.status).json({ error: _schedScope.error });

  // Phase 1 kill switch — block scheduling when PR creation is disabled.
  if (DISABLE_PR_CREATION) {
    return res.status(503).json({ error: 'PR creation is currently disabled on this server.' });
  }

  const [buffer, schedule] = await Promise.all([
    fetchGitHubJson('data/ops/buffer.json', {}),
    fetchGitHubJson(PR_SCHEDULE_PATH, {})
  ]);

  // Block if already scheduled (applies to both Mode A and Mode B)
  if (schedule[country]) {
    return res.status(409).json({ error: 'A PR is already scheduled for this country', job: schedule[country] });
  }

  // Check for open PR — determines mode (A = create new, B = append)
  const prCheck = await _hasOpenPRForCountry(country);
  if (!prCheck.ok) {
    return res.status(502).json({ error: `Cannot verify open PRs on GitHub: ${prCheck.error}` });
  }

  const isAppendMode = prCheck.hasOpen;
  const activePR     = isAppendMode ? prCheck.activePR : null;

  // Collect entries for this country, scoped to the triggering user's role.
  // Governance: only validated entries are included in the Publish Request.
  // Pending/unvalidated entries in scope remain in Buffer and do not block creation.
  const countryBuf     = buffer[country] || {};
  const allEntries     = Object.values(countryBuf).flat();
  const scheduleUsers  = await fetchGitHubJson('config/users.json', []);
  const scopedEntries  = _filterEntriesByPRScope(allEntries, scheduleUsers, req.user.email);
  const validatedCount = scopedEntries.filter(e => e.status === 'validated').length;

  if (!validatedCount) {
    return res.status(400).json({ error: 'No validated entries to create a PR for' });
  }
  // Pending entries are intentionally NOT checked here — they remain in Buffer
  // and are excluded from the Publish Request. See governance rule §11.3-5.

  // Mode B duplicate process issue check
  // Checks three sources for issues already claimed by the active PR:
  //   1. history.json — entries already executed and moved to history (primary source)
  //   2. pr_schedule.json — a prior batch job scheduled but not yet executed
  //      Note: the schedule[country] guard above already blocks two concurrent jobs,
  //      so source 2 can only be non-empty if a race condition occurred.
  //      Including it here is belt-and-suspenders.
  // The executor also runs _preflightAppendCheck which reads the authoritative
  // PR branch content at execution time (the final safety net).
  if (isAppendMode) {
    const history = await fetchGitHubJson('data/ops/history.json', {});

    // Source 1: history entries pending_merge for this PR
    const activePRHistory = (history[country] || []).filter(
      h => h.prNumber === activePR.prNumber && h.pr_status === 'pending_merge'
    );
    const activePRIssues = new Set(
      activePRHistory.map(h => h.process?.issue || h.process?.id).filter(Boolean)
    );

    // Source 2: any previously scheduled (but not yet executed) append batch for
    // the same PR in pr_schedule.json — derive its issues from the buffer entry_ids
    // cross-referenced against the buffer. In practice the schedule[country] guard
    // above prevents two live jobs, but we check anyway.
    // (schedule was already loaded above)
    const priorJob = schedule[country]; // null — already blocked above, but defensively:
    if (priorJob && priorJob.mode === 'append' && priorJob.active_pr?.prNumber === activePR.prNumber) {
      const priorEntryIds = new Set(priorJob.entry_ids || []);
      const countryBufForCheck = buffer[country] || {};
      Object.values(countryBufForCheck).flat()
        .filter(e => priorEntryIds.has(e.id))
        .forEach(e => {
          const issue = e.process?.issue || e.process?.id;
          if (issue) activePRIssues.add(issue);
        });
    }

    const newValidated = scopedEntries.filter(e => e.status === 'validated');
    const duplicates   = newValidated.filter(e => {
      const issue = e.process?.issue || e.process?.id;
      return issue && activePRIssues.has(issue);
    });
    if (duplicates.length > 0) {
      const issueList = duplicates.map(e => e.process?.issue || e.process?.id).join(', ');
      return res.status(409).json({
        error: `Duplicate process issue(s) already in active PR #${activePR.prNumber}: ${issueList}. Duplicate submission is not allowed.`,
        duplicateIssues: duplicates.map(e => e.process?.issue || e.process?.id),
        activePRNumber:  activePR.prNumber
      });
    }
  }

  // Snapshot the IDs of the validated entries included in this batch.
  // Used by the frontend to freeze exactly those entries during countdown.
  const validatedEntryIds = scopedEntries
    .filter(e => e.status === 'validated')
    .map(e => e.id)
    .filter(Boolean);

  const now     = new Date();
  const batchId = `batch_${country}_${now.getTime()}`;

  const job = {
    country,
    mode:          isAppendMode ? 'append' : 'create',
    scheduled_at:  now.toISOString(),
    execute_after: new Date(now.getTime() + PR_DELAY_MS).toISOString(),
    created_by:    req.user.email,
    delay_ms:      PR_DELAY_MS,
    entry_count:   validatedCount,
    entry_ids:     validatedEntryIds,
    trigger_role:  req.user.role,
    batch_id:      batchId,
    ...(isAppendMode ? { active_pr: activePR } : {})
  };

  schedule[country] = job;
  await commitJsonToMainBranch(PR_SCHEDULE_PATH, schedule, `ops: schedule ${isAppendMode ? 'append' : 'PR'} for ${country} by ${req.user.email}`);

  appendActivityLog({
    event:       isAppendMode ? 'pr-append-scheduled' : 'pr-scheduled',
    by:          req.user.email,
    country,
    execute_after: job.execute_after,
    entryCount:  validatedCount,
    batchId,
    ...(isAppendMode ? { activePRNumber: activePR.prNumber } : {})
  });

  console.log(`[PR schedule] Scheduled ${isAppendMode ? `append (batch ${batchId}) to PR #${activePR.prNumber}` : 'PR'} for "${country}" to execute after ${job.execute_after}`);
  res.json({ success: true, job });
});

/**
 * DELETE /api/ops/pr/schedule/:country
 * Cancels (undoes) a scheduled PR job. Available during the 2-minute window.
 * All roles may undo a PR they can see.
 *
 * Audit trail (Phase 8.6): a matching 'pr-schedule-cancelled' (Mode A) or
 * 'pr-append-schedule-cancelled' (Mode B) event is written to activity_logs.json.
 * The corresponding 'pr-scheduled' / 'pr-append-scheduled' event was already written
 * when the schedule was created — the cancellation log completes the audit pair.
 * Mode B: the underlying GitHub PR still exists even though the append was undone.
 */
app.delete('/api/ops/pr/schedule/:country', requireAuth, async (req, res) => {
  const country = (req.params.country || '').toLowerCase();
  if (!validateCountry(country)) {
    return res.status(400).json({ error: 'Invalid country' });
  }
  // Phase 3: country-scope enforcement
  const _undoScope = await _assertCountryAllowed(req.user, country);
  if (!_undoScope.ok) return res.status(_undoScope.status).json({ error: _undoScope.error });

  const schedule = await fetchGitHubJson(PR_SCHEDULE_PATH, {});
  if (!schedule[country]) {
    return res.status(404).json({ error: 'No scheduled PR found for this country' });
  }

  const job = schedule[country];
  delete schedule[country];
  await commitJsonToMainBranch(PR_SCHEDULE_PATH, schedule, `ops: undo PR schedule for ${country} by ${req.user.email}`);

  // Write audit log — fire-and-forget; failure must not block the success response.
  const isAppend = job.mode === 'append';
  appendActivityLog({
    event:         isAppend ? 'pr-append-schedule-cancelled' : 'pr-schedule-cancelled',
    by:            req.user.email,
    role:          req.user.role,
    country,
    batchId:       job.batch_id    || null,
    entryCount:    job.entry_count || 0,
    entryIds:      job.entry_ids   || [],
    scheduledAt:   job.scheduled_at   || null,
    executeAfter:  job.execute_after  || null,
    originalCreatedBy: job.created_by || null,
    ...(isAppend ? {
      activePRNumber: job.active_pr?.prNumber || null,
      activePRUrl:    job.active_pr?.prUrl    || null
    } : {})
  });

  console.log(`[PR schedule] PR for "${country}" cancelled by ${req.user.email}`);
  res.json({ success: true, job });
});

/**
 * GET /api/ops/pr/status/:country
 * Polls GitHub for the current status of the most recent PR for a country.
 * Returns { prNumber, prUrl, state: 'open'|'merged'|'closed', merged: bool }
 * Also updates history pr_status if the PR has been merged or closed.
 */
app.get('/api/ops/pr/status/:country', requireAuth, async (req, res) => {
  const country = (req.params.country || '').toLowerCase();
  if (!validateCountry(country)) {
    return res.status(400).json({ error: 'Invalid country' });
  }

  try {
    // Find all PRs (open + closed) for this country's branch prefix.
    // Matches both new naming (ops/<country>/<timestamp>) and legacy (<country>_<timestamp>).
    const openRes = await fetch(
      `https://api.github.ibm.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/pulls?state=all&per_page=20`,
      { headers: ghHeaders() }
    );
    if (!openRes.ok) return res.json({ state: 'unknown' });

    const prs = await openRes.json();
    const countryPRs = prs.filter(pr => {
      const ref = pr.head?.ref || '';
      return ref.startsWith(`ops/${country}/`) || ref.startsWith(`${country}_`);
    });
    if (!countryPRs.length) return res.json({ state: 'none' });

    // Most recent PR = highest number
    const pr = countryPRs.sort((a, b) => b.number - a.number)[0];
    const state  = pr.state;          // 'open' | 'closed'
    const merged = !!pr.merged_at;
    const result = { prNumber: pr.number, prUrl: pr.html_url, state, merged };

    // Sync history if PR has resolved
    if (state === 'closed') {
      const newPrStatus = merged ? 'merged' : 'refused';
      const history = await fetchGitHubJson('data/ops/history.json', {});
      let dirty = false;
      (history[country] || []).forEach(h => {
        if (h.prNumber === pr.number && h.pr_status === 'pending_merge') {
          h.pr_status = newPrStatus;
          if (merged) h.mergedAt = pr.merged_at;
          else        h.closedAt = pr.closed_at;
          dirty = true;
        }
      });
      if (dirty) {
        await commitJsonToMainBranch(
          'data/ops/history.json', history,
          `ops: sync pr_status=${newPrStatus} for ${country} PR #${pr.number}`
        );
        appendActivityLog({
          event:     merged ? 'pr-merged' : 'pr-refused',
          country,
          prNumber:  pr.number,
          prUrl:     pr.html_url,
          by:        'system@poll'
        });
      }
    }

    res.json(result);
  } catch (err) {
    console.error('[PR status] poll error:', err.message);
    res.json({ state: 'unknown', error: err.message });
  }
});

// ─── PR details read endpoint (read-only, uses server-side GitHub token) ─────

/**
 * GET /api/ops/pr/details/:prNumber
 * Returns full GitHub PR metadata + file list for a given PR number.
 * Used by admin tooling and controlled tests — does not modify any state.
 */
app.get('/api/ops/pr/details/:prNumber', requireAuth, async (req, res) => {
  const prNumber = parseInt(req.params.prNumber, 10);
  if (!prNumber || isNaN(prNumber)) {
    return res.status(400).json({ error: 'Valid PR number required' });
  }
  try {
    const [prRes, filesRes] = await Promise.all([
      fetch(`https://api.github.ibm.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/pulls/${prNumber}`, { headers: ghHeaders() }),
      fetch(`${GITHUB_API_BASE}/repos/${GITHUB_OWNER}/${GITHUB_REPO}/pulls/${prNumber}/files`, { headers: ghHeaders() })
    ]);

    if (!prRes.ok) return res.status(prRes.status).json({ error: `GitHub returned ${prRes.status} for PR #${prNumber}` });

    const pr    = await prRes.json();
    const files = filesRes.ok ? await filesRes.json() : [];

    const ALLOWED_PREFIX = 'data/processes/';
    const fileList = (Array.isArray(files) ? files : []).map(f => ({
      filename:  f.filename,
      status:    f.status,
      additions: f.additions,
      deletions: f.deletions,
      allowed:   f.filename.startsWith(ALLOWED_PREFIX)
    }));
    const blockedFiles = fileList.filter(f => !f.allowed).map(f => f.filename);

    res.json({
      prNumber:     pr.number,
      prUrl:        pr.html_url,
      state:        pr.state,
      baseBranch:   pr.base.ref,
      headBranch:   pr.head.ref,
      title:        pr.title,
      commits:      pr.commits,
      changedFiles: pr.changed_files,
      additions:    pr.additions,
      deletions:    pr.deletions,
      mergeable:    pr.mergeable,
      mergeableState: pr.mergeable_state,
      createdAt:    pr.created_at,
      files:        fileList,
      scopeClean:   blockedFiles.length === 0,
      blockedFiles
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Admin history entry delete (Admin only, surgical) ───────────────────────

/**
 * DELETE /api/ops/history/entry
 * Removes exactly ONE specific history entry identified by country + id.
 * Admin only.
 *
 * Safety rules enforced server-side:
 *   1. Loads history fresh from GitHub (never trusts client payload).
 *   2. Finds entries matching { country, id }.
 *   3. Refuses if 0 matches found.
 *   4. Refuses if > 1 match found (ambiguous — must not bulk-delete).
 *   5. Refuses if the single match does not also match the provided
 *      confirmIssue field (extra identity check).
 *   6. Writes back to GitHub only after all checks pass.
 *   7. Returns before/after counts.
 */
app.delete('/api/ops/history/entry', requireAuth, async (req, res) => {
  // ── Guard 1: Admin only ────────────────────────────────────────────────────
  if (req.user.role !== 'Admin') {
    return res.status(403).json({ error: 'Admin only' });
  }

  const { country, id, confirmIssue, reason } = req.body;

  // ── Guard 2: All fields required, including reason ─────────────────────────
  if (!country || !id || !confirmIssue || !reason) {
    return res.status(400).json({
      error: 'country, id, confirmIssue, and reason are all required'
    });
  }
  if (typeof reason !== 'string' || !reason.trim()) {
    return res.status(400).json({ error: 'reason must be a non-empty string' });
  }
  if (!validateCountry(country)) {
    return res.status(400).json({ error: 'Invalid country' });
  }

  try {
    // ── 1. Load fresh from source of truth ──────────────────────────────────
    const history = await fetchGitHubJson('data/ops/history.json', {});
    const countryHistory = Array.isArray(history[country]) ? history[country] : [];

    // ── 2. Find matches ──────────────────────────────────────────────────────
    const matches = countryHistory.filter(e => e.id === id);

    // ── 3. Refuse if no match ────────────────────────────────────────────────
    if (matches.length === 0) {
      return res.status(404).json({
        error: `No history entry found with id="${id}" for country="${country}"`
      });
    }

    // ── 4. Refuse if ambiguous (more than one entry with same id) ────────────
    if (matches.length > 1) {
      return res.status(409).json({
        error: `Found ${matches.length} entries matching id="${id}" — refusing ambiguous delete`,
        matchCount: matches.length
      });
    }

    const target = matches[0];

    // ── 5. Confirm issue field matches exactly ───────────────────────────────
    const actualIssue = target.process?.issue || target.issue || '';
    if (actualIssue !== confirmIssue) {
      return res.status(409).json({
        error: `Issue field mismatch — expected "${confirmIssue}", found "${actualIssue}". Delete aborted.`
      });
    }

    // ── 6. Remove and write back ─────────────────────────────────────────────
    const beforeCount = countryHistory.length;
    history[country]  = countryHistory.filter(e => e.id !== id);
    const afterCount  = history[country].length;

    const committed = await commitJsonToMainBranch(
      'data/ops/history.json',
      history,
      `ops: admin remove history entry "${id}" from ${country} — ${reason}`
    );

    if (!committed) {
      return res.status(503).json({ error: 'GitHub write failed — please retry' });
    }

    // ── 7. Write admin audit entry AFTER successful deletion ─────────────────
    await appendAdminAudit({
      action:        'history_entry_delete',
      performedBy:   req.user.email,
      role:          req.user.role,
      country,
      entryId:       id,
      confirmIssue,
      reason:        reason.trim(),
      deletedEntry:  target,   // full snapshot of the removed record
      beforeCount,
      afterCount
    });

    console.log(`[Admin] History entry "${id}" removed from "${country}" by ${req.user.email} — reason: ${reason}`);
    res.json({
      success:      true,
      country,
      removedId:    id,
      removedIssue: actualIssue,
      reason:       reason.trim(),
      beforeCount,
      afterCount
    });

  } catch (err) {
    console.error('[Admin history delete] error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─── Admin OPS-based Approve & Publish / Reject Request (Admin only) ─────────

/**
 * _adminPreflightCheck — Part K re-check helper for all critical Admin actions.
 *
 * Re-verifies live backend state immediately before any destructive Admin action:
 *   - Authenticated Admin (role re-checked live from token, not stale cache)
 *   - No active countdown for this country
 *   - History has pending_merge entries for the expected PR
 *   - PR still exists and has expected state on GitHub
 *   - No duplicate PR for same country (stale-action guard for multiple Admins)
 *   - Changed files remain within allowed scope
 *   - Target branch valid (only if expectedBase supplied)
 *
 * Returns { ok: true, prData, matchingEntries } or { ok: false, httpStatus, error, opsMessage, productionChanged, entriesLocked }
 */
async function _adminPreflightCheck(user, country, prNumber, expectedGitHubState) {
  const norm = e => (e || '').toLowerCase().trim();

  // 1. Re-confirm Admin role live from JWT payload (not from stale session assumption)
  if (user.role !== 'Admin') {
    return { ok: false, httpStatus: 403, error: 'Admin only', opsMessage: 'You do not have Admin permissions for this action.' };
  }

  // 2. Countdown guard
  const schedule = await fetchGitHubJson(PR_SCHEDULE_PATH, {});
  if (schedule[country]) {
    return {
      ok: false, httpStatus: 409,
      error: `A PR countdown is running for "${country}". Wait for it to complete or cancel it before proceeding.`,
      opsMessage: 'A Publish Request countdown is in progress for this country. You must wait for it to finish or cancel it before approving or rejecting.',
      productionChanged: false,
      entriesLocked: true
    };
  }

  // 3. History pre-flight — re-fetch fresh to catch stale Admin state
  const historyPre = await fetchGitHubJson('data/ops/history.json', {});
  const matchingEntries = (historyPre[country] || []).filter(
    h => h.prNumber === prNumber && h.pr_status === 'pending_merge'
  );
  if (matchingEntries.length === 0) {
    // Check if already processed by another Admin (Part A — stale-action guard)
    const alreadyDone = (historyPre[country] || []).some(
      h => h.prNumber === prNumber && (h.pr_status === 'merged' || h.pr_status === 'refused')
    );
    if (alreadyDone) {
      return {
        ok: false, httpStatus: 409,
        error: `Publish Request #${prNumber} for "${country}" has already been processed (merged or refused). This action was likely completed by another Admin.`,
        opsMessage: 'This Publish Request has already been acted on. Refresh OPS to see the current state.',
        productionChanged: true,   // may have merged already
        entriesLocked: false
      };
    }
    return {
      ok: false, httpStatus: 409,
      error: `No pending Publish Request entries found for country "${country}" PR #${prNumber}.`,
      opsMessage: 'No entries are waiting for this Publish Request. It may have been cancelled or already processed.',
      productionChanged: false,
      entriesLocked: false
    };
  }

  // 4. Live GitHub PR state check
  let prData = null;
  try {
    const prRes = await fetch(
      `${GITHUB_API_BASE}/repos/${GITHUB_OWNER}/${GITHUB_REPO}/pulls/${prNumber}`,
      { headers: ghHeaders() }
    );
    if (!prRes.ok) {
      const errBody = await prRes.text().catch(() => '');
      return {
        ok: false, httpStatus: prRes.status,
        error: `GitHub returned ${prRes.status} checking Publish Request #${prNumber}: ${errBody}`,
        opsMessage: `OPS could not verify the current state of Publish Request #${prNumber} on GitHub. No changes were made. Try Refresh Status.`,
        productionChanged: false,
        entriesLocked: true
      };
    }
    prData = await prRes.json();
  } catch (err) {
    return {
      ok: false, httpStatus: 502,
      error: `Network error fetching PR #${prNumber}: ${err.message}`,
      opsMessage: 'OPS could not reach GitHub to verify the Publish Request state. No changes were made. Check your connection and try Refresh Status.',
      productionChanged: false,
      entriesLocked: true
    };
  }

  // 5. Expected state check — detect external mismatch (Part J)
  if (expectedGitHubState === 'open' && prData.state !== 'open') {
    const isExternallyMerged = prData.state === 'closed' && !!prData.merged_at;
    const isExternallyClosed = prData.state === 'closed' && !prData.merged_at;

    // Part J — mismatch detected: log it (await so the log is written before returning)
    await appendActivityLog({
      event:           'github-mismatch-detected',
      country,
      prNumber,
      expectedState:   'open',
      actualState:     prData.state,
      merged:          !!prData.merged_at,
      prUrl:           prData.html_url,
      branchName:      prData.head?.ref || null,
      detectedBy:      user.email,
      detectedAt:      new Date().toISOString()
    });

    if (isExternallyMerged) {
      return {
        ok: false, httpStatus: 409,
        error: `External mismatch: Publish Request #${prNumber} was merged outside OPS (merged_at: ${prData.merged_at}).`,
        opsMessage: `Publish Request #${prNumber} was merged directly on GitHub — not through OPS. Production may have changed. Use "Sync as Published" from OPS after verifying the file scope below.`,
        productionChanged: true,
        entriesLocked: true,
        mismatch: { type: 'externally-merged', prData }
      };
    }
    if (isExternallyClosed) {
      return {
        ok: false, httpStatus: 409,
        error: `External mismatch: Publish Request #${prNumber} was closed outside OPS without merging.`,
        opsMessage: `Publish Request #${prNumber} was closed directly on GitHub without merging. Production did NOT change. Use "Sync as Refused" from OPS to close it cleanly.`,
        productionChanged: false,
        entriesLocked: true,
        mismatch: { type: 'externally-closed', prData }
      };
    }
    return {
      ok: false, httpStatus: 409,
      error: `Publish Request #${prNumber} is in unexpected state: "${prData.state}".`,
      opsMessage: `Publish Request #${prNumber} is in an unexpected state. No action was taken. Use Refresh Status to re-check.`,
      productionChanged: false,
      entriesLocked: true
    };
  }

  // 6. File scope check — Part J: verify no unexpected files
  try {
    const filesRes = await fetch(
      `${GITHUB_API_BASE}/repos/${GITHUB_OWNER}/${GITHUB_REPO}/pulls/${prNumber}/files`,
      { headers: ghHeaders() }
    );
    if (filesRes.ok) {
      const files = await filesRes.json();
      const blocked = (Array.isArray(files) ? files : [])
        .map(f => f.filename)
        .filter(f => !_isAllowedPRPath(f));
      if (blocked.length > 0) {
        appendActivityLog({
          event:        'github-mismatch-detected',
          country,
          prNumber,
          issue:        'unexpected-files',
          blockedFiles: blocked,
          detectedBy:   user.email,
          detectedAt:   new Date().toISOString()
        }).catch(() => {});
        return {
          ok: false, httpStatus: 409,
          error: `Publish Request #${prNumber} contains unexpected files outside allowed scope: ${blocked.join(', ')}`,
          opsMessage: `Publish Request #${prNumber} was found to contain unexpected files (${blocked.join(', ')}). This is unsafe. Reject this request and ask the country owner to submit a clean corrected request.`,
          productionChanged: false,
          entriesLocked: true,
          blockedFiles: blocked
        };
      }
    }
  } catch {}  // scope check failure is non-fatal but logged above

  // 7. Target branch check
  if (prData.base?.ref && prData.base.ref !== GITHUB_TARGET_BRANCH) {
    appendActivityLog({
      event:          'github-mismatch-detected',
      country,
      prNumber,
      issue:          'wrong-target-branch',
      expectedBase:   GITHUB_TARGET_BRANCH,
      actualBase:     prData.base.ref,
      detectedBy:     user.email,
      detectedAt:     new Date().toISOString()
    }).catch(() => {});
    return {
      ok: false, httpStatus: 409,
      error: `Publish Request #${prNumber} targets "${prData.base.ref}" instead of expected "${GITHUB_TARGET_BRANCH}".`,
      opsMessage: `Publish Request #${prNumber} is targeting the wrong branch. No action was taken. Reject this request.`,
      productionChanged: false,
      entriesLocked: true
    };
  }

  return { ok: true, prData, matchingEntries, historyPre };
}

/**
 * POST /api/admin/pr/approve
 * OPS-based Admin Approve & Publish.
 * Parts A, B, H, K: re-checks live state before every merge, detects mismatch,
 * handles merge failure with safe error state, blocks stale/duplicate Admin actions.
 *
 * Body: { country: string, prNumber: number }
 * Returns: { success, country, prNumber, mergedCount, sha }
 *          OR failure shape: { error, opsMessage, productionChanged, entriesLocked, availableActions }
 */
app.post('/api/admin/pr/approve', requireAuth, async (req, res) => {
  if (req.user.role !== 'Admin') {
    return res.status(403).json({ error: 'Admin only' });
  }

  const { country, prNumber } = req.body;
  if (!country || !validateCountry(country)) {
    return res.status(400).json({ error: 'Valid country is required' });
  }
  if (!prNumber || typeof prNumber !== 'number') {
    return res.status(400).json({ error: 'prNumber (number) is required' });
  }

  const approver = req.user.email;
  const now      = new Date().toISOString();

  try {
    // Part K — full re-check before approve
    const precheck = await _adminPreflightCheck(req.user, country, prNumber, 'open');
    if (!precheck.ok) {
      // Log the failed attempt (Part M)
      appendActivityLog({
        event:             'approve-preflight-failed',
        by:                approver,
        country,
        prNumber,
        error:             precheck.error,
        productionChanged: precheck.productionChanged,
        mismatch:          precheck.mismatch || null,
        blockedFiles:      precheck.blockedFiles || null,
        attemptedAt:       now
      }).catch(() => {});
      return res.status(precheck.httpStatus || 409).json({
        error:             precheck.error,
        opsMessage:        precheck.opsMessage,
        productionChanged: precheck.productionChanged,
        entriesLocked:     precheck.entriesLocked,
        mismatch:          precheck.mismatch || null,
        blockedFiles:      precheck.blockedFiles || null,
        availableActions:  _buildApproveFailureActions(precheck)
      });
    }

    const { prData, matchingEntries, historyPre } = precheck;

    // ── Squash-merge the PR via GitHub API (Part H) ───────────────────────────
    const mergeRes = await fetch(
      `${GITHUB_API_BASE}/repos/${GITHUB_OWNER}/${GITHUB_REPO}/pulls/${prNumber}/merge`,
      {
        method: 'PUT',
        headers: ghHeaders(),
        body: JSON.stringify({
          merge_method:    'squash',
          commit_title:    `OPS: Publish Request #${prNumber} approved by ${approver}`,
          commit_message:  `Approved via OPS panel. Country: ${country}. Approved by: ${approver}. Timestamp: ${now}.`
        })
      }
    );

    if (!mergeRes.ok) {
      const errBody = await mergeRes.text().catch(() => '');
      const isConflict = mergeRes.status === 405 || mergeRes.status === 422;

      // Part H — merge failure: log, keep entries locked, return actionable state
      appendActivityLog({
        event:           isConflict ? 'approve-conflict-detected' : 'approve-merge-failed',
        by:              approver,
        country,
        prNumber,
        httpStatus:      mergeRes.status,
        error:           errBody,
        attemptedAt:     now
      }).catch(() => {});

      const opsMessage = isConflict
        ? `Publish Request #${prNumber} has a merge conflict and cannot be approved. Production was NOT changed. Entries remain locked. Reject this request and ask the country owner to submit a corrected request.`
        : `GitHub rejected the merge for Publish Request #${prNumber} (HTTP ${mergeRes.status}). Production was NOT changed. Entries remain locked. Use Retry Approve or Reject Publish Request.`;

      return res.status(409).json({
        error:             `Approval failed: ${isConflict ? 'merge conflict' : `GitHub error ${mergeRes.status}`}`,
        opsMessage,
        productionChanged: false,
        entriesLocked:     true,
        httpStatus:        mergeRes.status,
        details:           errBody,
        availableActions:  isConflict
          ? ['rejectRequest', 'refreshStatus', 'viewErrorDetails']
          : ['retryApprove', 'rejectRequest', 'refreshStatus', 'viewErrorDetails']
      });
    }

    const mergeData = await mergeRes.json();
    const mergeSha  = mergeData.sha || null;

    // ── Update History: pending_merge → merged ────────────────────────────────
    let mergedCount = 0;
    matchingEntries.forEach(h => {
      h.pr_status  = 'merged';
      h.mergedAt   = now;
      h.approvedBy = approver;
      h.approvedAt = now;
      if (mergeSha) h.mergeCommitSha = mergeSha;
      mergedCount++;
    });

    await commitJsonToMainBranch(
      'data/ops/history.json', historyPre,
      `ops: mark ${country} PR #${prNumber} as merged — approved by ${approver}`
    );

    // ── J2/J3: Media lifecycle hooks (fire-and-forget after successful merge) ────
    // These run asynchronously and never block or fail the approve response.
    setImmediate(async () => {
      try {
        // Step 1: Promote staged media → final paths for all merged entries
        const promoteResult = await _promoteStagedMedia(country, matchingEntries);
        if (promoteResult.promoted.length > 0) {
          // Step 2: Rewrite production process data with final paths
          const pathMap = {};
          promoteResult.promoted.forEach(({ staged, final }) => { pathMap[staged] = final; });
          await _rewriteProductionMediaPaths(country, pathMap);
          // Step 3: Update history JSON with rewritten HTML (matchingEntries mutated in-place)
          const historyPost = await fetchGitHubJson('data/ops/history.json', {});
          if (historyPost[country]) {
            matchingEntries.forEach(updated => {
              const idx = historyPost[country].findIndex(h => h.id === updated.id);
              if (idx !== -1) historyPost[country][idx] = updated;
            });
            await commitJsonToMainBranch('data/ops/history.json', historyPost,
              `ops: rewrite staged→final media refs after PR #${prNumber} approved`
            ).catch(e => console.warn('[media promote] history rewrite failed:', e.message));
          }
          appendActivityLog({
            event: 'media-promoted', by: approver, country, prNumber,
            promoted: promoteResult.promoted.length,
            failed:   promoteResult.failed.length,
            rewroteEntries: promoteResult.rewroteEntries
          }).catch(() => {});
        }
        if (promoteResult.failed.length > 0) {
          console.warn(`[Admin approve] media promote had ${promoteResult.failed.length} failure(s) for PR #${prNumber}`);
        }
        // Step 4: Cleanup removed images from update entries (J3)
        const updateEntries = matchingEntries.filter(h => h.type === 'update');
        if (updateEntries.length > 0) {
          const modifyCleanup = await _cleanupRemovedImagesAfterApproval(country, updateEntries);
          if (modifyCleanup.deleted.length > 0 || modifyCleanup.errors.length > 0) {
            appendActivityLog({
              event: 'media-cleanup-after-approve-modify', by: approver, country, prNumber,
              deleted: modifyCleanup.deleted.length, kept: modifyCleanup.kept.length,
              errors: modifyCleanup.errors
            }).catch(() => {});
          }
        }
        // Step 5: Cleanup images from deleted processes (J2)
        const deleteEntries = matchingEntries.filter(h => h.type === 'delete');
        if (deleteEntries.length > 0) {
          const deleteCleanup = await _cleanupDeletedProcessImages(country, deleteEntries);
          if (deleteCleanup.deleted.length > 0 || deleteCleanup.errors.length > 0) {
            appendActivityLog({
              event: 'media-cleanup-after-approve-delete', by: approver, country, prNumber,
              deleted: deleteCleanup.deleted.length, kept: deleteCleanup.kept.length,
              errors: deleteCleanup.errors
            }).catch(() => {});
          }
        }
      } catch (mediaErr) {
        console.error('[Admin approve] media lifecycle error (non-blocking):', mediaErr.message);
        appendActivityLog({
          event: 'media-lifecycle-error', by: approver, country, prNumber, error: mediaErr.message
        }).catch(() => {});
      }
    });

    // ── Write Logs audit record ───────────────────────────────────────────────
    appendActivityLog({
      event:       'request-approved',
      by:          approver,
      role:        req.user.role,
      country,
      prNumber,
      prUrl:       prData.html_url,
      branchName:  prData.head?.ref || null,
      mergedCount,
      mergeCommitSha: mergeSha,
      approvedAt:  now
    });

    console.log(`[Admin approve] PR #${prNumber} merged for "${country}" by ${approver} — ${mergedCount} history entries updated`);
    res.json({ success: true, country, prNumber, mergedCount, sha: mergeSha });

  } catch (err) {
    console.error('[Admin approve] error:', err.message);
    appendActivityLog({
      event:       'approve-merge-failed',
      by:          approver,
      country,
      prNumber,
      error:       err.message,
      attemptedAt: now
    }).catch(() => {});
    res.status(500).json({
      error:             err.message,
      opsMessage:        `An unexpected error occurred while approving Publish Request #${prNumber}. Production status is uncertain. Use Refresh Status to verify, then Retry Approve or Reject as appropriate.`,
      productionChanged: null,
      entriesLocked:     true,
      availableActions:  ['refreshStatus', 'retryApprove', 'rejectRequest', 'viewErrorDetails']
    });
  }
});

/**
 * POST /api/admin/pr/close
 * OPS-based Admin Reject Request.
 * Parts A, B, I, K: re-checks live state before every close, handles close failure
 * safely, blocks stale/duplicate Admin actions.
 *
 * Body: { country: string, prNumber: number, reason?: string }
 * Returns: { success, country, prNumber, refusedCount }
 *          OR failure shape: { error, opsMessage, productionChanged, entriesLocked, availableActions }
 */
app.post('/api/admin/pr/close', requireAuth, async (req, res) => {
  if (req.user.role !== 'Admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  const { country, prNumber, reason } = req.body;
  if (!prNumber || typeof prNumber !== 'number') {
    return res.status(400).json({ error: 'prNumber (number) is required' });
  }
  if (!country || !validateCountry(country)) {
    return res.status(400).json({ error: 'Valid country is required' });
  }

  const rejecter = req.user.email;
  const now      = new Date().toISOString();

  try {
    // Part K — full re-check before reject (pass 'open' as expected state)
    const precheck = await _adminPreflightCheck(req.user, country, prNumber, 'open');
    if (!precheck.ok) {
      appendActivityLog({
        event:             'reject-preflight-failed',
        by:                rejecter,
        country,
        prNumber,
        error:             precheck.error,
        productionChanged: precheck.productionChanged,
        mismatch:          precheck.mismatch || null,
        attemptedAt:       now
      }).catch(() => {});
      return res.status(precheck.httpStatus || 409).json({
        error:             precheck.error,
        opsMessage:        precheck.opsMessage,
        productionChanged: precheck.productionChanged,
        entriesLocked:     precheck.entriesLocked,
        mismatch:          precheck.mismatch || null,
        availableActions:  _buildRejectFailureActions(precheck)
      });
    }

    const { prData, matchingEntries, historyPre } = precheck;

    // ── Close the PR via GitHub API ───────────────────────────────────────────
    const closeRes = await fetch(
      `${GITHUB_API_BASE}/repos/${GITHUB_OWNER}/${GITHUB_REPO}/pulls/${prNumber}`,
      {
        method: 'PATCH',
        headers: ghHeaders(),
        body: JSON.stringify({
          state: 'closed',
          body:  reason ? `[Admin Reject] ${reason}` : '[Admin] Rejected via OPS panel'
        })
      }
    );

    if (!closeRes.ok) {
      const errBody = await closeRes.text().catch(() => '');
      // Part I — close failure: do NOT mark as refused. Keep active/error.
      appendActivityLog({
        event:       'reject-close-failed',
        by:          rejecter,
        country,
        prNumber,
        httpStatus:  closeRes.status,
        error:       errBody,
        attemptedAt: now
      }).catch(() => {});
      return res.status(closeRes.status || 500).json({
        error:             `GitHub rejected the close for Publish Request #${prNumber} (HTTP ${closeRes.status}).`,
        opsMessage:        `OPS could not close Publish Request #${prNumber} on GitHub. Production was NOT changed. The request remains active. Use Retry Reject or Refresh Status. Do NOT use Force Sync unless Refresh Status confirms the PR is already closed.`,
        productionChanged: false,
        entriesLocked:     true,
        details:           errBody,
        availableActions:  ['retryReject', 'refreshStatus', 'viewErrorDetails']
      });
    }
    const pr = await closeRes.json();

    // Part I — verify GitHub actually closed it before marking as refused
    // The PATCH returns the updated PR object. State must be 'closed' and NOT merged.
    if (pr.state !== 'closed' || pr.merged_at) {
      appendActivityLog({
        event:       'reject-close-failed',
        by:          rejecter,
        country,
        prNumber,
        issue:       'pr-not-closed-after-patch',
        prState:     pr.state,
        mergedAt:    pr.merged_at || null,
        attemptedAt: now
      }).catch(() => {});
      return res.status(409).json({
        error:             `Publish Request #${prNumber} was not confirmed closed by GitHub (state: ${pr.state}).`,
        opsMessage:        `OPS could not confirm Publish Request #${prNumber} was closed. No OPS state was changed. Use Refresh Status to verify the actual GitHub state before retrying.`,
        productionChanged: !!pr.merged_at,
        entriesLocked:     true,
        availableActions:  ['retryReject', 'refreshStatus', 'viewErrorDetails']
      });
    }

    // ── GitHub confirmed closed — update History: pending_merge → refused ─────
    let refusedCount = 0;
    matchingEntries.forEach(h => {
      h.pr_status        = 'refused';
      h.closedAt         = now;
      h.rejectedBy       = rejecter;
      h.rejectedAt       = now;
      if (reason) h.rejectionReason = reason.trim();
      refusedCount++;
    });

    await commitJsonToMainBranch(
      'data/ops/history.json', historyPre,
      `ops: mark ${country} PR #${prNumber} as refused — rejected by ${rejecter}`
    );

    // ── J1: Cleanup staged media after PR rejection (fire-and-forget) ────────
    setImmediate(async () => {
      try {
        const rejectCleanup = await _cleanupRejectedStagedMedia(country, matchingEntries);
        if (rejectCleanup.deleted.length > 0 || rejectCleanup.errors.length > 0) {
          appendActivityLog({
            event:   'media-cleanup-after-reject',
            by:      rejecter,
            country,
            prNumber,
            deleted: rejectCleanup.deleted.length,
            kept:    rejectCleanup.kept.length,
            errors:  rejectCleanup.errors
          }).catch(() => {});
        }
      } catch (mediaErr) {
        console.error('[Admin reject] media cleanup error (non-blocking):', mediaErr.message);
      }
    });

    // ── Write Logs audit record ───────────────────────────────────────────────
    appendActivityLog({
      event:            'request-rejected',
      by:               rejecter,
      role:             req.user.role,
      country,
      prNumber,
      prUrl:            pr.html_url,
      branchName:       pr.head?.ref || null,
      refusedCount,
      rejectionReason:  reason ? reason.trim() : null,
      rejectedAt:       now
    });

    console.log(`[Admin reject] PR #${prNumber} closed for "${country}" by ${rejecter} — ${refusedCount} history entries updated`);
    res.json({ success: true, country, prNumber, state: pr.state, refusedCount });

  } catch (err) {
    console.error('[Admin reject] error:', err.message);
    appendActivityLog({
      event:       'reject-close-failed',
      by:          rejecter,
      country,
      prNumber,
      error:       err.message,
      attemptedAt: now
    }).catch(() => {});
    res.status(500).json({
      error:             err.message,
      opsMessage:        `An unexpected error occurred while rejecting Publish Request #${prNumber}. Production status is uncertain. Use Refresh Status to verify the GitHub state before retrying.`,
      productionChanged: null,
      entriesLocked:     true,
      availableActions:  ['retryReject', 'refreshStatus', 'viewErrorDetails']
    });
  }
});

// ─── Failure-action builders (Part L) ─────────────────────────────────────────

/**
 * Returns the list of safe OPS actions available after an approve pre-flight failure.
 */
function _buildApproveFailureActions(precheck) {
  if (precheck.mismatch?.type === 'externally-merged') {
    return ['syncAsPublished', 'refreshStatus', 'viewErrorDetails'];
  }
  if (precheck.mismatch?.type === 'externally-closed') {
    return ['syncAsRefused', 'refreshStatus', 'viewErrorDetails'];
  }
  if (precheck.blockedFiles?.length) {
    return ['rejectRequest', 'viewErrorDetails'];
  }
  if (precheck.productionChanged) {
    return ['refreshStatus', 'viewErrorDetails'];
  }
  return ['retryApprove', 'rejectRequest', 'refreshStatus', 'viewErrorDetails'];
}

/**
 * Returns the list of safe OPS actions available after a reject pre-flight failure.
 */
function _buildRejectFailureActions(precheck) {
  if (precheck.mismatch?.type === 'externally-merged') {
    return ['syncAsPublished', 'refreshStatus', 'viewErrorDetails'];
  }
  if (precheck.mismatch?.type === 'externally-closed') {
    return ['syncAsRefused', 'refreshStatus', 'viewErrorDetails'];
  }
  if (precheck.productionChanged) {
    return ['refreshStatus', 'viewErrorDetails'];
  }
  return ['retryReject', 'refreshStatus', 'viewErrorDetails'];
}

// ─── OPS GitHub Sync routes (Part J — Admin only) ─────────────────────────────

/**
 * POST /api/admin/pr/sync-published
 * Allows Admin to sync an externally-merged PR as Published from OPS, ONLY after
 * the backend verifies: PR is merged, files are in allowed scope, expected country.
 * Part J rule: do not blindly trust external state — backend must verify.
 *
 * Body: { country, prNumber }
 */
app.post('/api/admin/pr/sync-published', requireAuth, async (req, res) => {
  if (req.user.role !== 'Admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  const { country, prNumber } = req.body;
  if (!country || !validateCountry(country)) return res.status(400).json({ error: 'Valid country is required' });
  if (!prNumber || typeof prNumber !== 'number') return res.status(400).json({ error: 'prNumber (number) is required' });

  const actor = req.user.email;
  const now   = new Date().toISOString();

  try {
    // 1. Verify PR exists and is genuinely merged on GitHub
    const prRes = await fetch(
      `${GITHUB_API_BASE}/repos/${GITHUB_OWNER}/${GITHUB_REPO}/pulls/${prNumber}`,
      { headers: ghHeaders() }
    );
    if (!prRes.ok) {
      return res.status(prRes.status).json({ error: `GitHub returned ${prRes.status} checking PR #${prNumber}` });
    }
    const pr = await prRes.json();

    if (!pr.merged_at || pr.state !== 'closed') {
      return res.status(409).json({
        error: `PR #${prNumber} is not merged (state=${pr.state}, merged_at=${pr.merged_at || 'null'}). Sync as Published is only available for genuinely merged PRs.`,
        opsMessage: 'This Publish Request has not been merged. Sync as Published is only allowed after GitHub confirms the merge. Use Refresh Status first.'
      });
    }

    // 2. Verify files remain in allowed scope
    const filesRes = await fetch(
      `${GITHUB_API_BASE}/repos/${GITHUB_OWNER}/${GITHUB_REPO}/pulls/${prNumber}/files`,
      { headers: ghHeaders() }
    );
    if (filesRes.ok) {
      const files = await filesRes.json();
      const blocked = (Array.isArray(files) ? files : []).map(f => f.filename).filter(f => !_isAllowedPRPath(f));
      if (blocked.length > 0) {
        return res.status(409).json({
          error: `Cannot sync as Published — PR #${prNumber} contains out-of-scope files: ${blocked.join(', ')}`,
          opsMessage: 'Sync as Published was blocked because this Publish Request contained unexpected files outside the allowed scope. Investigate before taking further action.'
        });
      }
    }

    // 3. Update History entries
    const history = await fetchGitHubJson('data/ops/history.json', {});
    const matching = (history[country] || []).filter(
      h => h.prNumber === prNumber && h.pr_status === 'pending_merge'
    );
    if (matching.length === 0) {
      return res.status(409).json({
        error: `No pending_merge History entries found for country "${country}" PR #${prNumber}.`,
        opsMessage: 'No entries found to sync. The Publish Request may have already been processed.'
      });
    }

    const mergeSha = pr.merge_commit_sha || null;
    matching.forEach(h => {
      h.pr_status          = 'merged';
      h.mergedAt           = pr.merged_at;
      h.approvedBy         = actor;
      h.approvedAt         = now;
      h.syncedFromExternal = true;
      if (mergeSha) h.mergeCommitSha = mergeSha;
    });

    await commitJsonToMainBranch(
      'data/ops/history.json', history,
      `ops: sync PR #${prNumber} as published (external merge) for ${country} by ${actor}`
    );

    appendActivityLog({
      event:             'sync-as-published',
      by:                actor,
      country,
      prNumber,
      prUrl:             pr.html_url,
      mergeCommitSha:    mergeSha,
      mergedAt:          pr.merged_at,
      syncedCount:       matching.length,
      syncedAt:          now
    });

    console.log(`[Admin sync] PR #${prNumber} synced as Published for "${country}" by ${actor}`);
    res.json({ success: true, country, prNumber, syncedCount: matching.length });

  } catch (err) {
    console.error('[Admin sync-published] error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/admin/pr/sync-refused
 * Allows Admin to sync an externally-closed (unmerged) PR as Refused from OPS,
 * ONLY after backend verifies: PR is closed AND not merged.
 * Part J rule: do not blindly trust external state.
 *
 * Body: { country, prNumber, reason? }
 */
app.post('/api/admin/pr/sync-refused', requireAuth, async (req, res) => {
  if (req.user.role !== 'Admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  const { country, prNumber, reason } = req.body;
  if (!country || !validateCountry(country)) return res.status(400).json({ error: 'Valid country is required' });
  if (!prNumber || typeof prNumber !== 'number') return res.status(400).json({ error: 'prNumber (number) is required' });

  const actor = req.user.email;
  const now   = new Date().toISOString();

  try {
    // 1. Verify PR is closed and NOT merged on GitHub
    const prRes = await fetch(
      `${GITHUB_API_BASE}/repos/${GITHUB_OWNER}/${GITHUB_REPO}/pulls/${prNumber}`,
      { headers: ghHeaders() }
    );
    if (!prRes.ok) {
      return res.status(prRes.status).json({ error: `GitHub returned ${prRes.status} checking PR #${prNumber}` });
    }
    const pr = await prRes.json();

    if (pr.state !== 'closed' || pr.merged_at) {
      return res.status(409).json({
        error: `PR #${prNumber} is not closed-unmerged (state=${pr.state}, merged_at=${pr.merged_at || 'null'}). Sync as Refused is only available for closed unmerged PRs.`,
        opsMessage: 'This Publish Request has not been closed without merging. Verify the current GitHub state before using Sync as Refused.'
      });
    }

    // 2. Update History entries
    const history = await fetchGitHubJson('data/ops/history.json', {});
    const matching = (history[country] || []).filter(
      h => h.prNumber === prNumber && h.pr_status === 'pending_merge'
    );
    if (matching.length === 0) {
      return res.status(409).json({
        error: `No pending_merge History entries found for country "${country}" PR #${prNumber}.`,
        opsMessage: 'No entries found to sync. The Publish Request may have already been processed.'
      });
    }

    matching.forEach(h => {
      h.pr_status          = 'refused';
      h.closedAt           = pr.closed_at || now;
      h.rejectedBy         = actor;
      h.rejectedAt         = now;
      h.syncedFromExternal = true;
      if (reason) h.rejectionReason = reason.trim();
    });

    await commitJsonToMainBranch(
      'data/ops/history.json', history,
      `ops: sync PR #${prNumber} as refused (external close) for ${country} by ${actor}`
    );

    appendActivityLog({
      event:             'sync-as-refused',
      by:                actor,
      country,
      prNumber,
      prUrl:             pr.html_url,
      closedAt:          pr.closed_at || now,
      rejectionReason:   reason ? reason.trim() : null,
      syncedCount:       matching.length,
      syncedAt:          now
    });

    console.log(`[Admin sync] PR #${prNumber} synced as Refused for "${country}" by ${actor}`);
    res.json({ success: true, country, prNumber, syncedCount: matching.length });

  } catch (err) {
    console.error('[Admin sync-refused] error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/admin/pr/verify/:prNumber
 * Backend-verified status check for a specific PR (Part J, Part K).
 * Returns full state: merged, closed, files scope, target branch, head branch,
 * expected country scope, mismatch flags.
 * Admin only.
 */
app.get('/api/admin/pr/verify/:prNumber', requireAuth, async (req, res) => {
  if (req.user.role !== 'Admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  const prNumber = parseInt(req.params.prNumber, 10);
  if (!prNumber || isNaN(prNumber)) {
    return res.status(400).json({ error: 'Valid PR number required' });
  }

  try {
    const [prRes, filesRes] = await Promise.all([
      fetch(`${GITHUB_API_BASE}/repos/${GITHUB_OWNER}/${GITHUB_REPO}/pulls/${prNumber}`, { headers: ghHeaders() }),
      fetch(`${GITHUB_API_BASE}/repos/${GITHUB_OWNER}/${GITHUB_REPO}/pulls/${prNumber}/files`, { headers: ghHeaders() })
    ]);

    if (!prRes.ok) {
      return res.status(prRes.status).json({ error: `GitHub returned ${prRes.status}` });
    }

    const pr    = await prRes.json();
    const files = filesRes.ok ? await filesRes.json() : [];

    const fileList = (Array.isArray(files) ? files : []).map(f => ({
      filename: f.filename,
      status:   f.status,
      allowed:  _isAllowedPRPath(f.filename)
    }));
    const blockedFiles  = fileList.filter(f => !f.allowed).map(f => f.filename);
    const scopeClean    = blockedFiles.length === 0;
    const targetCorrect = pr.base?.ref === GITHUB_TARGET_BRANCH;

    // Detect mismatch type
    let mismatchType = null;
    if (pr.state === 'closed' && pr.merged_at)  mismatchType = 'externally-merged';
    if (pr.state === 'closed' && !pr.merged_at) mismatchType = 'externally-closed';
    if (!scopeClean)                             mismatchType = mismatchType || 'unexpected-files';
    if (!targetCorrect)                          mismatchType = mismatchType || 'wrong-target-branch';

    // Available sync actions based on verified state
    const syncActions = [];
    if (pr.state === 'closed' && pr.merged_at && scopeClean)  syncActions.push('syncAsPublished');
    if (pr.state === 'closed' && !pr.merged_at)               syncActions.push('syncAsRefused');

    res.json({
      prNumber,
      prUrl:          pr.html_url,
      state:          pr.state,
      merged:         !!pr.merged_at,
      mergedAt:       pr.merged_at || null,
      closedAt:       pr.closed_at || null,
      baseBranch:     pr.base?.ref || null,
      headBranch:     pr.head?.ref || null,
      targetCorrect,
      scopeClean,
      blockedFiles,
      files:          fileList,
      mismatchType,
      mismatchDetected: mismatchType !== null,
      syncActions,
      title:          pr.title,
      mergeable:      pr.mergeable,
      mergeableState: pr.mergeable_state,
      verifiedAt:     new Date().toISOString()
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/admin/pr/retry-create
 * Retries Publish Request creation for a country when the initial attempt failed
 * before a real GitHub PR was created. Part G.
 * Entries must still be in Buffer as validated to be eligible.
 * Admin only.
 *
 * Body: { country }
 */
app.post('/api/admin/pr/retry-create', requireAuth, async (req, res) => {
  if (req.user.role !== 'Admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  const { country } = req.body;
  if (!country || !validateCountry(country)) {
    return res.status(400).json({ error: 'Valid country is required' });
  }
  if (DISABLE_PR_CREATION) {
    return res.status(503).json({ error: 'PR creation is currently disabled on this server.' });
  }

  const actor = req.user.email;
  const now   = new Date().toISOString();

  try {
    // Re-use the same pre-flight and create flow as approve-and-merge
    const buffer       = await fetchGitHubJson('data/ops/buffer.json', {});
    const countryBuf   = buffer[country] || {};
    const allEntries   = Object.values(countryBuf).flat();
    const mergeUsers   = await fetchGitHubJson('config/users.json', []);
    const scopedEntries = _filterEntriesByPRScope(allEntries, mergeUsers, actor);
    const validatedEntries = scopedEntries.filter(e => e.status === 'validated');

    if (!validatedEntries.length) {
      return res.status(400).json({
        error: 'No validated entries available for retry.',
        opsMessage: 'There are no validated entries in the Buffer for this country. The previous creation failure left entries safely in Buffer. Validate entries first, then retry.',
        productionChanged: false,
        entriesLocked: false
      });
    }

    const preflight = await _preflightPRCheck(country, validatedEntries);
    if (!preflight.ok) {
      return res.status(preflight.httpStatus || 400).json({
        error:             preflight.error,
        opsMessage:        `Retry Create was blocked: ${preflight.error}. No production changes were made. Entries remain in Buffer.`,
        productionChanged: false,
        entriesLocked:     false
      });
    }

    appendActivityLog({ event: 'pr-create-retry', by: actor, country, entryCount: validatedEntries.length, attemptedAt: now });

    const prResult = await _createPRForCountry(country, validatedEntries, actor);

    if (!prResult.success) {
      appendActivityLog({ event: 'pr-create-failed', by: actor, country, error: prResult.error, attemptedAt: now });
      return res.status(500).json({
        error:             `Retry failed: ${prResult.error}`,
        opsMessage:        `Retry Create failed again. No production changes were made. Entries remain in Buffer. Retry again later or cancel the attempt.`,
        productionChanged: false,
        entriesLocked:     false,
        availableActions:  ['retryCreate', 'cancelAttempt', 'refreshStatus', 'viewErrorDetails']
      });
    }

    await _moveBufToHistoryAfterPR(country, validatedEntries, prResult, actor);

    appendActivityLog({
      event:      'pr-created',
      by:         actor,
      country,
      branchName: prResult.branchName,
      prNumber:   prResult.prNumber,
      prUrl:      prResult.prUrl,
      entryCount: validatedEntries.length,
      trigger:    'retry-create'
    });

    res.json({ success: true, country, prUrl: prResult.prUrl, prNumber: prResult.prNumber, branchName: prResult.branchName });

  } catch (err) {
    console.error('[Admin retry-create] error:', err.message);
    appendActivityLog({ event: 'pr-create-failed', by: actor, country, error: err.message, attemptedAt: now }).catch(() => {});
    res.status(500).json({
      error:             err.message,
      opsMessage:        'An unexpected error occurred during Retry Create. Entries remain in Buffer. No production changes were made.',
      productionChanged: false,
      entriesLocked:     false,
      availableActions:  ['retryCreate', 'cancelAttempt', 'refreshStatus', 'viewErrorDetails']
    });
  }
});

/**
 * DELETE /api/admin/branch
 * Deletes a git branch on the repo. Admin only.
 * Body: { branch: string }
 */
app.delete('/api/admin/branch', requireAuth, async (req, res) => {
  if (req.user.role !== 'Admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  const { branch } = req.body;
  if (!branch || typeof branch !== 'string' || !branch.trim()) {
    return res.status(400).json({ error: 'branch name is required' });
  }
  // Safety: only allow ops/ branches to be deleted via this route
  if (!branch.startsWith('ops/')) {
    return res.status(403).json({ error: 'This route may only delete ops/ branches' });
  }
  try {
    const r = await fetch(
      `https://api.github.ibm.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/git/refs/heads/${encodeURIComponent(branch)}`,
      { method: 'DELETE', headers: ghHeaders() }
    );
    if (r.status === 422 || r.status === 404) {
      return res.status(404).json({ error: `Branch "${branch}" not found` });
    }
    if (!r.ok) {
      const errBody = await r.text().catch(() => '');
      return res.status(r.status).json({ error: `GitHub returned ${r.status}: ${errBody}` });
    }
    console.log(`[Admin] Branch "${branch}" deleted by ${req.user.email}`);
    res.json({ success: true, branch, deleted: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Logs read endpoint ───────────────────────────────────────────────────────

/**
 * GET /api/ops/logs
 * Returns activity_logs.json — Admin only.
 * Phase 8.5: requireAuth added. Previously unauthenticated (TODO-2 from §8).
 */
app.get('/api/ops/logs', requireAuth, async (req, res) => {
  if (req.user.role !== 'Admin') {
    return res.status(403).json({ error: 'Forbidden — Logs are Admin only.' });
  }
  res.json(await fetchGitHubJson('data/logs/activity_logs.json', []));
});

// ─── Scheduled PR executor ────────────────────────────────────────────────────

// Guard: prevent concurrent executions
let _executorRunning = false;

/**
 * Core executor. Called by both setInterval and lazily on API requests.
 * Scans pr_schedule.json, fires any jobs whose execute_after time has passed.
 * For each due job:
 *   1. Checks all buffer entries for the country are validated (no pending).
 *   2. If not → silently cancels the job (writes log).
 *   3. If yes → calls _createPRForCountry, moves entries to history, clears job.
 */
async function _runScheduledPRExecutor() {
  if (_executorRunning) return;
  // Phase 1 kill switch — executor is a complete no-op when disabled.
  if (DISABLE_PR_CREATION) {
    console.warn('[PR executor] DISABLE_PR_CREATION=true — executor is disabled, skipping run');
    return;
  }
  _executorRunning = true;
  try {
    const schedule = await fetchGitHubJson(PR_SCHEDULE_PATH, {});
    const now      = Date.now();
    const due      = Object.entries(schedule).filter(
      ([, job]) => new Date(job.execute_after).getTime() <= now
    );

    if (!due.length) return;
    console.log(`[PR executor] ${due.length} job(s) due for execution`);

    for (const [country, job] of due) {
      const isAppend = job.mode === 'append';
      console.log(`[PR executor] Executing scheduled ${isAppend ? `append (batch ${job.batch_id})` : 'PR'} for "${country}" (scheduled by ${job.created_by})`);

      try {
        const buffer     = await fetchGitHubJson('data/ops/buffer.json', {});
        const countryBuf = buffer[country] || {};
        const allEntries = Object.values(countryBuf).flat();
        // Apply role-based scope: executor fires on behalf of the job creator
        const execUsers    = await fetchGitHubJson('config/users.json', []);
        const scopedAll    = _filterEntriesByPRScope(allEntries, execUsers, job.created_by);

        // Honour the entry_ids snapshot: only process entries that were part of
        // this scheduled batch, not any new entries added after scheduling.
        const validated = Array.isArray(job.entry_ids)
          ? scopedAll.filter(e => e.status === 'validated' && job.entry_ids.includes(e.id))
          : scopedAll.filter(e => e.status === 'validated');
        const scopedPending = scopedAll.filter(e => e.status === 'pending');

        // Remove the job from the schedule regardless of outcome — avoids retry loops
        const freshSchedule = await fetchGitHubJson(PR_SCHEDULE_PATH, {});
        delete freshSchedule[country];
        await commitJsonToMainBranch(PR_SCHEDULE_PATH, freshSchedule, `ops: complete ${isAppend ? 'append' : 'PR'} schedule job for ${country}`);

        if (isAppend) {
          // ── Mode B: Append to existing active PR ─────────────────────────────
          const activePR = job.active_pr;
          if (!activePR || !activePR.prNumber || !activePR.branchName) {
            console.error(`[PR executor] Append job for "${country}" missing active_pr metadata — skipping`);
            appendActivityLog({ event: 'pr-append-failed', country, error: 'Missing active_pr metadata in job', by: 'system@executor' });
            continue;
          }
          if (!validated.length) {
            console.warn(`[PR executor] Append job for "${country}" has no validated entries — skipping`);
            appendActivityLog({ event: 'pr-append-failed', country, error: 'No validated entries at execution time', by: 'system@executor', batchId: job.batch_id });
            continue;
          }

          // Mode B pre-flight: PR still open, branch exists, no conflicts/duplicates
          const appendPreflight = await _preflightAppendCheck(country, validated, activePR);
          if (!appendPreflight.ok) {
            console.warn(`[PR executor] Append pre-flight failed for "${country}" PR #${activePR.prNumber}: ${appendPreflight.error}`);
            appendActivityLog({
              event:    'pr-append-failed',
              country,
              error:    appendPreflight.error,
              prNumber: activePR.prNumber,
              batchId:  job.batch_id,
              by:       'system@executor'
            });
            continue;
          }

          const appendResult = await _appendToActivePR(country, validated, job.created_by, activePR, job.batch_id);

          if (appendResult.success) {
            console.log(`[PR executor] Append batch ${job.batch_id} committed to PR #${activePR.prNumber} for "${country}"`);
            await _moveBufToHistoryAfterAppend(country, validated, activePR, job.created_by, job.batch_id);
            appendActivityLog({
              event:         'pr-append-created',
              by:            job.created_by,
              country,
              branchName:    activePR.branchName,
              prNumber:      activePR.prNumber,
              prUrl:         activePR.prUrl,
              entryCount:    validated.length,
              batchId:       job.batch_id,
              trigger:       'scheduled'
            });
          } else {
            console.error(`[PR executor] Append failed for "${country}" PR #${activePR.prNumber}: ${appendResult.error}`);
            appendActivityLog({
              event:     'pr-append-failed',
              country,
              error:     appendResult.error,
              prNumber:  activePR.prNumber,
              batchId:   job.batch_id,
              by:        'system@executor'
            });
          }

        } else {
          // ── Mode A: Create new PR ─────────────────────────────────────────────
          // Pre-flight check (token, base branch, validated entries, open PR guard)
          const preflight = await _preflightPRCheck(country, validated);
          if (!preflight.ok) {
            console.warn(`[PR executor] Pre-flight failed for "${country}": ${preflight.error}`);
            appendActivityLog({
              event:   'pr-preflight-failed',
              country,
              error:   preflight.error,
              by:      'system@executor'
            });
            continue;
          }

          const prResult = await _createPRForCountry(country, validated, job.created_by);

          if (prResult.success) {
            // Buffer entries only move to History after PR scope is verified clean.
            // _createPRForCountry already ran _verifyPRFileScope internally.
            console.log(`[PR executor] PR #${prResult.prNumber} created for "${country}" → ${prResult.prUrl}`);
            await _moveBufToHistoryAfterPR(country, validated, prResult, job.created_by);

            appendActivityLog({
              event:      'pr-created',
              by:         job.created_by,
              country,
              branchName: prResult.branchName,
              prNumber:   prResult.prNumber,
              prUrl:      prResult.prUrl,
              entryCount: validated.length,
              trigger:    'scheduled'
            });
          } else {
            // Do NOT move buffer entries to history on failure or scope violation.
            const isScopeViolation = !!prResult.scopeViolation;
            console.error(`[PR executor] PR ${isScopeViolation ? 'scope violation' : 'creation failed'} for "${country}": ${prResult.error}`);
            appendActivityLog({
              event:         isScopeViolation ? 'pr-scope-violation' : 'pr-create-failed',
              country,
              error:         prResult.error,
              branchName:    prResult.branchName,
              prNumber:      prResult.prNumber,
              blockedFiles:  prResult.blockedFiles,
              by:            'system@executor'
            });
          }
        }

      } catch (jobErr) {
        console.error(`[PR executor] Unexpected error for "${country}":`, jobErr.message);
      }
    }
  } finally {
    _executorRunning = false;
  }
}

/**
 * Lazy hybrid trigger: called at the start of schedule/status endpoints so
 * that a Render instance waking from sleep still executes due jobs promptly.
 */
async function _maybeTriggerScheduledPRs() {
  _runScheduledPRExecutor().catch(err =>
    console.error('[PR executor] lazy trigger error:', err.message)
  );
}

// ─── Rich Process Content V1: Staged/Final Media Model ───────────────────────
//
// Upload path:   assets/process-media/_staged/{country}/{processId}/{uuid}.webp
// Final path:    assets/process-media/{country}/{processId}/{uuid}.webp
//
// Lifecycle:
//   1. OPS user uploads image → stored at _staged path on main branch
//   2. Buffer entry references staged src in its process HTML
//   3. On PR approve (merge): staged files are copied to final paths,
//      process HTML src refs are rewritten to final paths, staged files deleted
//   4. On PR reject:  staged files (those no longer referenced) are cleaned up
//   5. On Buffer cancel: staged files introduced only by that entry are cleaned up
//
// This ensures no unapproved media is ever committed to a non-staged final path.

/**
 * Governance constants for media uploads.
 */
const MEDIA_MAX_SIZE_BYTES        = 1 * 1024 * 1024; // 1 MB raw upload limit
const MEDIA_MAX_STORED_WIDTH      = 1200;             // px — stored width after processing
const MEDIA_MAX_DISPLAY_WIDTH     = 800;              // px — enforced by sanitizer
const MEDIA_DEFAULT_DISPLAY_WIDTH = 600;              // px — default display width
const MEDIA_MIN_DISPLAY_WIDTH     = 200;              // px — minimum display width
const MEDIA_MAX_IMAGES_PER_PROCESS = 3;               // max images per process
const MEDIA_ALLOWED_MIME = new Set(['image/png','image/jpeg','image/webp']);
const MEDIA_ALLOWED_EXT  = new Set(['.png','.jpg','.jpeg','.webp']);

// Path prefixes
const MEDIA_STAGED_PREFIX = 'assets/process-media/_staged/';
const MEDIA_FINAL_PREFIX  = 'assets/process-media/';

/**
 * Validates that `imagePath` is a safe path under assets/process-media/.
 * Accepts both staged (_staged/) and final paths.
 * Prevents path traversal and unsafe characters.
 */
function _isValidMediaPath(imagePath) {
  if (!imagePath || typeof imagePath !== 'string') return false;
  if (!imagePath.startsWith('assets/process-media/')) return false;
  // No traversal
  if (imagePath.includes('..')) return false;
  // Only safe chars: letters, digits, /, -, _, .
  if (!/^[a-zA-Z0-9/_.\-]+$/.test(imagePath)) return false;
  // Must end in .webp (only stored format)
  if (!imagePath.endsWith('.webp')) return false;
  return true;
}

/**
 * Check whether a media path is in the staging area (_staged/ prefix).
 */
function _isStagedPath(mediaPath) {
  return typeof mediaPath === 'string' && mediaPath.startsWith(MEDIA_STAGED_PREFIX);
}

/**
 * Check whether a media path is in the final (approved) area.
 * Final paths: assets/process-media/{country}/... (not _staged/)
 */
function _isFinalPath(mediaPath) {
  return typeof mediaPath === 'string' &&
    mediaPath.startsWith(MEDIA_FINAL_PREFIX) &&
    !mediaPath.startsWith(MEDIA_STAGED_PREFIX);
}

/**
 * Validate a final (non-staged) media path structure.
 * Pattern: assets/process-media/{country}/{processId}/{uuid}.webp
 * where country = [a-z0-9_-]+, processId = [a-zA-Z0-9_-]+, uuid = valid uuid.webp
 */
function _isValidFinalMediaPath(p) {
  if (!_isValidMediaPath(p)) return false;
  if (_isStagedPath(p)) return false;
  // Must be exactly assets/process-media/{country}/{processId}/{uuid}.webp — 4 segments
  const rel = p.slice(MEDIA_FINAL_PREFIX.length); // country/processId/uuid.webp
  const parts = rel.split('/');
  if (parts.length !== 3) return false;
  const [country, processId, file] = parts;
  if (!country || !/^[a-z0-9_-]+$/.test(country)) return false;
  if (!processId || !/^[a-zA-Z0-9_-]+$/.test(processId)) return false;
  if (!file || !file.endsWith('.webp') || file.length < 40) return false; // uuid is 36 chars + .webp
  return true;
}

/**
 * Validate a staged media path structure.
 * Pattern: assets/process-media/_staged/{country}/{processId}/{uuid}.webp
 */
function _isValidStagedMediaPath(p) {
  if (!_isValidMediaPath(p)) return false;
  if (!_isStagedPath(p)) return false;
  const rel = p.slice(MEDIA_STAGED_PREFIX.length); // country/processId/uuid.webp
  const parts = rel.split('/');
  if (parts.length !== 3) return false;
  const [country, processId, file] = parts;
  if (!country || !/^[a-z0-9_-]+$/.test(country)) return false;
  if (!processId || !/^[a-zA-Z0-9_-]+$/.test(processId)) return false;
  if (!file || !file.endsWith('.webp') || file.length < 40) return false;
  return true;
}

/**
 * Convert a staged path to its final (approved) path equivalent.
 * assets/process-media/_staged/{country}/{processId}/{uuid}.webp
 *   → assets/process-media/{country}/{processId}/{uuid}.webp
 */
function _stagedToFinalPath(stagedPath) {
  if (!_isStagedPath(stagedPath)) return stagedPath;
  return MEDIA_FINAL_PREFIX + stagedPath.slice(MEDIA_STAGED_PREFIX.length);
}

/**
 * Generate a deterministic image filename: {uuid}.webp
 * Using crypto.randomUUID() — no original filename stored.
 */
function _generateImageId() {
  return `${crypto.randomUUID()}.webp`;
}

/**
 * Upload a GitHub binary (base64) file using the Contents API.
 * Creates or overwrites the file at path with the given base64 content.
 */
async function _uploadMediaToGitHub(filePath, base64Content, message) {
  // Check if file already exists (need its SHA to update)
  const existing = await getGitHubFileContent(filePath);
  const sha = existing?.sha || undefined;

  const body = {
    message,
    content: base64Content,
    branch: GITHUB_BRANCH
  };
  if (sha) body.sha = sha;

  const res = await fetch(
    `${GITHUB_API_BASE}/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${filePath}`,
    {
      method: 'PUT',
      headers: ghHeaders(),
      body: JSON.stringify(body)
    }
  );
  if (!res.ok) {
    const errText = await res.text().catch(() => '');
    throw new Error(`GitHub media upload failed (HTTP ${res.status}): ${errText}`);
  }
  return res.json();
}

/**
 * Delete a file from GitHub using the Contents API.
 * Returns true on success, false if file not found or delete failed.
 */
async function _deleteMediaFromGitHub(filePath, reason) {
  const existing = await getGitHubFileContent(filePath);
  if (!existing?.sha) return false; // already gone

  const res = await fetch(
    `${GITHUB_API_BASE}/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${filePath}`,
    {
      method: 'DELETE',
      headers: ghHeaders(),
      body: JSON.stringify({
        message: `ops: delete media ${filePath} — ${reason}`,
        sha: existing.sha,
        branch: GITHUB_BRANCH
      })
    }
  );
  return res.ok;
}

/**
 * Collects all img src references from a process.process HTML string.
 */
function _extractMediaRefs(processHtml) {
  if (!processHtml || typeof processHtml !== 'string') return new Set();
  const refs = new Set();
  const re = /src="(assets\/process-media\/[^"]+)"/gi;
  let m;
  while ((m = re.exec(processHtml)) !== null) refs.add(m[1]);
  return refs;
}

/**
 * Check if a media path is still referenced by any production process,
 * active buffer entry, or history entry. Returns true if referenced (must NOT delete).
 * @param {string}  mediaPath           - exact path to check
 * @param {string}  [excludeProcessId]  - skip this process ID when scanning production
 * @param {string}  [excludeBufferEntryId] - skip this buffer entry ID when scanning buffer
 */
async function _isMediaReferenced(mediaPath, excludeProcessId = null, excludeBufferEntryId = null) {
  // 1. Production processes (all countries — media paths are globally unique by UUID)
  const allCountriesRes = await fetchGitHubJson('config/countries.json', []);
  for (const c of allCountriesRes) {
    const pd = await readProcessData(c.key);
    if (!pd) continue;
    for (const p of pd.data) {
      if (excludeProcessId && p.id === excludeProcessId) continue;
      if (_extractMediaRefs(p.process).has(mediaPath)) return true;
    }
  }

  // 2. Active buffer entries (all countries)
  const buffer = await fetchGitHubJson('data/ops/buffer.json', {});
  for (const ck of Object.keys(buffer)) {
    for (const userEntries of Object.values(buffer[ck] || {})) {
      for (const entry of (userEntries || [])) {
        if (excludeBufferEntryId && entry.id === excludeBufferEntryId) continue;
        if (entry.type !== 'delete' && _extractMediaRefs(entry.process?.process).has(mediaPath)) {
          return true;
        }
      }
    }
  }

  // 3. History entries (pending_merge and merged) — media from recently approved processes
  const history = await fetchGitHubJson('data/ops/history.json', {});
  for (const ck of Object.keys(history)) {
    for (const entry of (history[ck] || [])) {
      // Check both before and after snapshots if present
      const snapshots = [entry.process?.process, entry.beforeSnapshot?.process, entry.afterSnapshot?.process];
      for (const snap of snapshots) {
        if (snap && _extractMediaRefs(snap).has(mediaPath)) return true;
      }
    }
  }

  return false;
}

/**
 * Promote staged media files to final paths after Publish Request approval.
 * For each staged src ref in matchingEntries' process HTML:
 *   1. Read staged file from GitHub
 *   2. Write to final path
 *   3. Delete staged file
 *   4. Rewrite process HTML src refs from staged → final
 *
 * Updates matchingEntries process HTML in-place and writes updated process data to GitHub.
 * Returns summary { promoted[], failed[], rewroteEntries }.
 *
 * @param {string} country
 * @param {Array}  matchingEntries - history entries for the approved PR
 */
async function _promoteStagedMedia(country, matchingEntries) {
  const promoted = [];
  const failed   = [];
  let rewroteEntries = 0;

  // Collect all staged refs across all matching history entries
  const allStagedRefs = new Set();
  for (const h of matchingEntries) {
    const processHtml = h.process?.process || h.afterSnapshot?.process || '';
    for (const ref of _extractMediaRefs(processHtml)) {
      if (_isStagedPath(ref)) allStagedRefs.add(ref);
    }
  }

  if (allStagedRefs.size === 0) return { promoted, failed, rewroteEntries };

  // Promote each staged file
  const pathMap = {}; // { stagedPath → finalPath }
  for (const stagedPath of allStagedRefs) {
    if (!_isValidStagedMediaPath(stagedPath)) {
      failed.push({ path: stagedPath, reason: 'invalid staged path structure' });
      continue;
    }
    const finalPath = _stagedToFinalPath(stagedPath);
    try {
      // Read staged file
      const fileInfo = await getGitHubFileContent(stagedPath);
      if (!fileInfo?.content) {
        failed.push({ path: stagedPath, reason: 'staged file not found on GitHub' });
        continue;
      }
      // Write to final path
      await _uploadMediaToGitHub(
        finalPath,
        fileInfo.content,
        `ops: promote staged media to final — ${country}`
      );
      // Delete staged file
      await _deleteMediaFromGitHub(stagedPath, `promoted to final after PR approval for ${country}`);
      pathMap[stagedPath] = finalPath;
      promoted.push({ staged: stagedPath, final: finalPath });
      console.log(`[media promote] ${stagedPath} → ${finalPath}`);
    } catch (err) {
      failed.push({ path: stagedPath, reason: err.message });
      console.warn(`[media promote] FAILED ${stagedPath}:`, err.message);
    }
  }

  // Rewrite HTML src refs in matchingEntries in-place
  if (Object.keys(pathMap).length > 0) {
    for (const h of matchingEntries) {
      let changed = false;
      // Rewrite in process snapshot
      if (h.process?.process && typeof h.process.process === 'string') {
        let html = h.process.process;
        Object.entries(pathMap).forEach(([sp, fp]) => {
          const next = html.split(`src="${sp}"`).join(`src="${fp}"`);
          if (next !== html) { html = next; changed = true; }
        });
        if (changed) h.process.process = html;
      }
      // Also rewrite afterSnapshot if present
      if (h.afterSnapshot?.process && typeof h.afterSnapshot.process === 'string') {
        let html = h.afterSnapshot.process;
        Object.entries(pathMap).forEach(([sp, fp]) => {
          html = html.split(`src="${sp}"`).join(`src="${fp}"`);
        });
        h.afterSnapshot.process = html;
      }
      if (changed) rewroteEntries++;
    }
  }

  return { promoted, failed, rewroteEntries };
}

/**
 * After a Publish Request approval, rewrite staged → final paths in the
 * live production process data on GitHub for the affected country.
 * Called after _promoteStagedMedia() has already moved the actual files.
 *
 * @param {string} country
 * @param {Object} pathMap - { stagedPath: finalPath }
 */
async function _rewriteProductionMediaPaths(country, pathMap) {
  if (!pathMap || Object.keys(pathMap).length === 0) return;
  const pd = await readProcessData(country);
  if (!pd) return;

  let changed = false;
  for (const p of pd.data) {
    if (!p.process || typeof p.process !== 'string') continue;
    let html = p.process;
    Object.entries(pathMap).forEach(([sp, fp]) => {
      const next = html.split(`src="${sp}"`).join(`src="${fp}"`);
      if (next !== html) { html = next; changed = true; }
    });
    if (changed) p.process = html;
  }

  if (changed) {
    await writeProcessData(country, pd.data, pd.meta || {});
    console.log(`[media rewrite] production data updated for ${country}`);
  }
}

/**
 * Cleanup staged media referenced by a specific set of history entries,
 * after a Publish Request has been rejected (refused).
 * Deletes staged files that are no longer referenced by production or active buffer.
 *
 * @param {string} country
 * @param {Array}  refusedEntries - history entries with pr_status='refused'
 */
async function _cleanupRejectedStagedMedia(country, refusedEntries) {
  const toClean = new Set();

  for (const h of refusedEntries) {
    const processHtml = h.process?.process || h.afterSnapshot?.process || '';
    for (const ref of _extractMediaRefs(processHtml)) {
      if (_isStagedPath(ref)) toClean.add(ref);
    }
  }

  if (toClean.size === 0) return { deleted: [], kept: [], errors: [] };

  const deleted = [], kept = [], errors = [];
  for (const stagedPath of toClean) {
    try {
      const stillReferenced = await _isMediaReferenced(stagedPath);
      if (stillReferenced) {
        kept.push(stagedPath);
        continue;
      }
      const ok = await _deleteMediaFromGitHub(stagedPath, `cleanup after PR rejection for ${country}`);
      if (ok) {
        deleted.push(stagedPath);
        console.log(`[media cleanup/reject] deleted staged ${stagedPath}`);
      } else {
        kept.push(stagedPath); // file may already be gone — safe
        errors.push(`${stagedPath}: delete returned false`);
      }
    } catch (err) {
      errors.push(`${stagedPath}: ${err.message}`);
      console.warn(`[media cleanup/reject] error cleaning ${stagedPath}:`, err.message);
    }
  }

  return { deleted, kept, errors };
}

/**
 * Cleanup images that were removed from a process when a modify entry is approved.
 * Compares before/after HTML from history entries; deletes images that appeared
 * in beforeSnapshot but not in afterSnapshot (i.e., removed during the edit),
 * subject to reference check.
 *
 * @param {string} country
 * @param {Array}  mergedEntries - history entries with type='update'
 */
async function _cleanupRemovedImagesAfterApproval(country, mergedEntries) {
  const deleted = [], kept = [], errors = [];

  for (const h of mergedEntries) {
    if (h.type !== 'update') continue;
    const beforeHtml = h.beforeSnapshot?.process || '';
    const afterHtml  = h.process?.process || h.afterSnapshot?.process || '';
    const beforeRefs = _extractMediaRefs(beforeHtml);
    const afterRefs  = _extractMediaRefs(afterHtml);

    // Images in before but not in after = removed during edit
    for (const ref of beforeRefs) {
      if (afterRefs.has(ref)) continue; // still present
      try {
        const stillReferenced = await _isMediaReferenced(ref, h.process?.originalProcessId);
        if (stillReferenced) {
          kept.push(ref);
          continue;
        }
        const ok = await _deleteMediaFromGitHub(ref, `removed image cleanup after approval for ${country}`);
        if (ok) {
          deleted.push(ref);
          console.log(`[media cleanup/approve-modify] deleted removed image ${ref}`);
        } else {
          kept.push(ref);
          errors.push(`${ref}: delete returned false`);
        }
      } catch (err) {
        errors.push(`${ref}: ${err.message}`);
        console.warn(`[media cleanup/approve-modify] error for ${ref}:`, err.message);
      }
    }
  }

  return { deleted, kept, errors };
}

/**
 * Cleanup images from a deleted process after Publish Request approval.
 * Deletes all media files referenced by the deleted process,
 * subject to reference check.
 *
 * @param {string} country
 * @param {Array}  mergedDeleteEntries - history entries with type='delete'
 */
async function _cleanupDeletedProcessImages(country, mergedDeleteEntries) {
  const deleted = [], kept = [], errors = [];

  for (const h of mergedDeleteEntries) {
    if (h.type !== 'delete') continue;
    const processHtml = h.beforeSnapshot?.process || h.process?.process || '';
    const refs = _extractMediaRefs(processHtml);

    for (const ref of refs) {
      try {
        const stillReferenced = await _isMediaReferenced(ref, h.process?.originalProcessId || h.originalProcessId);
        if (stillReferenced) {
          kept.push(ref);
          continue;
        }
        const ok = await _deleteMediaFromGitHub(ref, `deleted process cleanup after approval for ${country}`);
        if (ok) {
          deleted.push(ref);
          console.log(`[media cleanup/approve-delete] deleted ${ref}`);
        } else {
          kept.push(ref);
          errors.push(`${ref}: delete returned false`);
        }
      } catch (err) {
        errors.push(`${ref}: ${err.message}`);
        console.warn(`[media cleanup/approve-delete] error for ${ref}:`, err.message);
      }
    }
  }

  return { deleted, kept, errors };
}

/**
 * POST /api/ops/media/upload
 * Authenticated image upload endpoint.
 *
 * Form fields:
 *   - image (file) — the image to upload
 *   - country       — target country
 *   - processId     — target process ID (stable draft ID from client)
 *
 * Returns: { success, mediaPath, displaySrc, width, height }
 * mediaPath is the internal assets/process-media/ path stored in img src.
 */
app.post('/api/ops/media/upload', requireAuth, _mediaUpload.single('image'), async (req, res) => {
  const country   = (req.body?.country  || '').trim().toLowerCase();
  const processId = (req.body?.processId || '').trim();

  if (!country || !validateCountry(country)) {
    return res.status(400).json({ error: 'Valid country is required' });
  }
  if (!processId || !/^[a-zA-Z0-9_\-]+$/.test(processId) || processId.includes('..')) {
    return res.status(400).json({ error: 'Valid processId is required (alphanumeric, _, -)' });
  }

  // Country-scope check
  const scopeCheck = await _assertCountryAllowed(req.user, country);
  if (!scopeCheck.ok) return res.status(scopeCheck.status).json({ error: scopeCheck.error });

  if (!req.file) {
    return res.status(400).json({ error: 'No image file uploaded' });
  }

  const { buffer: fileBuffer, mimetype, originalname } = req.file;

  // MIME validation
  if (!MEDIA_ALLOWED_MIME.has(mimetype)) {
    return res.status(400).json({
      error: `Unsupported image type: ${mimetype}. Allowed: PNG, JPG/JPEG, WebP.`
    });
  }

  // Extension validation (secondary check)
  const ext = (originalname || '').toLowerCase().match(/\.[a-z0-9]+$/)?.[0] || '';
  if (!MEDIA_ALLOWED_EXT.has(ext)) {
    return res.status(400).json({
      error: `Unsupported file extension: ${ext}. Allowed: .png, .jpg, .jpeg, .webp`
    });
  }

  // Size validation (1 MB)
  if (fileBuffer.length > MEDIA_MAX_SIZE_BYTES) {
    return res.status(400).json({
      error: `Image too large: ${(fileBuffer.length / 1024 / 1024).toFixed(1)}MB. Maximum 1MB.`
    });
  }

  // Count existing images for this process in the buffer
  // (to enforce max 3 per process)
  const buffer = await fetchGitHubJson('data/ops/buffer.json', {});
  const countryBuf = buffer[country] || {};
  let existingImageCount = 0;
  outer: for (const userEntries of Object.values(countryBuf)) {
    for (const entry of (userEntries || [])) {
      if (entry.process?.id === processId || entry.process?.originalProcessId === processId) {
        existingImageCount = _extractMediaRefs(entry.process?.process || '').size;
        break outer;
      }
    }
  }
  if (existingImageCount >= MEDIA_MAX_IMAGES_PER_PROCESS) {
    return res.status(400).json({
      error: `Maximum ${MEDIA_MAX_IMAGES_PER_PROCESS} images allowed per process.`
    });
  }

  try {
    // Process image with sharp:
    // - Convert to WebP
    // - Resize to max MEDIA_MAX_STORED_WIDTH preserving aspect ratio
    // - Strip metadata
    const processed = await sharp(fileBuffer)
      .resize(MEDIA_MAX_STORED_WIDTH, null, {
        withoutEnlargement: true,
        fit: 'inside'
      })
      .webp({ quality: 82 })
      .withMetadata(false)
      .toBuffer();

    const imageId  = _generateImageId();
    // ── Write to STAGED path (not final) ─────────────────────────────────────
    // Staged images are promoted to final paths only after Admin PR approval.
    // Buffer preview references staged paths. Public production never sees staged.
    const mediaPath = `${MEDIA_STAGED_PREFIX}${country}/${processId}/${imageId}`;

    // Upload to GitHub (staged path)
    const base64Content = processed.toString('base64');
    await _uploadMediaToGitHub(
      mediaPath,
      base64Content,
      `ops: stage process image for ${country}/${processId}`
    );

    // Get dimensions for response
    const meta = await sharp(processed).metadata();

    console.log(`[media] staged ${mediaPath} (${processed.length} bytes, ${meta.width}x${meta.height})`);

    // previewDataUri: base64 data URI of the processed WebP.
    // Used by the Quill authoring preview only — never stored in HTML or JSON.
    // The browser can render it immediately with no further network request and
    // no auth token required (data: URIs are inline; img elements never send
    // Authorization headers so the proxy auth gate cannot serve staged images).
    const previewDataUri = `data:image/webp;base64,${base64Content}`;

    res.json({
      success:        true,
      mediaPath,
      displaySrc:     mediaPath,
      previewDataUri,
      staged:         true,
      width:          meta.width  || MEDIA_MAX_STORED_WIDTH,
      height:         meta.height || null,
      defaultDisplayWidth: MEDIA_DEFAULT_DISPLAY_WIDTH
    });

  } catch (err) {
    console.error('[media upload] error:', err.message);
    res.status(500).json({ error: `Image processing failed: ${err.message}` });
  }
});

/**
 * POST /api/ops/media/cleanup
 * Authenticated endpoint to safely delete staged media images.
 * Called when a Buffer entry is cancelled/removed before final approval.
 *
 * Body: { country, processId, mediaPaths: string[], bufferEntryId? }
 * Returns: { success, deleted: string[], kept: string[], errors: string[] }
 */
app.post('/api/ops/media/cleanup', requireAuth, async (req, res) => {
  const { country, processId, mediaPaths, bufferEntryId } = req.body || {};

  if (!country || !validateCountry(country)) {
    return res.status(400).json({ error: 'Valid country is required' });
  }
  if (!Array.isArray(mediaPaths) || mediaPaths.length === 0) {
    return res.status(400).json({ error: 'mediaPaths array is required' });
  }

  // Country-scope check
  const scopeCheck = await _assertCountryAllowed(req.user, country);
  if (!scopeCheck.ok) return res.status(scopeCheck.status).json({ error: scopeCheck.error });

  const deleted = [];
  const kept    = [];
  const errors  = [];

  for (const rawPath of mediaPaths) {
    // Only valid staged paths may be deleted via this endpoint
    // (final paths are managed by the approve/reject lifecycle only)
    if (!_isValidStagedMediaPath(rawPath)) {
      errors.push(`${rawPath}: invalid or non-staged path — only staged media may be cleaned up manually`);
      continue;
    }
    // Safety: staged path must be under this country's staged folder
    if (!rawPath.startsWith(`${MEDIA_STAGED_PREFIX}${country}/`)) {
      errors.push(`${rawPath}: not in country staged media folder`);
      continue;
    }

    try {
      // Full reference check before deletion
      const stillReferenced = await _isMediaReferenced(rawPath, null, bufferEntryId);
      if (stillReferenced) {
        kept.push(rawPath);
        console.log(`[media cleanup] kept ${rawPath} — still referenced`);
        continue;
      }
      const ok = await _deleteMediaFromGitHub(rawPath, `staged cleanup by ${req.user.email}`);
      if (ok) {
        deleted.push(rawPath);
        console.log(`[media cleanup] deleted staged ${rawPath}`);
      } else {
        kept.push(rawPath);
        errors.push(`${rawPath}: delete returned false`);
      }
    } catch (err) {
      errors.push(`${rawPath}: ${err.message}`);
    }
  }

  appendActivityLog({
    event:     'media-cleanup',
    by:        req.user.email,
    country,
    processId: processId || null,
    deleted,
    kept,
    errors
  }).catch(() => {});

  res.json({ success: true, deleted, kept, errors });
});

/**
 * POST /api/ops/media/copy
 * Duplicates image files from a source country/process into a destination
 * country/process staged folder. Used by copy-to-country.
 *
 * Source can be staged or final paths. Destination is always a new staged path.
 * (The copied process goes through its own Buffer → PR → approve lifecycle.)
 *
 * Body: {
 *   srcCountry, dstCountry,
 *   srcProcessId, dstProcessId,
 *   mediaPaths: string[]   // original src paths to copy
 * }
 * Returns: { success, pathMap: { [srcPath]: dstStagedPath }, errors: string[] }
 */
app.post('/api/ops/media/copy', requireAuth, async (req, res) => {
  const { srcCountry, dstCountry, srcProcessId, dstProcessId, mediaPaths } = req.body || {};

  if (!srcCountry || !validateCountry(srcCountry)) {
    return res.status(400).json({ error: 'Valid srcCountry is required' });
  }
  if (!dstCountry || !validateCountry(dstCountry)) {
    return res.status(400).json({ error: 'Valid dstCountry is required' });
  }
  if (!Array.isArray(mediaPaths) || mediaPaths.length === 0) {
    return res.json({ success: true, pathMap: {}, errors: [] }); // no-op
  }

  // Scope: user must have access to destination country
  const scopeCheck = await _assertCountryAllowed(req.user, dstCountry);
  if (!scopeCheck.ok) return res.status(scopeCheck.status).json({ error: scopeCheck.error });

  const pathMap = {};
  const errors  = [];

  for (const srcPath of mediaPaths) {
    // Source must be a valid media path (staged or final)
    if (!_isValidMediaPath(srcPath)) {
      errors.push(`${srcPath}: invalid media path`);
      continue;
    }
    // Source must belong to the source country (either staged or final)
    const expectedStagedPrefix = `${MEDIA_STAGED_PREFIX}${srcCountry}/`;
    const expectedFinalPrefix  = `${MEDIA_FINAL_PREFIX}${srcCountry}/`;
    if (!srcPath.startsWith(expectedStagedPrefix) && !srcPath.startsWith(expectedFinalPrefix)) {
      errors.push(`${srcPath}: not in source country media folder`);
      continue;
    }

    try {
      // Read source file content from GitHub
      const fileInfo = await getGitHubFileContent(srcPath);
      if (!fileInfo?.content) {
        errors.push(`${srcPath}: source file not found`);
        continue;
      }

      // Destination is always a new staged path — copied process follows its own lifecycle
      const newImageId = _generateImageId();
      const dstPath    = `${MEDIA_STAGED_PREFIX}${dstCountry}/${dstProcessId}/${newImageId}`;

      await _uploadMediaToGitHub(
        dstPath,
        fileInfo.content, // already base64
        `ops: copy media from ${srcCountry}/${srcProcessId} to staged ${dstCountry}/${dstProcessId}`
      );

      pathMap[srcPath] = dstPath;
      console.log(`[media copy] ${srcPath} → ${dstPath} (staged)`);

    } catch (err) {
      errors.push(`${srcPath}: ${err.message}`);
    }
  }

  res.json({ success: true, pathMap, errors });
});

// ─── Test exports (only when required as a module, not when run directly) ────
// Allows test files to import pure functions without starting the HTTP server.
if (require.main !== module) {
  module.exports = {
    sanitizeProcessHtml,
    _safeMediaSrc,
    _safeLinkHref,
    _isValidMediaPath,
    _isValidStagedMediaPath,
    _isValidFinalMediaPath,
    _isStagedPath,
    _isFinalPath,
    _stagedToFinalPath,
    _extractMediaRefs,
    _isAllowedPRPath,
    validateProcessEntry,
    // constants
    MEDIA_MAX_IMAGES_PER_PROCESS: 3,
    MEDIA_MAX_SIZE_BYTES:        1 * 1024 * 1024,
    MEDIA_MAX_STORED_WIDTH:      1200,
    MEDIA_MAX_DISPLAY_WIDTH:     800,
    MEDIA_DEFAULT_DISPLAY_WIDTH: 600,
    MEDIA_MIN_DISPLAY_WIDTH:     200,
    MEDIA_STAGED_PREFIX:         'assets/process-media/_staged/',
    MEDIA_FINAL_PREFIX:          'assets/process-media/'
  };
}

// ─── Start ────────────────────────────────────────────────────────────────────

if (require.main === module) app.listen(port, () => {
  console.log(`Process Finder server listening on http://localhost:${port}`);
  console.log('[STORAGE] GitHub-only mode — no local filesystem used');
  console.log(GITHUB_TOKEN
    ? `[OPS] GitHub automation enabled — target branch: ${GITHUB_TARGET_BRANCH} (${GITHUB_OWNER}/${GITHUB_REPO})`
    : `[OPS] WARNING: GITHUB_TOKEN not configured — PR automation disabled`);
  if (GITHUB_TARGET_BRANCH !== 'main') {
    console.warn(`[OPS] WARNING: GITHUB_TARGET_BRANCH="${GITHUB_TARGET_BRANCH}", not "main". Set GITHUB_TARGET_BRANCH=main in Render for production — PRs are currently targeting the wrong branch.`);
  }
  if (DISABLE_PR_CREATION) {
    console.warn('[OPS] WARNING: DISABLE_PR_CREATION=true — all PR creation, branch creation, and buffer-to-history movements are disabled.');
  }

  // ── Scheduled PR executor — runs every 60 seconds ────────────────────────
  // Hybrid approach: setInterval catches active sessions; lazy execution in
  // _maybeTriggerScheduledPRs() fires on any authenticated API call so that
  // Render cold-start / sleep scenarios are also handled.
  const PR_EXEC_INTERVAL_MS = 60 * 1000;
  setInterval(() => {
    _runScheduledPRExecutor().catch(err =>
      console.error('[PR executor] Unhandled error:', err.message)
    );
  }, PR_EXEC_INTERVAL_MS);
  console.log('[PR executor] Scheduled PR executor running every 60 seconds');
});
