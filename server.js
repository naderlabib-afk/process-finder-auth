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
const OPS_PR_ALLOWED_PATH_PREFIX = 'data/processes/';

function _isAllowedPRPath(filePath) {
  return typeof filePath === 'string' && filePath.startsWith(OPS_PR_ALLOWED_PATH_PREFIX);
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
      `https://api.github.ibm.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/pulls/${prNumber}/files`,
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
 *   3. Validated entries provided
 *   4. No pending entries remain
 *   5. No PR already open for this country
 */
async function _preflightPRCheck(country, validatedEntries, allEntries) {
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

  const pendingCount = (allEntries || []).filter(e => e.status === 'pending').length;
  if (pendingCount > 0) {
    return {
      ok: false, httpStatus: 400,
      error: `${pendingCount} pending entr${pendingCount > 1 ? 'ies' : 'y'} must be validated or removed before creating a PR`
    };
  }

  const hasOpen = await _hasOpenPRForCountry(country);
  if (hasOpen) {
    return {
      ok: false, httpStatus: 409,
      error: 'A PR package is already pending approval for this country'
    };
  }

  return { ok: true };
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
  const { country, type, process } = req.body;
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
 * Hard-deletes a single buffer entry. No history write, no audit log.
 * New workflow: cancel = remove without trace.
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

  const buffer  = await fetchGitHubJson('data/ops/buffer.json', {});
  const entries = (buffer[country] && buffer[country][targetUser]) || [];

  if (!entries[index]) {
    return res.status(404).json({ error: 'Buffer entry not found' });
  }

  const entry = entries[index];

  // OL permission check: can only remove own pending entries
  if (cancellerRole === 'OL') {
    const ownerEmail = (entry.user || targetUser || '').toLowerCase().trim();
    if (ownerEmail !== canceller.toLowerCase().trim()) {
      return res.status(403).json({ error: 'OL can only remove their own entries' });
    }
    if (entry.status === 'validated') {
      return res.status(403).json({ error: 'OL cannot remove a validated entry' });
    }
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

  // Splice out — no history write, no log entry
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

  const targetUser = req.body.user;
  if (!targetUser) return res.status(400).json({ error: 'user field required to identify buffer queue' });

  const buffer  = await fetchGitHubJson('data/ops/buffer.json', {});
  const entries = (buffer[country] && buffer[country][targetUser]) || [];
  const entry   = entries[index];

  if (!entry) {
    return res.status(404).json({ error: 'Buffer entry not found' });
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
  try {
    // Read all buffer entries for this country
    const buffer       = await fetchGitHubJson('data/ops/buffer.json', {});
    const countryBuf   = buffer[country] || {};
    const allEntries   = Object.values(countryBuf).flat();
    const validatedEntries = allEntries.filter(e => e.status === 'validated');

    // Run the same pre-flight check used by the scheduled executor
    const preflight = await _preflightPRCheck(country, validatedEntries, allEntries);
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

// ─── Activity Log helper ──────────────────────────────────────────────────────
/**
 * Appends an entry to data/logs/activity_logs.json on GitHub.
 * Only called for impactful events: validation, PR scheduled, PR created,
 * PR merged, PR refused, rollback.
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
const PR_DELAY_MS  = 10 * 60 * 1000; // 10 minutes
const PR_SCHEDULE_PATH = 'data/ops/pr_schedule.json';

/**
 * Returns true if there is currently an open (not merged, not closed) PR
 * for the given country by searching GitHub for PRs from branches matching
 * the OPS branch naming pattern.
 *
 * Matches both the new pattern  ops/<country>/<timestamp>
 * and the legacy pattern        <country>_<timestamp>
 * so that existing open PRs created before this fix are still detected.
 */
async function _hasOpenPRForCountry(country) {
  try {
    const res = await fetch(
      `https://api.github.ibm.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/pulls?state=open&per_page=50`,
      { headers: ghHeaders() }
    );
    if (!res.ok) return false;
    const prs = await res.json();
    return prs.some(pr => {
      const ref = pr.head && pr.head.ref ? pr.head.ref : '';
      // New naming: ops/<country>/...
      if (ref.startsWith(`ops/${country}/`)) return true;
      // Legacy naming: <country>_YYYYMMDD_HHMM
      if (ref.startsWith(`${country}_`)) return true;
      return false;
    });
  } catch {
    return false;
  }
}

// ─── PR Schedule routes ───────────────────────────────────────────────────────

/**
 * GET /api/ops/pr/schedule
 * Returns the full pr_schedule.json so the frontend can render countdown timers.
 */
app.get('/api/ops/pr/schedule', async (req, res) => {
  await _maybeTriggerScheduledPRs(); // lazy hybrid trigger
  res.json(await fetchGitHubJson(PR_SCHEDULE_PATH, {}));
});

/**
 * POST /api/ops/pr/schedule
 * Schedules a PR for a country (10-minute delayed creation).
 * All roles (OL, Manager, Admin) may call this.
 *
 * Blocked if:
 *   - Any buffer entry for this country is still "pending" (not all validated)
 *   - A PR job is already scheduled for this country
 *   - A PR is already open on GitHub for this country
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

  const [buffer, schedule] = await Promise.all([
    fetchGitHubJson('data/ops/buffer.json', {}),
    fetchGitHubJson(PR_SCHEDULE_PATH, {})
  ]);

  // Block if already scheduled
  if (schedule[country]) {
    return res.status(409).json({ error: 'A PR is already scheduled for this country', job: schedule[country] });
  }

  // Block if open PR exists on GitHub
  const hasOpen = await _hasOpenPRForCountry(country);
  if (hasOpen) {
    return res.status(409).json({ error: 'A PR is already open on GitHub for this country' });
  }

  // Collect all entries for this country from the buffer
  const countryBuf      = buffer[country] || {};
  const allEntries      = Object.values(countryBuf).flat();
  const validatedCount  = allEntries.filter(e => e.status === 'validated').length;
  const pendingCount    = allEntries.filter(e => e.status === 'pending').length;

  if (!validatedCount) {
    return res.status(400).json({ error: 'No validated entries to create a PR for' });
  }
  if (pendingCount > 0) {
    return res.status(400).json({
      error: `${pendingCount} pending entr${pendingCount > 1 ? 'ies' : 'y'} must be validated or removed before scheduling a PR`
    });
  }

  // Snapshot the IDs of the validated entries included in this PR.
  // Used by the frontend to freeze exactly those entries during countdown.
  const validatedEntryIds = allEntries
    .filter(e => e.status === 'validated')
    .map(e => e.id)
    .filter(Boolean);

  const now = new Date();
  const job = {
    country,
    scheduled_at:  now.toISOString(),
    execute_after: new Date(now.getTime() + PR_DELAY_MS).toISOString(),
    created_by:    req.user.email,
    delay_ms:      PR_DELAY_MS,
    entry_count:   validatedCount,
    entry_ids:     validatedEntryIds
  };

  schedule[country] = job;
  await commitJsonToMainBranch(PR_SCHEDULE_PATH, schedule, `ops: schedule PR for ${country} by ${req.user.email}`);

  appendActivityLog({
    event:       'pr-scheduled',
    by:          req.user.email,
    country,
    execute_after: job.execute_after,
    entryCount:  validatedCount
  });

  console.log(`[PR schedule] Scheduled PR for "${country}" to execute after ${job.execute_after}`);
  res.json({ success: true, job });
});

/**
 * DELETE /api/ops/pr/schedule/:country
 * Cancels (undoes) a scheduled PR job. Available during the 10-minute window.
 * All roles may undo a PR they can see.
 */
app.delete('/api/ops/pr/schedule/:country', requireAuth, async (req, res) => {
  const country = (req.params.country || '').toLowerCase();
  if (!validateCountry(country)) {
    return res.status(400).json({ error: 'Invalid country' });
  }

  const schedule = await fetchGitHubJson(PR_SCHEDULE_PATH, {});
  if (!schedule[country]) {
    return res.status(404).json({ error: 'No scheduled PR found for this country' });
  }

  const job = schedule[country];
  delete schedule[country];
  await commitJsonToMainBranch(PR_SCHEDULE_PATH, schedule, `ops: undo PR schedule for ${country} by ${req.user.email}`);

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
      fetch(`https://api.github.ibm.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/pulls/${prNumber}/files`, { headers: ghHeaders() })
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

// ─── Logs read endpoint ───────────────────────────────────────────────────────

/**
 * GET /api/ops/logs
 * Returns activity_logs.json — the new structured log (validation, PR events, rollback).
 */
app.get('/api/ops/logs', async (req, res) => {
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
      console.log(`[PR executor] Executing scheduled PR for "${country}" (scheduled by ${job.created_by})`);

      try {
        const buffer     = await fetchGitHubJson('data/ops/buffer.json', {});
        const countryBuf = buffer[country] || {};
        const allEntries = Object.values(countryBuf).flat();
        const validated  = allEntries.filter(e => e.status === 'validated');

        // Remove the job from the schedule regardless of outcome — avoids retry loops
        const freshSchedule = await fetchGitHubJson(PR_SCHEDULE_PATH, {});
        delete freshSchedule[country];
        await commitJsonToMainBranch(PR_SCHEDULE_PATH, freshSchedule, `ops: complete PR schedule job for ${country}`);

        // Pre-flight check (token, base branch, entry state, open PR guard)
        const preflight = await _preflightPRCheck(country, validated, allEntries);
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

// ─── Start ────────────────────────────────────────────────────────────────────

app.listen(port, () => {
  console.log(`Process Finder server listening on http://localhost:${port}`);
  console.log('[STORAGE] GitHub-only mode — no local filesystem used');
  console.log(GITHUB_TOKEN
    ? `[OPS] GitHub automation enabled — target branch: ${GITHUB_TARGET_BRANCH} (${GITHUB_OWNER}/${GITHUB_REPO})`
    : `[OPS] WARNING: GITHUB_TOKEN not configured — PR automation disabled`);

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
