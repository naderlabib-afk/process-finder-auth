#!/usr/bin/env node
/**
 * test-put-buffer-guards.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Validates the three per-entry security guards in PUT /api/ops/buffer.
 *
 *   Guard A — Per-entry ownership / role authorization
 *   Guard B — Validated-entry content-edit block (unvalidate → edit → revalidate)
 *   Guard C — Pending-merge / scheduled-PR lock
 *
 * Core security scenarios (Guards A, B, C):
 *   1. OL cannot edit a Manager-owned pending entry                       → 403
 *   2. OL cannot edit a Manager-owned validated entry                     → 403
 *   3. Peer OL cannot edit another OL's pending entry                     → 403
 *   4. Peer OL cannot edit another OL's validated entry                   → 403
 *   5. OL cannot directly edit own validated entry through PUT             → 403
 *   6. Manager cannot directly edit authorized OL-owned validated entry    → 403
 *   7. Peer Manager cannot edit peer Manager validated entry               → 403
 *   8. Scheduled/pending_merge entries locked for everyone                 → 409
 *
 * Workflow continuity scenarios:
 *   9.  OL can unvalidate own validated entry via POST /api/ops/validate   → 200
 *  10.  Manager can unvalidate OL-owned validated entry via validate route → 200
 *  11.  After unvalidate, OL can edit own (now-pending) entry via PUT      → 200
 *  12.  Manager can edit OL-owned (now-pending) entry via PUT              → 200
 *  13.  Valid same-owner pending edit (normal saveBufferEdit flow)          → 200
 *
 * Strategy:
 *   - Forks server.js as a child process on port 3109.
 *   - Starts a local mock GitHub API server on port 3108.
 *   - Uses GITHUB_API_BASE env var to redirect all GitHub API calls to mock.
 *   - Mints JWTs locally using the same TEST_JWT_SECRET injected into server.
 *
 * Safe: no real GitHub calls, no real commits, no production data touched.
 * Exit code 0 = all 13 scenarios passed. Non-zero = at least one failed.
 */

'use strict';

const http   = require('http');
const net    = require('net');
const path   = require('path');
const crypto = require('crypto');
const { fork } = require('child_process');

// ── Test accounting ────────────────────────────────────────────────────────────
let _pass = 0;
let _fail = 0;
const _failures = [];

function assert(label, condition, extra = '') {
  if (condition) {
    console.log(`  ✅ ${label}`);
    _pass++;
  } else {
    const msg = `${label}${extra ? ' — ' + extra : ''}`;
    console.error(`  ❌ ${msg}`);
    _failures.push(msg);
    _fail++;
  }
}

function section(title) {
  console.log(`\n── ${title} ${'─'.repeat(Math.max(0, 60 - title.length))}`);
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

// ── JWT helpers ────────────────────────────────────────────────────────────────
const TEST_JWT_SECRET = 'put-buffer-guards-test-secret-do-not-use-in-prod';

function b64url(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function mintJwt(payload) {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body   = b64url(JSON.stringify(payload));
  const sig    = b64url(
    crypto.createHmac('sha256', TEST_JWT_SECRET).update(`${header}.${body}`).digest()
  );
  return `${header}.${body}.${sig}`;
}

const now = Math.floor(Date.now() / 1000);
const ADMIN_TOKEN     = mintJwt({ email: 'admin@ibm.com',     role: 'Admin',   iat: now, exp: now + 28800 });
const OL_A_TOKEN      = mintJwt({ email: 'ol-a@ibm.com',      role: 'OL',      iat: now, exp: now + 28800 });
const OL_B_TOKEN      = mintJwt({ email: 'ol-b@ibm.com',      role: 'OL',      iat: now, exp: now + 28800 });
const MANAGER_A_TOKEN = mintJwt({ email: 'manager-a@ibm.com', role: 'Manager', iat: now, exp: now + 28800 });
const MANAGER_B_TOKEN = mintJwt({ email: 'manager-b@ibm.com', role: 'Manager', iat: now, exp: now + 28800 });

const SERVER_PORT = 3109;
const MOCK_PORT   = 3108;
const COUNTRY     = 'fr';

// ── Mock GitHub state ──────────────────────────────────────────────────────────
let mockState = {};
let _commits  = [];

function resetMockState(overrides = {}) {
  _commits = [];
  mockState = {
    'config/users.json': [
      { email: 'admin@ibm.com',     name: 'Admin',     role: 'Admin',   countries: ['all'] },
      { email: 'ol-a@ibm.com',      name: 'OL A',      role: 'OL',      countries: ['fr'] },
      { email: 'ol-b@ibm.com',      name: 'OL B',      role: 'OL',      countries: ['fr'] },
      { email: 'manager-a@ibm.com', name: 'Manager A', role: 'Manager', countries: ['fr'] },
      { email: 'manager-b@ibm.com', name: 'Manager B', role: 'Manager', countries: ['fr'] }
    ],
    // Buffer: ol-a has a pending entry and a validated entry;
    //         ol-b has a pending entry;
    //         manager-a has a pending entry;
    //         plus two entries locked by PR/schedule
    'data/ops/buffer.json': {
      fr: {
        'ol-a@ibm.com': [
          {
            id: 'fr_ola_pending',
            type: 'create',
            user: 'ol-a@ibm.com',
            status: 'pending',
            process: { id: 'fr_ola_pending', issue: 'OL-A-PENDING', category: 'Contract', machineType: '', process: 'content' },
            createdAt: new Date().toISOString()
          },
          {
            id: 'fr_ola_validated',
            type: 'create',
            user: 'ol-a@ibm.com',
            status: 'validated',
            process: { id: 'fr_ola_validated', issue: 'OL-A-VALIDATED', category: 'Contract', machineType: '', process: 'content' },
            createdAt: new Date().toISOString(),
            validatedAt: new Date().toISOString(),
            validatedBy: 'manager-a@ibm.com'
          },
          // Entry locked by scheduled PR
          {
            id: 'fr_sched_locked',
            type: 'create',
            user: 'ol-a@ibm.com',
            status: 'pending',
            process: { id: 'fr_sched_locked', issue: 'OL-A-SCHED', category: 'Contract', machineType: '', process: 'content' },
            createdAt: new Date().toISOString()
          }
        ],
        'ol-b@ibm.com': [
          {
            id: 'fr_olb_pending',
            type: 'create',
            user: 'ol-b@ibm.com',
            status: 'pending',
            process: { id: 'fr_olb_pending', issue: 'OL-B-PENDING', category: 'Contract', machineType: '', process: 'content' },
            createdAt: new Date().toISOString()
          }
        ],
        'manager-a@ibm.com': [
          {
            id: 'fr_mgra_pending',
            type: 'create',
            user: 'manager-a@ibm.com',
            status: 'pending',
            process: { id: 'fr_mgra_pending', issue: 'MGR-A-PENDING', category: 'Contract', machineType: '', process: 'content' },
            createdAt: new Date().toISOString()
          }
        ]
      }
    },
    // History: one entry in pending_merge (locked by open PR)
    'data/ops/history.json': {
      fr: [
        {
          id: 'fr_pr_locked',
          type: 'create',
          user: 'ol-a@ibm.com',
          pr_status: 'pending_merge',
          prNumber: 55,
          prUrl: 'https://github.ibm.com/nlabib/process-finder/pull/55',
          branchName: 'ops/fr/20260710-1000',
          process: { id: 'fr_pr_locked', issue: 'OL-A-IN-PR', category: 'Contract', machineType: '', process: 'content' }
        }
      ]
    },
    // Schedule: one scheduled PR job that locks fr_sched_locked
    'data/ops/pr_schedule.json': {
      fr: {
        mode: 'create',
        entry_ids: ['fr_sched_locked'],
        scheduled_at: new Date().toISOString(),
        execute_after: new Date(Date.now() + 600000).toISOString(),
        created_by: 'manager-a@ibm.com'
      }
    },
    'data/ops/assignment_history.json': [],
    'data/logs/activity_logs.json':     [],
    'data/logs/admin-audit.json':        [],
    'config/countries.json': [
      { key: 'fr', name: 'France', code: 'FR' }
    ],
    ...overrides
  };
}
resetMockState();

// ── Mock server ────────────────────────────────────────────────────────────────
function encodeFileContent(obj) {
  return Buffer.from(JSON.stringify(obj, null, 2)).toString('base64');
}

const mockServer = http.createServer((req, res) => {
  let body = '';
  req.on('data', c => { body += c; });
  req.on('end', () => {
    const send = (status, obj) => {
      const data = JSON.stringify(obj);
      res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) });
      res.end(data);
    };

    const p = (req.url || '').split('?')[0];
    const m = req.method;

    // GET /repos/.../contents/:path
    if (m === 'GET' && p.includes('/contents/')) {
      const match = p.match(/\/repos\/[^/]+\/[^/]+\/contents\/(.+)/);
      if (match) {
        const filePath = decodeURIComponent(match[1]);
        if (mockState[filePath] !== undefined) {
          return send(200, {
            path: filePath,
            sha:  'sha-' + filePath.replace(/\//g, '-'),
            content: encodeFileContent(mockState[filePath]) + '\n',
            encoding: 'base64'
          });
        }
        return send(404, { message: 'Not Found' });
      }
    }

    // PUT /repos/.../contents/:path  (file write / commit)
    if (m === 'PUT' && p.includes('/contents/') && !p.includes('/merge')) {
      const match = p.match(/\/repos\/[^/]+\/[^/]+\/contents\/(.+)/);
      if (match) {
        const filePath = decodeURIComponent(match[1]);
        let parsed; try { parsed = JSON.parse(body); } catch { parsed = {}; }
        if (parsed.content) {
          try {
            const decoded = Buffer.from(parsed.content, 'base64').toString('utf8');
            mockState[filePath] = JSON.parse(decoded);
            _commits.push({ path: filePath, message: parsed.message });
          } catch {}
        }
        return send(200, { content: { path: filePath, sha: 'new-sha' }, commit: { sha: 'abc123' } });
      }
    }

    // GET /repos/.../git/refs/heads/:branch  (needed by commitJsonToMainBranch)
    if (m === 'GET' && p.includes('/git/refs/heads/')) {
      return send(200, { ref: 'refs/heads/main', object: { sha: 'main-sha' } });
    }

    // GET /repos/.../pulls?state=open
    if (m === 'GET' && p.includes('/pulls') && !p.match(/\/pulls\/\d+/)) {
      return send(200, []);
    }

    send(404, { message: `Mock: no handler for ${m} ${p}` });
  });
});

// ── HTTP client helper ─────────────────────────────────────────────────────────
function apiCall(method, urlPath, bodyObj, token) {
  return new Promise((resolve, reject) => {
    const bodyStr = bodyObj ? JSON.stringify(bodyObj) : '';
    const opts = {
      hostname: 'localhost',
      port: SERVER_PORT,
      path: urlPath,
      method,
      headers: {
        'Content-Type':   'application/json',
        'Content-Length': Buffer.byteLength(bodyStr),
        'Authorization':  `Bearer ${token}`
      }
    };
    const req = http.request(opts, res => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => {
        let json; try { json = JSON.parse(data); } catch { json = null; }
        resolve({ status: res.statusCode, ok: res.statusCode >= 200 && res.statusCode < 300, json });
      });
    });
    req.on('error', reject);
    req.end(bodyStr);
  });
}

function waitForPort(port, retries = 30, delay = 300) {
  return new Promise((resolve, reject) => {
    function attempt(n) {
      const sock = net.connect(port, 'localhost');
      sock.on('connect', () => { sock.destroy(); resolve(); });
      sock.on('error', () => {
        sock.destroy();
        if (n <= 0) return reject(new Error(`Port ${port} never opened`));
        setTimeout(() => attempt(n - 1), delay);
      });
    }
    attempt(retries);
  });
}

// ── Helpers to build test PUT payloads ────────────────────────────────────────
// Takes the live mock buffer and returns a mutated copy for testing.

function cloneBuffer() {
  return JSON.parse(JSON.stringify(mockState['data/ops/buffer.json']));
}

// Mutates the issue text of one specific entry to simulate a content edit.
function touchEntry(buf, country, userEmail, entryId) {
  const entries = buf[country]?.[userEmail] || [];
  const entry   = entries.find(e => e.id === entryId);
  if (entry) entry.process.issue = entry.process.issue + '-EDITED';
  return buf;
}

// ── Main ───────────────────────────────────────────────────────────────────────
(async () => {
  // Start mock GitHub API server
  await new Promise(r => mockServer.listen(MOCK_PORT, '127.0.0.1', r));
  console.log(`[mock] GitHub API mock listening on port ${MOCK_PORT}`);

  // Fork the real server with test environment
  const serverEnv = {
    ...process.env,
    PORT:             String(SERVER_PORT),
    GITHUB_API_BASE:  `http://127.0.0.1:${MOCK_PORT}`,
    GITHUB_TOKEN:     'mock-token',
    GITHUB_OWNER:     'nlabib',
    GITHUB_REPO:      'process-finder',
    GITHUB_BRANCH:    'main',
    JWT_SECRET:       TEST_JWT_SECRET,
    EMAIL_SEND_MODE:  'mock',
    DISABLE_PR_CREATION: 'true'
  };

  const serverProc = fork(
    path.join(__dirname, 'server.js'),
    [],
    { env: serverEnv, silent: true }
  );
  serverProc.stdout?.on('data', d => { /* suppress */ });
  serverProc.stderr?.on('data', d => { /* suppress */ });

  try {
    await waitForPort(SERVER_PORT);
    console.log(`[server] listening on port ${SERVER_PORT}`);

    // ── CORE SECURITY SCENARIOS ───────────────────────────────────────────────

    section('1. OL cannot edit a Manager-owned pending entry');
    {
      resetMockState();
      const mgraEntry = cloneBuffer()[COUNTRY]['manager-a@ibm.com'].find(e => e.id === 'fr_mgra_pending');
      const edited = { ...mgraEntry, process: { ...mgraEntry.process, issue: 'MGR-A-STOLEN-BY-OL-A' } };
      const buf = { [COUNTRY]: { 'manager-a@ibm.com': [edited] } };
      const r = await apiCall('PUT', '/api/ops/buffer', { buffer: buf }, OL_A_TOKEN);
      assert('status is 403', r.status === 403, `got ${r.status}`);
      assert('code is OWNERSHIP_VIOLATION', r.json?.code === 'OWNERSHIP_VIOLATION', JSON.stringify(r.json));
    }

    // ─────────────────────────────────────────────────────────────────────────
    section('2. OL cannot edit a Manager-owned validated entry');
    {
      resetMockState();
      // Elevate manager-a's entry to validated
      const mgraEntryLive = mockState['data/ops/buffer.json'][COUNTRY]['manager-a@ibm.com'][0];
      mgraEntryLive.status = 'validated';
      mgraEntryLive.validatedBy = 'manager-a@ibm.com';
      const mgraEntry = cloneBuffer()[COUNTRY]['manager-a@ibm.com'].find(e => e.id === 'fr_mgra_pending');
      const edited = { ...mgraEntry, process: { ...mgraEntry.process, issue: 'MGR-A-VALIDATED-STOLEN-BY-OL' } };
      const buf = { [COUNTRY]: { 'manager-a@ibm.com': [edited] } };
      const r = await apiCall('PUT', '/api/ops/buffer', { buffer: buf }, OL_A_TOKEN);
      assert('status is 403', r.status === 403, `got ${r.status}`);
      // Guard A fires before Guard B
      assert('code is OWNERSHIP_VIOLATION', r.json?.code === 'OWNERSHIP_VIOLATION', JSON.stringify(r.json));
    }

    // ─────────────────────────────────────────────────────────────────────────
    section('3. Peer OL cannot edit another OL\'s pending entry');
    {
      resetMockState();
      const olbEntry = cloneBuffer()[COUNTRY]['ol-b@ibm.com'].find(e => e.id === 'fr_olb_pending');
      const edited = { ...olbEntry, process: { ...olbEntry.process, issue: 'OL-B-STOLEN-BY-OL-A' } };
      const buf = { [COUNTRY]: { 'ol-b@ibm.com': [edited] } };
      const r = await apiCall('PUT', '/api/ops/buffer', { buffer: buf }, OL_A_TOKEN);
      assert('status is 403', r.status === 403, `got ${r.status}`);
      assert('code is OWNERSHIP_VIOLATION', r.json?.code === 'OWNERSHIP_VIOLATION', JSON.stringify(r.json));
    }

    // ─────────────────────────────────────────────────────────────────────────
    section('4. Peer OL cannot edit another OL\'s validated entry');
    {
      resetMockState();
      const validatedEntry = cloneBuffer()[COUNTRY]['ol-a@ibm.com'].find(e => e.id === 'fr_ola_validated');
      const edited = { ...validatedEntry, process: { ...validatedEntry.process, issue: 'OL-A-VALIDATED-STOLEN-BY-OL-B' } };
      const buf = { [COUNTRY]: { 'ol-a@ibm.com': [edited] } };
      const r = await apiCall('PUT', '/api/ops/buffer', { buffer: buf }, OL_B_TOKEN);
      assert('status is 403', r.status === 403, `got ${r.status}`);
      // Guard A fires first (ownership), Guard B would also fire
      assert('code is OWNERSHIP_VIOLATION', r.json?.code === 'OWNERSHIP_VIOLATION', JSON.stringify(r.json));
    }

    // ─────────────────────────────────────────────────────────────────────────
    section('5. OL cannot directly edit own validated entry through PUT (Guard B)');
    // Even the entry owner cannot bypass the unvalidate→edit→revalidate workflow.
    // Guard B must fire because liveEntry.status === "validated".
    {
      resetMockState();
      const validatedEntry = cloneBuffer()[COUNTRY]['ol-a@ibm.com'].find(e => e.id === 'fr_ola_validated');
      const edited = { ...validatedEntry, process: { ...validatedEntry.process, issue: 'OL-A-VALIDATED-SELF-EDIT' } };
      const buf = { [COUNTRY]: { 'ol-a@ibm.com': [edited] } };
      const r = await apiCall('PUT', '/api/ops/buffer', { buffer: buf, editEntryId: 'fr_ola_validated' }, OL_A_TOKEN);
      assert('status is 403', r.status === 403, `got ${r.status}`);
      assert('code is UNVALIDATE_REQUIRED', r.json?.code === 'UNVALIDATE_REQUIRED', JSON.stringify(r.json));
    }

    // ─────────────────────────────────────────────────────────────────────────
    section('6. Manager cannot directly edit authorized OL-owned validated entry through PUT');
    // Manager is authorized to manage OL entries (Guard A passes).
    // But the entry is validated — Guard B must block.
    {
      resetMockState();
      const validatedEntry = cloneBuffer()[COUNTRY]['ol-a@ibm.com'].find(e => e.id === 'fr_ola_validated');
      const edited = { ...validatedEntry, process: { ...validatedEntry.process, issue: 'OL-A-VALIDATED-MGR-EDIT' } };
      const buf = { [COUNTRY]: { 'ol-a@ibm.com': [edited] } };
      const r = await apiCall('PUT', '/api/ops/buffer', { buffer: buf, editEntryId: 'fr_ola_validated' }, MANAGER_A_TOKEN);
      assert('status is 403', r.status === 403, `got ${r.status}`);
      assert('code is UNVALIDATE_REQUIRED', r.json?.code === 'UNVALIDATE_REQUIRED', JSON.stringify(r.json));
    }

    // ─────────────────────────────────────────────────────────────────────────
    section('7. Peer Manager cannot edit peer Manager\'s validated entry');
    {
      resetMockState();
      const mgraEntryLive = mockState['data/ops/buffer.json'][COUNTRY]['manager-a@ibm.com'][0];
      mgraEntryLive.status = 'validated';
      mgraEntryLive.validatedBy = 'manager-a@ibm.com';
      const mgraEntry = cloneBuffer()[COUNTRY]['manager-a@ibm.com'].find(e => e.id === 'fr_mgra_pending');
      const edited = { ...mgraEntry, process: { ...mgraEntry.process, issue: 'MGR-A-VALIDATED-MGR-B-EDIT' } };
      const buf = { [COUNTRY]: { 'manager-a@ibm.com': [edited] } };
      const r = await apiCall('PUT', '/api/ops/buffer', { buffer: buf }, MANAGER_B_TOKEN);
      assert('status is 403', r.status === 403, `got ${r.status}`);
      // Guard A fires first for peer-Manager case
      assert('code is OWNERSHIP_VIOLATION', r.json?.code === 'OWNERSHIP_VIOLATION', JSON.stringify(r.json));
    }

    // ─────────────────────────────────────────────────────────────────────────
    section('8. Scheduled/pending_merge entries locked for everyone (Guard C)');
    // Test both sub-cases in one section.
    {
      // 8a: scheduled PR lock
      resetMockState();
      const schedEntry = cloneBuffer()[COUNTRY]['ol-a@ibm.com'].find(e => e.id === 'fr_sched_locked');
      const editedSched = { ...schedEntry, process: { ...schedEntry.process, issue: 'SCHED-LOCKED-EDIT' } };
      const bufSched = { [COUNTRY]: { 'ol-a@ibm.com': [editedSched] } };
      const r1 = await apiCall('PUT', '/api/ops/buffer', { buffer: bufSched }, ADMIN_TOKEN);
      assert('8a: scheduled lock — status is 409', r1.status === 409, `got ${r1.status}`);
      assert('8a: code is SCHEDULED_PR_LOCK', r1.json?.code === 'SCHEDULED_PR_LOCK', JSON.stringify(r1.json));

      // 8b: open PR (pending_merge) lock — use a clean pending-only payload.
      // Exclude fr_ola_validated (validated → Guard B would fire first) and
      // fr_sched_locked (scheduled → Guard C SCHEDULED_PR_LOCK would fire first).
      // Only include the pending fr_pr_locked entry so Guard C hits OPEN_PR_LOCK.
      resetMockState();
      const buf2 = { [COUNTRY]: { 'ol-a@ibm.com': [{
        id: 'fr_pr_locked',
        type: 'create',
        user: 'ol-a@ibm.com',
        status: 'pending',
        process: { id: 'fr_pr_locked', issue: 'OL-A-IN-PR-EDIT', category: 'Contract', machineType: '', process: 'content' },
        createdAt: new Date().toISOString()
      }]}};
      const r2 = await apiCall('PUT', '/api/ops/buffer', { buffer: buf2 }, ADMIN_TOKEN);
      assert('8b: open PR lock — status is 409', r2.status === 409, `got ${r2.status}`);
      assert('8b: code is OPEN_PR_LOCK', r2.json?.code === 'OPEN_PR_LOCK', JSON.stringify(r2.json));
    }

    // ── WORKFLOW CONTINUITY SCENARIOS ─────────────────────────────────────────

    section('9. OL can unvalidate own validated entry via POST /api/ops/validate');
    // The correct path: OL calls /api/ops/validate to unvalidate, not PUT.
    // The cross-validator guard in /api/ops/validate blocks unvalidation by a
    // different user (line 2565–2577), so we must set validatedBy to ol-a@ibm.com
    // so OL-A is both the owner and the validator — OL can always reverse their own.
    {
      resetMockState();
      const liveValidated = mockState['data/ops/buffer.json'][COUNTRY]['ol-a@ibm.com']
        .find(e => e.id === 'fr_ola_validated');
      liveValidated.validatedBy = 'ol-a@ibm.com'; // OL validated their own entry
      const r = await apiCall('POST', '/api/ops/validate', {
        country: COUNTRY,
        user: 'ol-a@ibm.com',
        index: 1   // fr_ola_validated is the second entry (index 1) in ol-a's slice
      }, OL_A_TOKEN);
      assert('status is 200', r.status === 200, `got ${r.status} — ${JSON.stringify(r.json)}`);
      assert('entry returned as pending', r.json?.entry?.status === 'pending', JSON.stringify(r.json?.entry));
    }

    // ─────────────────────────────────────────────────────────────────────────
    section('10. Manager can unvalidate OL-owned validated entry via POST /api/ops/validate');
    // manager-a validated the entry (validatedBy = manager-a@ibm.com).
    // The cross-validator guard allows it because the caller IS the validator.
    {
      resetMockState();
      // validatedBy is already 'manager-a@ibm.com' in the default mock state
      const r = await apiCall('POST', '/api/ops/validate', {
        country: COUNTRY,
        user: 'ol-a@ibm.com',
        index: 1
      }, MANAGER_A_TOKEN);
      assert('status is 200', r.status === 200, `got ${r.status} — ${JSON.stringify(r.json)}`);
      assert('entry returned as pending', r.json?.entry?.status === 'pending', JSON.stringify(r.json?.entry));
    }

    // ─────────────────────────────────────────────────────────────────────────
    section('11. After unvalidate, OL can edit own (now-pending) entry via PUT');
    // Simulate post-unvalidate state: set fr_ola_validated to pending in mock buffer.
    {
      resetMockState();
      const liveEntry = mockState['data/ops/buffer.json'][COUNTRY]['ol-a@ibm.com'].find(e => e.id === 'fr_ola_validated');
      liveEntry.status = 'pending';
      delete liveEntry.validatedBy;
      delete liveEntry.validatedAt;
      const edited = { ...liveEntry, process: { ...liveEntry.process, issue: 'OL-A-NOW-PENDING-EDITED' } };
      const buf = { [COUNTRY]: { 'ol-a@ibm.com': [edited] } };
      const r = await apiCall('PUT', '/api/ops/buffer', { buffer: buf, editEntryId: 'fr_ola_validated' }, OL_A_TOKEN);
      assert('status is 200', r.status === 200, `got ${r.status} — ${JSON.stringify(r.json)}`);
      assert('success is true', r.json?.success === true, JSON.stringify(r.json));
    }

    // ─────────────────────────────────────────────────────────────────────────
    section('12. After unvalidate, Manager can edit OL-owned (now-pending) entry via PUT');
    {
      resetMockState();
      const liveEntry = mockState['data/ops/buffer.json'][COUNTRY]['ol-a@ibm.com'].find(e => e.id === 'fr_ola_validated');
      liveEntry.status = 'pending';
      delete liveEntry.validatedBy;
      delete liveEntry.validatedAt;
      const edited = { ...liveEntry, process: { ...liveEntry.process, issue: 'OL-A-NOW-PENDING-MGR-EDITED' } };
      const buf = { [COUNTRY]: { 'ol-a@ibm.com': [edited] } };
      const r = await apiCall('PUT', '/api/ops/buffer', { buffer: buf, editEntryId: 'fr_ola_validated' }, MANAGER_A_TOKEN);
      assert('status is 200', r.status === 200, `got ${r.status} — ${JSON.stringify(r.json)}`);
      assert('success is true', r.json?.success === true, JSON.stringify(r.json));
    }

    // ─────────────────────────────────────────────────────────────────────────
    section('13. Valid same-owner pending edit (normal saveBufferEdit flow)');
    // ol-a edits their own pending entry (fr_ola_pending) — must succeed unchanged.
    {
      resetMockState();
      const baseEntry = cloneBuffer()[COUNTRY]['ol-a@ibm.com'].find(e => e.id === 'fr_ola_pending');
      const edited = { ...baseEntry, process: { ...baseEntry.process, issue: baseEntry.process.issue + '-EDITED' } };
      const buf = { [COUNTRY]: { 'ol-a@ibm.com': [edited] } };
      const r = await apiCall(
        'PUT', '/api/ops/buffer',
        { buffer: buf, editEntryId: 'fr_ola_pending' },
        OL_A_TOKEN
      );
      assert('status is 200', r.status === 200, `got ${r.status} — ${JSON.stringify(r.json)}`);
      assert('success is true', r.json?.success === true, JSON.stringify(r.json));
    }

  } finally {
    serverProc.kill();
    mockServer.close();
  }

  // ── Summary ────────────────────────────────────────────────────────────────
  console.log(`\n${'─'.repeat(64)}`);
  console.log(`PUT /api/ops/buffer guards: ${_pass} passed, ${_fail} failed`);
  if (_failures.length) {
    console.error('\nFailed assertions:');
    _failures.forEach(f => console.error(`  ✗ ${f}`));
  }
  process.exit(_fail > 0 ? 1 : 0);
})();
