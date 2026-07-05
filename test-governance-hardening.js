#!/usr/bin/env node
/**
 * test-governance-hardening.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Validates all governance hardening rules from Parts A–N.
 *
 * Test groups:
 *   PEER   — OL/Manager peer boundary (Part C)
 *   INH    — OL/Manager replacement and inheritance (Part D)
 *   PROMO  — Promotion/demotion OL→Manager (Part E)
 *   ADMIN  — Admin as backup/overruler, stale-action guard (Parts A, B)
 *   HIST   — History read-only/refused, no restore (Part 5, 6)
 *   FAIL-G — PR creation failure: entries stay in Buffer (Part G)
 *   FAIL-H — Approve/merge failure: keep locked, no Published (Part H)
 *   FAIL-I — Reject close failure: keep active/error (Part I)
 *   MISMATCH — External GitHub mismatch handling (Part J)
 *   SYNC   — Sync as Published / Refused after verification (Part J)
 *   ASSIGN — Assignment history written on user ops (Part F)
 *
 * Exit code 0 = all pass. Non-zero = at least one failure.
 */
'use strict';

const http     = require('http');
const net      = require('net');
const path     = require('path');
const { fork } = require('child_process');
const crypto   = require('crypto');

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
const TEST_JWT_SECRET = 'governance-hardening-test-secret-do-not-use-in-prod';

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
const ADMIN_A_TOKEN   = mintJwt({ email: 'admin-a@ibm.com',  role: 'Admin',   iat: now, exp: now + 28800 });
const ADMIN_B_TOKEN   = mintJwt({ email: 'admin-b@ibm.com',  role: 'Admin',   iat: now, exp: now + 28800 });
const OL_A_TOKEN      = mintJwt({ email: 'ol-a@ibm.com',     role: 'OL',      iat: now, exp: now + 28800 });
const OL_B_TOKEN      = mintJwt({ email: 'ol-b@ibm.com',     role: 'OL',      iat: now, exp: now + 28800 });
const MANAGER_A_TOKEN = mintJwt({ email: 'manager-a@ibm.com', role: 'Manager', iat: now, exp: now + 28800 });
const MANAGER_B_TOKEN = mintJwt({ email: 'manager-b@ibm.com', role: 'Manager', iat: now, exp: now + 28800 });

const SERVER_PORT = 3105;
const MOCK_PORT   = 3104;
const COUNTRY     = 'fr';
const PR_NUM      = 80;

// ── Mock GitHub state ──────────────────────────────────────────────────────────
let mockState = {};
let _githubCalls = [];

function resetMockState(overrides = {}) {
  _githubCalls = [];
  mockState = {
    'config/users.json': [
      { email: 'admin-a@ibm.com',  name: 'Admin A',   role: 'Admin',   countries: ['all'] },
      { email: 'admin-b@ibm.com',  name: 'Admin B',   role: 'Admin',   countries: ['all'] },
      { email: 'ol-a@ibm.com',     name: 'OL A',      role: 'OL',      countries: ['fr'] },
      { email: 'ol-b@ibm.com',     name: 'OL B',      role: 'OL',      countries: ['fr'] },
      { email: 'manager-a@ibm.com', name: 'Manager A', role: 'Manager', countries: ['fr'] },
      { email: 'manager-b@ibm.com', name: 'Manager B', role: 'Manager', countries: ['fr'] }
    ],
    'data/ops/buffer.json': {
      fr: {
        'ol-a@ibm.com': [
          { id: 'fr_ol_a_001', type: 'create', user: 'ol-a@ibm.com', status: 'validated',
            process: { id: 'fr_ol_a_001', issue: 'OL-A-ISSUE', category: 'Contract', machineType: '', process: 'test' },
            createdAt: new Date().toISOString() }
        ],
        'ol-b@ibm.com': [
          { id: 'fr_ol_b_001', type: 'create', user: 'ol-b@ibm.com', status: 'pending',
            process: { id: 'fr_ol_b_001', issue: 'OL-B-ISSUE', category: 'Contract', machineType: '', process: 'test' },
            createdAt: new Date().toISOString() }
        ],
        'manager-a@ibm.com': [
          { id: 'fr_mgr_a_001', type: 'create', user: 'manager-a@ibm.com', status: 'validated',
            process: { id: 'fr_mgr_a_001', issue: 'MGR-A-ISSUE', category: 'Contract', machineType: '', process: 'test' },
            createdAt: new Date().toISOString() }
        ]
      }
    },
    'data/ops/history.json': {
      fr: [
        { id: 'fr_pr_001', type: 'create', user: 'ol-a@ibm.com', status: 'validated',
          pr_status: 'pending_merge', prNumber: PR_NUM,
          prUrl: `https://github.ibm.com/nlabib/process-finder/pull/${PR_NUM}`,
          branchName: `ops/fr/20260710-1000`,
          process: { id: 'fr_pr_001', issue: 'PR-TEST', category: 'Contract', machineType: '', process: 'test' }
        }
      ]
    },
    'data/ops/pr_schedule.json': {},
    'data/ops/assignment_history.json': [],
    'data/logs/activity_logs.json': [],
    'data/logs/admin-audit.json': [],
    _openPRs: [
      { number: PR_NUM, state: 'open', html_url: `https://github.ibm.com/nlabib/process-finder/pull/${PR_NUM}`,
        head: { ref: `ops/fr/20260710-1000` }, base: { ref: 'main' }, merged_at: null, closed_at: null }
    ],
    _commits: [],
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
    _githubCalls.push({ method: m, path: p, body: body || null });

    // GET /repos/.../contents/:path
    if (m === 'GET' && p.includes('/contents/')) {
      const match = p.match(/\/repos\/[^/]+\/[^/]+\/contents\/(.+)/);
      if (match) {
        const filePath = match[1];
        if (mockState[filePath] !== undefined) {
          return send(200, {
            path: filePath, sha: 'sha-' + filePath.replace(/\//g, '-'),
            content: encodeFileContent(mockState[filePath]) + '\n', encoding: 'base64'
          });
        }
        return send(404, { message: 'Not Found' });
      }
    }

    // PUT /repos/.../contents/:path (write)
    if (m === 'PUT' && p.includes('/contents/') && !p.includes('/merge')) {
      const match = p.match(/\/repos\/[^/]+\/[^/]+\/contents\/(.+)/);
      if (match) {
        const filePath = match[1];
        let parsed; try { parsed = JSON.parse(body); } catch { parsed = {}; }
        if (parsed.content) {
          try {
            const decoded = Buffer.from(parsed.content, 'base64').toString('utf8');
            mockState[filePath] = JSON.parse(decoded);
            mockState._commits.push({ path: filePath, message: parsed.message });
          } catch {}
        }
        return send(200, { content: { path: filePath, sha: 'new-sha' }, commit: { sha: 'abc123' } });
      }
    }

    // GET /repos/.../pulls?state=open
    if (m === 'GET' && p.includes('/pulls') && !p.match(/\/pulls\/\d+/)) {
      return send(200, mockState._openPRs || []);
    }

    // GET /repos/.../pulls/:number
    const prGetMatch = m === 'GET' && p.match(/\/pulls\/(\d+)$/);
    if (prGetMatch) {
      const num = parseInt(prGetMatch[1], 10);
      const pr  = (mockState._openPRs || []).find(x => x.number === num);
      if (pr) return send(200, pr);
      return send(404, { message: 'Not Found' });
    }

    // GET /repos/.../pulls/:number/files
    const prFilesMatch = m === 'GET' && p.match(/\/pulls\/(\d+)\/files$/);
    if (prFilesMatch) {
      return send(200, [{ filename: `data/processes/${COUNTRY}.json`, status: 'modified', additions: 5, deletions: 0 }]);
    }

    // PUT /repos/.../pulls/:number/merge (squash-merge)
    const mergeMatch = m === 'PUT' && p.match(/\/pulls\/(\d+)\/merge$/);
    if (mergeMatch) {
      const num = parseInt(mergeMatch[1], 10);
      const pr  = (mockState._openPRs || []).find(x => x.number === num);
      if (!pr) return send(404, { message: 'Not Found' });
      if (mockState._mergeFailMode === '405') return send(405, { message: 'Pull Request is not mergeable' });
      if (mockState._mergeFailMode === '500') return send(500, { message: 'Internal Server Error' });
      pr.state = 'closed'; pr.merged_at = new Date().toISOString();
      return send(200, { sha: 'merge-sha-' + num, merged: true, message: 'Pull Request successfully merged' });
    }

    // PATCH /repos/.../pulls/:number (close)
    const patchMatch = m === 'PATCH' && p.match(/\/pulls\/(\d+)$/);
    if (patchMatch) {
      const num = parseInt(patchMatch[1], 10);
      const pr  = (mockState._openPRs || []).find(x => x.number === num);
      if (!pr) return send(404, { message: 'Not Found' });
      if (mockState._closeFailMode === '500') return send(500, { message: 'Internal Server Error' });
      pr.state = 'closed'; pr.closed_at = new Date().toISOString();
      return send(200, { ...pr });
    }

    // GET /repos/.../git/refs/heads/:branch
    if (m === 'GET' && p.includes('/git/refs/heads/')) {
      return send(200, { ref: 'refs/heads/main', object: { sha: 'main-sha' } });
    }

    // POST /repos/.../git/refs (create branch)
    if (m === 'POST' && p.includes('/git/refs')) {
      return send(201, { ref: 'refs/heads/new-branch', object: { sha: 'main-sha' } });
    }

    // POST /repos/.../pulls (create PR)
    if (m === 'POST' && p.includes('/pulls')) {
      const nextNum = (mockState._openPRs || []).length + 90;
      const newPR = { number: nextNum, state: 'open', html_url: `https://github.ibm.com/nlabib/process-finder/pull/${nextNum}`,
        head: { ref: `ops/fr/test` }, base: { ref: 'main' }, merged_at: null, closed_at: null };
      if (!mockState._openPRs) mockState._openPRs = [];
      mockState._openPRs.push(newPR);
      return send(201, { ...newPR });
    }

    send(404, { message: `Mock: no handler for ${m} ${p}` });
  });
});

// ── HTTP client helper ─────────────────────────────────────────────────────────
function apiCall(method, urlPath, bodyObj, token = ADMIN_A_TOKEN) {
  return new Promise((resolve, reject) => {
    const bodyStr = bodyObj ? JSON.stringify(bodyObj) : '';
    const opts = {
      hostname: 'localhost', port: SERVER_PORT, path: urlPath, method,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(bodyStr),
        'Authorization': `Bearer ${token}`
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

function waitForPort(port, retries = 20, delay = 300) {
  return new Promise((resolve, reject) => {
    function attempt(n) {
      const sock = net.connect(port, 'localhost');
      sock.on('connect', () => { sock.destroy(); resolve(); });
      sock.on('error', () => {
        if (n <= 0) return reject(new Error(`Port ${port} not ready`));
        setTimeout(() => attempt(n - 1), delay);
      });
    }
    attempt(retries);
  });
}

// ── Main ───────────────────────────────────────────────────────────────────────
(async () => {
  await new Promise(r => mockServer.listen(MOCK_PORT, r));

  const serverProc = fork(path.join(__dirname, 'server.js'), [], {
    env: {
      ...process.env,
      PORT:             String(SERVER_PORT),
      JWT_SECRET:       TEST_JWT_SECRET,
      GITHUB_TOKEN:     'mock-token',
      GITHUB_OWNER:     'nlabib',
      GITHUB_REPO:      'process-finder',
      GITHUB_BRANCH:    'main',
      GITHUB_TARGET_BRANCH: 'main',
      GITHUB_API_BASE:  `http://localhost:${MOCK_PORT}`,
      DISABLE_PR_CREATION: 'false',
      EMAIL_SEND_MODE:  'mock'
    },
    silent: true
  });
  serverProc.stdout?.on('data', () => {});
  serverProc.stderr?.on('data', () => {});

  try {
    await waitForPort(SERVER_PORT);

    // ══════════════════════════════════════════════════════════════════════════
    // PEER-1: OL A cannot validate OL B's entry (peer boundary)
    // ══════════════════════════════════════════════════════════════════════════
    section('PEER-1: OL A cannot validate OL B entry');
    resetMockState();

    const rOLBValidate = await apiCall('POST', '/api/ops/validate',
      { country: COUNTRY, user: 'ol-b@ibm.com', index: 0 }, OL_A_TOKEN);
    assert('PEER-1  OL A → 403 validating OL B entry', rOLBValidate.status === 403,
      `status=${rOLBValidate.status} body=${JSON.stringify(rOLBValidate.json)}`);

    // ══════════════════════════════════════════════════════════════════════════
    // PEER-2: OL A cannot cancel OL B's entry (peer boundary)
    // ══════════════════════════════════════════════════════════════════════════
    section('PEER-2: OL A cannot cancel OL B entry');
    resetMockState();

    const rOLBCancel = await apiCall('POST', '/api/ops/cancel',
      { country: COUNTRY, user: 'ol-b@ibm.com', index: 0 }, OL_A_TOKEN);
    assert('PEER-2  OL A → 403 cancelling OL B entry', rOLBCancel.status === 403,
      `status=${rOLBCancel.status}`);

    // ══════════════════════════════════════════════════════════════════════════
    // PEER-3: Manager A cannot cancel Manager B's own Manager-created entry
    // ══════════════════════════════════════════════════════════════════════════
    section('PEER-3: Manager A cannot cancel Manager B entry');
    resetMockState({
      'data/ops/buffer.json': {
        fr: {
          'manager-b@ibm.com': [
            { id: 'fr_mgr_b_001', type: 'create', user: 'manager-b@ibm.com', status: 'pending',
              process: { id: 'fr_mgr_b_001', issue: 'MGR-B-ISSUE', category: 'Contract', machineType: '', process: 'test' },
              createdAt: new Date().toISOString() }
          ]
        }
      }
    });

    const rMgrBCancel = await apiCall('POST', '/api/ops/cancel',
      { country: COUNTRY, user: 'manager-b@ibm.com', index: 0 }, MANAGER_A_TOKEN);
    assert('PEER-3  Manager A → 403 cancelling Manager B own entry', rMgrBCancel.status === 403,
      `status=${rMgrBCancel.status} body=${JSON.stringify(rMgrBCancel.json)}`);

    // ══════════════════════════════════════════════════════════════════════════
    // PEER-4: Manager A CAN cancel OL A's pending entry
    // ══════════════════════════════════════════════════════════════════════════
    section('PEER-4: Manager A can cancel OL A entry');
    resetMockState();

    const rMgrCancelOL = await apiCall('POST', '/api/ops/cancel',
      { country: COUNTRY, user: 'ol-b@ibm.com', index: 0 }, MANAGER_A_TOKEN);
    // OL-B has a pending entry — Manager A may cancel it (OL-owned pending)
    assert('PEER-4  Manager A can cancel OL-owned pending entry', rMgrCancelOL.ok,
      `status=${rMgrCancelOL.status} body=${JSON.stringify(rMgrCancelOL.json)}`);

    // ══════════════════════════════════════════════════════════════════════════
    // INH-1: Removing OL A triggers inheritance to OL B
    // ══════════════════════════════════════════════════════════════════════════
    section('INH-1: Removing OL A triggers buffer inheritance to OL B');
    resetMockState();

    const rRemoveOLA = await apiCall('POST', '/api/admin/users', {
      users: [{ op: 'remove', user: { email: 'ol-a@ibm.com' } }],
      reason: 'OL A departed'
    }, ADMIN_A_TOKEN);
    assert('INH-1  Remove OL A returns 200', rRemoveOLA.ok,
      `status=${rRemoveOLA.status} body=${JSON.stringify(rRemoveOLA.json)}`);
    assert('INH-1  assignmentEvents > 0', (rRemoveOLA.json?.assignmentEvents || 0) > 0,
      `events=${rRemoveOLA.json?.assignmentEvents}`);

    await sleep(600);

    // Check assignment history was written
    const asgHistory = mockState['data/ops/assignment_history.json'] || [];
    const removedEv  = asgHistory.find(e => e.action === 'removed' && e.userEmail === 'ol-a@ibm.com');
    assert('INH-1b assignment_history.json has removed event for OL A', !!removedEv,
      `history=${JSON.stringify(asgHistory.map(e => ({ action: e.action, userEmail: e.userEmail })))}`);

    const inheritEv = asgHistory.find(e => e.action === 'ownership-inherited' && e.previousOwner === 'ol-a@ibm.com');
    assert('INH-1c assignment_history.json has ownership-inherited event pointing to OL B', !!inheritEv,
      `history=${JSON.stringify(asgHistory.map(e => ({ action: e.action, userEmail: e.userEmail, previousOwner: e.previousOwner })))}`);

    // ══════════════════════════════════════════════════════════════════════════
    // PROMO-1: OL A promoted to Manager — role change event recorded
    // ══════════════════════════════════════════════════════════════════════════
    section('PROMO-1: OL A promoted to Manager — assignment event recorded');
    resetMockState();

    const rPromote = await apiCall('POST', '/api/admin/users', {
      users: [{ op: 'update', user: { email: 'ol-a@ibm.com', name: 'OL A', role: 'Manager', countries: ['fr'] } }],
      reason: 'Promoted to Manager'
    }, ADMIN_A_TOKEN);
    assert('PROMO-1  Promote OL A to Manager returns 200', rPromote.ok,
      `status=${rPromote.status} body=${JSON.stringify(rPromote.json)}`);
    assert('PROMO-1  assignmentEvents > 0', (rPromote.json?.assignmentEvents || 0) > 0, '');

    await sleep(600);
    const asgHistory2 = mockState['data/ops/assignment_history.json'] || [];
    const promoEv = asgHistory2.find(e => e.action === 'promoted' && e.userEmail === 'ol-a@ibm.com');
    assert('PROMO-1b  promoted event in assignment_history', !!promoEv,
      `history=${JSON.stringify(asgHistory2.map(e => ({ action: e.action, userEmail: e.userEmail })))}`);
    assert('PROMO-1c  previousRole is OL', promoEv?.previousRole === 'OL', `prev=${promoEv?.previousRole}`);
    assert('PROMO-1d  new role is Manager', promoEv?.role === 'Manager', `role=${promoEv?.role}`);

    // ══════════════════════════════════════════════════════════════════════════
    // ADMIN-1: Admin A approve → success
    // ══════════════════════════════════════════════════════════════════════════
    section('ADMIN-1: Admin A can approve PR');
    resetMockState();

    const rApprove = await apiCall('POST', '/api/admin/pr/approve',
      { country: COUNTRY, prNumber: PR_NUM }, ADMIN_A_TOKEN);
    assert('ADMIN-1  Admin A approve returns 200', rApprove.ok,
      `status=${rApprove.status} body=${JSON.stringify(rApprove.json)}`);
    assert('ADMIN-1b mergedCount ≥ 1', (rApprove.json?.mergedCount || 0) >= 1, '');

    // ══════════════════════════════════════════════════════════════════════════
    // ADMIN-2: Admin B approve on already-merged PR → stale-action guard
    // ══════════════════════════════════════════════════════════════════════════
    section('ADMIN-2: Admin B approve on already-approved request → stale-action guard');
    // Don't reset — use the state where PR was already merged by Admin A
    await sleep(400);

    const rStale = await apiCall('POST', '/api/admin/pr/approve',
      { country: COUNTRY, prNumber: PR_NUM }, ADMIN_B_TOKEN);
    assert('ADMIN-2  Admin B gets 409 on already-processed PR', rStale.status === 409,
      `status=${rStale.status} body=${JSON.stringify(rStale.json)}`);
    assert('ADMIN-2b  opsMessage present', typeof rStale.json?.opsMessage === 'string', '');
    assert('ADMIN-2c  productionChanged flag provided', 'productionChanged' in (rStale.json || {}), '');

    // ══════════════════════════════════════════════════════════════════════════
    // ADMIN-3: Admin B is NOT blocked from acting on separate country
    // ══════════════════════════════════════════════════════════════════════════
    section('ADMIN-3: Admin B can approve a different country PR (unrestricted)');
    resetMockState({
      'data/ops/history.json': {
        fr: [],
        it: [{ id: 'it_pr_001', type: 'create', user: 'ol-a@ibm.com', status: 'validated',
          pr_status: 'pending_merge', prNumber: 90,
          branchName: 'ops/it/20260710-1100',
          process: { id: 'it_pr_001', issue: 'IT-TEST', category: 'Contract', machineType: '', process: 'test' } }]
      },
      _openPRs: [
        { number: 90, state: 'open', html_url: 'https://github.ibm.com/nlabib/process-finder/pull/90',
          head: { ref: 'ops/it/20260710-1100' }, base: { ref: 'main' }, merged_at: null, closed_at: null }
      ]
    });

    const rItApprove = await apiCall('POST', '/api/admin/pr/approve',
      { country: 'it', prNumber: 90 }, ADMIN_B_TOKEN);
    assert('ADMIN-3  Admin B can approve IT PR (no country restriction)', rItApprove.ok,
      `status=${rItApprove.status} body=${JSON.stringify(rItApprove.json)}`);

    // ══════════════════════════════════════════════════════════════════════════
    // HIST-1: Refused entries in History — no restore/reopen
    // ══════════════════════════════════════════════════════════════════════════
    section('HIST-1: Refused entries are read-only — no restore or reopen');
    resetMockState({
      'data/ops/history.json': {
        fr: [{ id: 'fr_refused_001', type: 'create', user: 'ol-a@ibm.com', status: 'validated',
          pr_status: 'refused', prNumber: PR_NUM,
          branchName: 'ops/fr/20260710-1000',
          process: { id: 'fr_refused_001', issue: 'REFUSED-ISSUE', category: 'Contract', machineType: '', process: 'test' } }]
      },
      _openPRs: []
    });
    // Attempt to approve the same PR (already refused) — must be blocked
    const rRefusedApprove = await apiCall('POST', '/api/admin/pr/approve',
      { country: COUNTRY, prNumber: PR_NUM }, ADMIN_A_TOKEN);
    assert('HIST-1  Cannot approve an already-refused PR', rRefusedApprove.status === 409,
      `status=${rRefusedApprove.status}`);
    assert('HIST-1b opsMessage explains it was already processed', typeof rRefusedApprove.json?.opsMessage === 'string', '');

    // ══════════════════════════════════════════════════════════════════════════
    // FAIL-G: PR creation failure leaves entries in Buffer (Part G)
    // Test via a state where there is an existing open PR (409 preflight),
    // so retry-create is blocked and must return safe error fields.
    // ══════════════════════════════════════════════════════════════════════════
    section('FAIL-G: PR creation failure — entries stay in Buffer');
    resetMockState({
      // Simulate an already-open PR so _preflightPRCheck returns 409 "already pending"
      _openPRs: [
        { number: PR_NUM, state: 'open',
          html_url: `https://github.ibm.com/nlabib/process-finder/pull/${PR_NUM}`,
          head: { ref: `ops/fr/20260710-1000` }, base: { ref: 'main' },
          merged_at: null, closed_at: null }
      ]
    });

    const rRetryCrea = await apiCall('POST', '/api/admin/pr/retry-create',
      { country: COUNTRY }, ADMIN_A_TOKEN);
    // With an open PR, preflight returns 409 — retry-create must be blocked safely
    assert('FAIL-G  retry-create blocked when PR already open (non-200)',
      !rRetryCrea.ok, `status=${rRetryCrea.status}`);
    assert('FAIL-G  retry-create failure returns productionChanged=false',
      rRetryCrea.json?.productionChanged === false,
      `productionChanged=${rRetryCrea.json?.productionChanged}`);
    assert('FAIL-G  retry-create failure returns entriesLocked=false',
      rRetryCrea.json?.entriesLocked === false,
      `entriesLocked=${rRetryCrea.json?.entriesLocked}`);

    // ══════════════════════════════════════════════════════════════════════════
    // FAIL-H: Approve merge failure — entries stay locked, no Published (Part H)
    // ══════════════════════════════════════════════════════════════════════════
    section('FAIL-H: Approve merge failure — entries stay locked, no Published');
    resetMockState();
    mockState._mergeFailMode = '405'; // conflict

    const rMergeFail = await apiCall('POST', '/api/admin/pr/approve',
      { country: COUNTRY, prNumber: PR_NUM }, ADMIN_A_TOKEN);
    assert('FAIL-H  Merge conflict returns 409', rMergeFail.status === 409,
      `status=${rMergeFail.status}`);
    assert('FAIL-H  productionChanged=false on merge failure', rMergeFail.json?.productionChanged === false,
      `productionChanged=${rMergeFail.json?.productionChanged}`);
    assert('FAIL-H  entriesLocked=true on merge failure', rMergeFail.json?.entriesLocked === true,
      `entriesLocked=${rMergeFail.json?.entriesLocked}`);
    assert('FAIL-H  opsMessage is string', typeof rMergeFail.json?.opsMessage === 'string', '');
    assert('FAIL-H  availableActions present', Array.isArray(rMergeFail.json?.availableActions), '');
    assert('FAIL-H  no Published in History after failed merge',
      !(mockState['data/ops/history.json']?.fr || []).some(h => h.pr_status === 'merged'), '');

    // Verify Logs captured the failure
    await sleep(300);
    const logsH = mockState['data/logs/activity_logs.json'] || [];
    const mergeFailLog = logsH.find(l => l.event === 'approve-conflict-detected');
    assert('FAIL-H  approve-conflict-detected event in Logs', !!mergeFailLog, `logs=${JSON.stringify(logsH.map(l => l.event))}`);

    // ══════════════════════════════════════════════════════════════════════════
    // FAIL-I: Reject close failure — keep active/error, no Refused (Part I)
    // ══════════════════════════════════════════════════════════════════════════
    section('FAIL-I: Reject close failure — keep active/error, no Refused');
    resetMockState();
    mockState._closeFailMode = '500'; // GitHub close fails

    const rCloseFail = await apiCall('POST', '/api/admin/pr/close',
      { country: COUNTRY, prNumber: PR_NUM, reason: 'test' }, ADMIN_A_TOKEN);
    assert('FAIL-I  Close failure returns non-200', !rCloseFail.ok,
      `status=${rCloseFail.status}`);
    assert('FAIL-I  productionChanged=false on close failure', rCloseFail.json?.productionChanged === false,
      `productionChanged=${rCloseFail.json?.productionChanged}`);
    assert('FAIL-I  entriesLocked=true on close failure', rCloseFail.json?.entriesLocked === true,
      `entriesLocked=${rCloseFail.json?.entriesLocked}`);
    assert('FAIL-I  opsMessage is string', typeof rCloseFail.json?.opsMessage === 'string', '');
    assert('FAIL-I  History not marked refused after failed close',
      !(mockState['data/ops/history.json']?.fr || []).some(h => h.pr_status === 'refused'), '');

    // Verify Logs captured the rejection failure
    await sleep(300);
    const logsI = mockState['data/logs/activity_logs.json'] || [];
    const closeFailLog = logsI.find(l => l.event === 'reject-close-failed');
    assert('FAIL-I  reject-close-failed event in Logs', !!closeFailLog, `logs=${JSON.stringify(logsI.map(l => l.event))}`);

    // ══════════════════════════════════════════════════════════════════════════
    // MISMATCH-1: Externally merged PR detected on approve (Part J)
    // ══════════════════════════════════════════════════════════════════════════
    section('MISMATCH-1: Externally merged PR detected on approve');
    resetMockState({
      _openPRs: [
        { number: PR_NUM, state: 'closed', html_url: `https://github.ibm.com/nlabib/process-finder/pull/${PR_NUM}`,
          head: { ref: 'ops/fr/20260710-1000' }, base: { ref: 'main' },
          merged_at: new Date().toISOString(), closed_at: new Date().toISOString(),
          merge_commit_sha: 'external-merge-sha' }
      ]
    });

    const rExtMerge = await apiCall('POST', '/api/admin/pr/approve',
      { country: COUNTRY, prNumber: PR_NUM }, ADMIN_A_TOKEN);
    assert('MISMATCH-1  Externally merged PR returns 409', rExtMerge.status === 409,
      `status=${rExtMerge.status}`);
    assert('MISMATCH-1  mismatch type is externally-merged',
      rExtMerge.json?.mismatch?.type === 'externally-merged',
      `mismatch=${JSON.stringify(rExtMerge.json?.mismatch)}`);
    assert('MISMATCH-1  opsMessage guides to syncAsPublished', rExtMerge.json?.opsMessage?.includes('Sync as Published') === true, '');
    assert('MISMATCH-1  availableActions contains syncAsPublished',
      (rExtMerge.json?.availableActions || []).includes('syncAsPublished'), '');

    // Verify mismatch was logged (fire-and-forget, needs a moment to resolve)
    await sleep(700);
    const logsJ1 = mockState['data/logs/activity_logs.json'] || [];
    const mismatchLog1 = logsJ1.find(l => l.event === 'github-mismatch-detected');
    assert('MISMATCH-1b  github-mismatch-detected event in Logs', !!mismatchLog1,
      `logs=${JSON.stringify(logsJ1.map(l => l.event))}`);

    // ══════════════════════════════════════════════════════════════════════════
    // MISMATCH-2: Externally closed PR detected on reject (Part J)
    // ══════════════════════════════════════════════════════════════════════════
    section('MISMATCH-2: Externally closed (unmerged) PR detected on reject');
    resetMockState({
      _openPRs: [
        { number: PR_NUM, state: 'closed', html_url: `https://github.ibm.com/nlabib/process-finder/pull/${PR_NUM}`,
          head: { ref: 'ops/fr/20260710-1000' }, base: { ref: 'main' },
          merged_at: null, closed_at: new Date().toISOString() }
      ]
    });

    const rExtClosed = await apiCall('POST', '/api/admin/pr/close',
      { country: COUNTRY, prNumber: PR_NUM, reason: 'test' }, ADMIN_A_TOKEN);
    assert('MISMATCH-2  Externally closed PR returns 409', rExtClosed.status === 409,
      `status=${rExtClosed.status}`);
    assert('MISMATCH-2  mismatch type is externally-closed',
      rExtClosed.json?.mismatch?.type === 'externally-closed',
      `mismatch=${JSON.stringify(rExtClosed.json?.mismatch)}`);
    assert('MISMATCH-2  opsMessage guides to syncAsRefused', rExtClosed.json?.opsMessage?.includes('Sync as Refused') === true, '');
    assert('MISMATCH-2  availableActions contains syncAsRefused',
      (rExtClosed.json?.availableActions || []).includes('syncAsRefused'), '');

    // ══════════════════════════════════════════════════════════════════════════
    // SYNC-1: Sync as Published after backend verifies merged (Part J)
    // ══════════════════════════════════════════════════════════════════════════
    section('SYNC-1: Sync as Published — backend verifies merge, updates History');
    resetMockState({
      _openPRs: [
        { number: PR_NUM, state: 'closed', html_url: `https://github.ibm.com/nlabib/process-finder/pull/${PR_NUM}`,
          head: { ref: 'ops/fr/20260710-1000' }, base: { ref: 'main' },
          merged_at: '2026-07-10T10:00:00.000Z', closed_at: '2026-07-10T10:00:00.000Z',
          merge_commit_sha: 'verified-merge-sha' }
      ]
    });

    const rSyncPub = await apiCall('POST', '/api/admin/pr/sync-published',
      { country: COUNTRY, prNumber: PR_NUM }, ADMIN_A_TOKEN);
    assert('SYNC-1  sync-published returns 200', rSyncPub.ok,
      `status=${rSyncPub.status} body=${JSON.stringify(rSyncPub.json)}`);
    assert('SYNC-1b syncedCount ≥ 1', (rSyncPub.json?.syncedCount || 0) >= 1, '');

    await sleep(400);
    const histAfterSync = mockState['data/ops/history.json']?.fr || [];
    const syncedMerged = histAfterSync.filter(h => h.pr_status === 'merged' && h.syncedFromExternal === true);
    assert('SYNC-1c History entries updated to merged with syncedFromExternal=true', syncedMerged.length >= 1, `merged=${syncedMerged.length}`);
    const logsSync = mockState['data/logs/activity_logs.json'] || [];
    const syncLog = logsSync.find(l => l.event === 'sync-as-published');
    assert('SYNC-1d sync-as-published event in Logs', !!syncLog, '');

    // ══════════════════════════════════════════════════════════════════════════
    // SYNC-2: Sync as Refused after backend verifies closed unmerged (Part J)
    // ══════════════════════════════════════════════════════════════════════════
    section('SYNC-2: Sync as Refused — backend verifies closed unmerged, updates History');
    resetMockState({
      _openPRs: [
        { number: PR_NUM, state: 'closed', html_url: `https://github.ibm.com/nlabib/process-finder/pull/${PR_NUM}`,
          head: { ref: 'ops/fr/20260710-1000' }, base: { ref: 'main' },
          merged_at: null, closed_at: '2026-07-10T11:00:00.000Z' }
      ]
    });

    const rSyncRef = await apiCall('POST', '/api/admin/pr/sync-refused',
      { country: COUNTRY, prNumber: PR_NUM, reason: 'External close sync' }, ADMIN_A_TOKEN);
    assert('SYNC-2  sync-refused returns 200', rSyncRef.ok,
      `status=${rSyncRef.status} body=${JSON.stringify(rSyncRef.json)}`);
    assert('SYNC-2b syncedCount ≥ 1', (rSyncRef.json?.syncedCount || 0) >= 1, '');

    await sleep(400);
    const histAfterSyncRef = mockState['data/ops/history.json']?.fr || [];
    const syncedRefused = histAfterSyncRef.filter(h => h.pr_status === 'refused' && h.syncedFromExternal === true);
    assert('SYNC-2c History entries updated to refused with syncedFromExternal=true', syncedRefused.length >= 1, `refused=${syncedRefused.length}`);
    const logsSyncRef = mockState['data/logs/activity_logs.json'] || [];
    const syncRefLog = logsSyncRef.find(l => l.event === 'sync-as-refused');
    assert('SYNC-2d sync-as-refused event in Logs', !!syncRefLog, '');

    // ══════════════════════════════════════════════════════════════════════════
    // SYNC-3: Sync as Published blocked when PR is NOT merged (Part J safety)
    // ══════════════════════════════════════════════════════════════════════════
    section('SYNC-3: Sync as Published blocked when PR not genuinely merged');
    resetMockState(); // PR is open, not merged

    const rSyncPubBlocked = await apiCall('POST', '/api/admin/pr/sync-published',
      { country: COUNTRY, prNumber: PR_NUM }, ADMIN_A_TOKEN);
    assert('SYNC-3  sync-published blocked for open PR', !rSyncPubBlocked.ok,
      `status=${rSyncPubBlocked.status}`);

    // ══════════════════════════════════════════════════════════════════════════
    // ASSIGN-1: Add new user → assignment history written
    // ══════════════════════════════════════════════════════════════════════════
    section('ASSIGN-1: Add new user → assignment history recorded');
    resetMockState();

    const rAddUser = await apiCall('POST', '/api/admin/users', {
      users: [{ op: 'add', user: { email: 'new-ol@ibm.com', name: 'New OL', role: 'OL', countries: ['fr'] } }],
      reason: 'Adding new France OL'
    }, ADMIN_A_TOKEN);
    assert('ASSIGN-1  Add user returns 200', rAddUser.ok,
      `status=${rAddUser.status}`);
    assert('ASSIGN-1  assignmentEvents > 0', (rAddUser.json?.assignmentEvents || 0) > 0, '');

    await sleep(600);
    const asgH3 = mockState['data/ops/assignment_history.json'] || [];
    const addEv = asgH3.find(e => e.action === 'added' && e.userEmail === 'new-ol@ibm.com');
    assert('ASSIGN-1b added event in assignment_history', !!addEv,
      `history=${JSON.stringify(asgH3.map(e => ({ action: e.action, userEmail: e.userEmail })))}`);
    assert('ASSIGN-1c eventId is set', typeof addEv?.eventId === 'string' && addEv.eventId.startsWith('asgn_'), `eventId=${addEv?.eventId}`);
    assert('ASSIGN-1d effectiveAt is set', typeof addEv?.effectiveAt === 'string', '');
    assert('ASSIGN-1e changedBy is Admin email', addEv?.changedBy === 'admin-a@ibm.com', `changedBy=${addEv?.changedBy}`);

    // ══════════════════════════════════════════════════════════════════════════
    // COUNTDOWN-1: Approve/Reject blocked while countdown active (existing rule)
    // ══════════════════════════════════════════════════════════════════════════
    section('COUNTDOWN-1: Approve blocked while countdown active');
    resetMockState({
      'data/ops/pr_schedule.json': {
        fr: { country: 'fr', created_by: 'ol-a@ibm.com', execute_after: new Date(Date.now() + 60000).toISOString() }
      }
    });

    const rCountdownApprove = await apiCall('POST', '/api/admin/pr/approve',
      { country: COUNTRY, prNumber: PR_NUM }, ADMIN_A_TOKEN);
    assert('COUNTDOWN-1  Approve blocked by countdown → 409', rCountdownApprove.status === 409,
      `status=${rCountdownApprove.status}`);
    assert('COUNTDOWN-1b opsMessage present', typeof rCountdownApprove.json?.opsMessage === 'string', '');

    // ══════════════════════════════════════════════════════════════════════════
    // MIN-ADMIN-1: Remove last Admin → blocked (Part A minimum Admin protection)
    // ══════════════════════════════════════════════════════════════════════════
    section('MIN-ADMIN-1: Remove last Admin → blocked by backend');
    resetMockState({
      'config/users.json': [
        { email: 'admin-a@ibm.com', name: 'Admin A', role: 'Admin', countries: ['all'] },
        { email: 'ol-a@ibm.com',    name: 'OL A',    role: 'OL',    countries: ['fr'] }
      ]
    });

    // Attempt to remove the only Admin
    const rRemoveLastAdmin = await apiCall('POST', '/api/admin/users', {
      users: [{ op: 'remove', user: { email: 'admin-a@ibm.com' } }]
    }, ADMIN_A_TOKEN);
    // Self-remove is blocked first — but also verify last-admin guard fires
    // (self-remove error takes precedence, so accept either 400)
    assert('MIN-ADMIN-1  Remove self blocked → 400', rRemoveLastAdmin.status === 400,
      `status=${rRemoveLastAdmin.status} body=${JSON.stringify(rRemoveLastAdmin.json)}`);

    // Now test with admin-b trying to remove the only other admin (admin-a)
    // while admin-b itself is admin. This leaves zero admins in working.
    resetMockState({
      'config/users.json': [
        { email: 'admin-a@ibm.com', name: 'Admin A', role: 'Admin', countries: ['all'] },
        { email: 'admin-b@ibm.com', name: 'Admin B', role: 'Admin', countries: ['all'] }
      ]
    });
    // admin-b removes admin-a — working becomes only admin-b → still 1 admin: should pass
    const rRemoveOtherAdmin = await apiCall('POST', '/api/admin/users', {
      users: [{ op: 'remove', user: { email: 'admin-a@ibm.com' } }]
    }, ADMIN_B_TOKEN);
    assert('MIN-ADMIN-1b Remove one of two Admins → allowed (1 remains)', rRemoveOtherAdmin.ok,
      `status=${rRemoveOtherAdmin.status} body=${JSON.stringify(rRemoveOtherAdmin.json)}`);

    // Now single-admin state: admin-b tries to demote themselves (update role to OL)
    // Result: working has 0 admins — must be blocked
    resetMockState({
      'config/users.json': [
        { email: 'admin-b@ibm.com', name: 'Admin B', role: 'Admin', countries: ['all'] },
        { email: 'ol-a@ibm.com',    name: 'OL A',    role: 'OL',    countries: ['fr'] }
      ]
    });
    const rDemoteLastAdmin = await apiCall('POST', '/api/admin/users', {
      users: [{ op: 'update', user: { email: 'admin-b@ibm.com', name: 'Admin B', role: 'OL', countries: ['fr'] } }]
    }, ADMIN_B_TOKEN);
    assert('MIN-ADMIN-1c Demote last Admin to OL → 400', rDemoteLastAdmin.status === 400,
      `status=${rDemoteLastAdmin.status} body=${JSON.stringify(rDemoteLastAdmin.json)}`);
    assert('MIN-ADMIN-1d Error message mentions Admin', typeof rDemoteLastAdmin.json?.error === 'string',
      `error=${rDemoteLastAdmin.json?.error}`);

    // ══════════════════════════════════════════════════════════════════════════
    // DUP-1: Duplicate issue in Buffer → save blocked (Item 2)
    // ══════════════════════════════════════════════════════════════════════════
    section('DUP-1: Duplicate issue in Buffer → POST /api/ops/buffer returns 409');
    resetMockState({
      'config/users.json': [
        { email: 'admin-a@ibm.com',  name: 'Admin A', role: 'Admin',   countries: ['all'] },
        { email: 'ol-a@ibm.com',     name: 'OL A',    role: 'OL',      countries: ['fr'] }
      ],
      'data/ops/buffer.json': {
        fr: {
          'ol-a@ibm.com': [
            { id: 'fr_dup_001', type: 'create', user: 'ol-a@ibm.com', status: 'pending',
              process: { id: 'fr_dup_001', issue: 'DUPLICATE-ISSUE', category: 'Contract', machineType: '', process: 'existing' },
              createdAt: new Date().toISOString() }
          ]
        }
      },
      [`data/processes/${COUNTRY}.json`]: { processes: [] }
    });

    const rDupBuffer = await apiCall('POST', '/api/ops/buffer', {
      country: COUNTRY,
      type: 'create',
      process: { issue: 'DUPLICATE-ISSUE', category: 'Contract', machineType: '', process: 'new attempt' }
    }, OL_A_TOKEN);
    assert('DUP-1  Duplicate issue in Buffer → 409', rDupBuffer.status === 409,
      `status=${rDupBuffer.status} body=${JSON.stringify(rDupBuffer.json)}`);
    assert('DUP-1b Error message contains issue name', (rDupBuffer.json?.error || '').includes('DUPLICATE-ISSUE'),
      `error=${rDupBuffer.json?.error}`);
    assert('DUP-1c duplicateIssue field is set', rDupBuffer.json?.duplicateIssue === 'DUPLICATE-ISSUE',
      `duplicateIssue=${rDupBuffer.json?.duplicateIssue}`);

    // ── DUP-2: Duplicate issue in production → save blocked ──────────────────
    section('DUP-2: Duplicate issue already in production → POST /api/ops/buffer returns 409');
    resetMockState({
      'config/users.json': [
        { email: 'admin-a@ibm.com', name: 'Admin A', role: 'Admin', countries: ['all'] },
        { email: 'ol-a@ibm.com',    name: 'OL A',    role: 'OL',    countries: ['fr'] }
      ],
      'data/ops/buffer.json': { fr: {} },
      [`data/processes/${COUNTRY}.json`]: {
        processes: [
          { id: 'prod_001', issue: 'PROD-EXISTING', category: 'Contract', machineType: '', process: 'existing prod process' }
        ]
      }
    });

    const rDupProd = await apiCall('POST', '/api/ops/buffer', {
      country: COUNTRY,
      type: 'create',
      process: { issue: 'PROD-EXISTING', category: 'Contract', machineType: '', process: 'attempted new' }
    }, OL_A_TOKEN);
    assert('DUP-2  Issue already in production → 409', rDupProd.status === 409,
      `status=${rDupProd.status} body=${JSON.stringify(rDupProd.json)}`);
    assert('DUP-2b Error message mentions update', (rDupProd.json?.error || '').toLowerCase().includes('update'),
      `error=${rDupProd.json?.error}`);

    // ── DUP-3: update/delete type is exempt from duplicate check ─────────────
    section('DUP-3: update type is exempt from duplicate check');
    resetMockState({
      'config/users.json': [
        { email: 'admin-a@ibm.com', name: 'Admin A', role: 'Admin', countries: ['all'] },
        { email: 'ol-a@ibm.com',    name: 'OL A',    role: 'OL',    countries: ['fr'] }
      ],
      'data/ops/buffer.json': { fr: {} },
      [`data/processes/${COUNTRY}.json`]: {
        processes: [
          { id: 'prod_001', issue: 'PROD-EXISTING', category: 'Contract', machineType: '', process: 'in prod' }
        ]
      }
    });

    const rUpdateExempt = await apiCall('POST', '/api/ops/buffer', {
      country: COUNTRY,
      type: 'update',
      process: { id: 'prod_001', issue: 'PROD-EXISTING', category: 'Contract', machineType: '', process: 'updated text' }
    }, OL_A_TOKEN);
    assert('DUP-3  update type not blocked by duplicate check', rUpdateExempt.ok,
      `status=${rUpdateExempt.status} body=${JSON.stringify(rUpdateExempt.json)}`);

  } finally {
    serverProc.kill();
    mockServer.close();

    console.log('\n' + '═'.repeat(64));
    if (_fail === 0) {
      console.log(` Results: ${_pass} passed, 0 failed`);
    } else {
      console.log(` Results: ${_pass} passed, ${_fail} failed`);
      console.log('\nFailed assertions:');
      _failures.forEach(f => console.error(`  ❌ ${f}`));
    }
    console.log('═'.repeat(64));
    process.exit(_fail > 0 ? 1 : 0);
  }
})();
