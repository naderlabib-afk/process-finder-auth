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
    'data/processes/fr.json': {
      processes: [
        { id: 'prod_fr_001', issue: 'PROD-FR-UNIQUE', category: 'Contract', machineType: '', process: 'production fr item 1' },
        { id: 'prod_fr_002', issue: 'PROD-FR-KEEP', category: 'Contract', machineType: '', process: 'production fr item 2' }
      ]
    },
    'data/processes/mea.json': {
      processes: [
        { id: 'prod_mea_001', issue: 'MEA-UNIQUE', category: 'Contract', machineType: '', process: 'same issue allowed in another country baseline' }
      ]
    },
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
    // GOV-1..4: Minimum Admin protection
    // ══════════════════════════════════════════════════════════════════════════
    section('GOV-1: Last Admin cannot be downgraded');
    resetMockState({
      'config/users.json': [
        { email: 'admin-a@ibm.com', name: 'Admin A', role: 'Admin', countries: ['all'] },
        { email: 'ol-a@ibm.com', name: 'OL A', role: 'OL', countries: ['fr'] }
      ]
    });
    const adminCommitCountBeforeDowngrade = mockState._commits.filter(c => c.path === 'config/users.json').length;
    const rLastAdminDowngrade = await apiCall('POST', '/api/admin/users', {
      users: [{ op: 'update', user: { email: 'admin-a@ibm.com', name: 'Admin A', role: 'Manager', countries: ['fr'] } }]
    }, ADMIN_A_TOKEN);
    assert('GOV-1  Last Admin downgrade blocked', rLastAdminDowngrade.status === 400,
      `status=${rLastAdminDowngrade.status} body=${JSON.stringify(rLastAdminDowngrade.json)}`);
    assert('GOV-1b minimum admin message returned', rLastAdminDowngrade.json?.opsMessage?.includes('must always have at least one Admin') === true, '');
    assert('GOV-1c no users.json commit on blocked downgrade',
      mockState._commits.filter(c => c.path === 'config/users.json').length === adminCommitCountBeforeDowngrade, '');

    section('GOV-2: Last Admin cannot be removed');
    resetMockState({
      'config/users.json': [
        { email: 'admin-a@ibm.com', name: 'Admin A', role: 'Admin', countries: ['all'] },
        { email: 'ol-a@ibm.com', name: 'OL A', role: 'OL', countries: ['fr'] }
      ]
    });
    const adminCommitCountBeforeRemove = mockState._commits.filter(c => c.path === 'config/users.json').length;
    const rLastAdminRemove = await apiCall('POST', '/api/admin/users', {
      users: [{ op: 'remove', user: { email: 'admin-a@ibm.com' } }]
    }, ADMIN_A_TOKEN);
    assert('GOV-2  Last Admin removal blocked', rLastAdminRemove.status === 400,
      `status=${rLastAdminRemove.status} body=${JSON.stringify(rLastAdminRemove.json)}`);
    assert('GOV-2b no users.json commit on blocked remove',
      mockState._commits.filter(c => c.path === 'config/users.json').length === adminCommitCountBeforeRemove, '');

    section('GOV-3: Admin downgrade allowed when another Admin remains');
    resetMockState();
    const rAdminDowngradeAllowed = await apiCall('POST', '/api/admin/users', {
      users: [{ op: 'update', user: { email: 'admin-a@ibm.com', name: 'Admin A', role: 'Manager', countries: ['fr'] } }]
    }, ADMIN_B_TOKEN);
    assert('GOV-3  Downgrade succeeds when another Admin remains', rAdminDowngradeAllowed.ok,
      `status=${rAdminDowngradeAllowed.status} body=${JSON.stringify(rAdminDowngradeAllowed.json)}`);

    section('GOV-4: Same batch replacement Admin permits downgrade');
    resetMockState({
      'config/users.json': [
        { email: 'admin-a@ibm.com', name: 'Admin A', role: 'Admin', countries: ['all'] },
        { email: 'ol-a@ibm.com', name: 'OL A', role: 'OL', countries: ['fr'] }
      ]
    });
    const rBatchReplaceAdmin = await apiCall('POST', '/api/admin/users', {
      users: [
        { op: 'add', user: { email: 'admin-b@ibm.com', name: 'Admin B', role: 'Admin', countries: ['all'] } },
        { op: 'update', user: { email: 'admin-a@ibm.com', name: 'Admin A', role: 'Manager', countries: ['fr'] } }
      ]
    }, ADMIN_A_TOKEN);
    assert('GOV-4  Replacement Admin in same batch allows downgrade', rBatchReplaceAdmin.ok,
      `status=${rBatchReplaceAdmin.status} body=${JSON.stringify(rBatchReplaceAdmin.json)}`);

    // ══════════════════════════════════════════════════════════════════════════
    // DUP-1..9: Duplicate Issue/Subject blocking
    // ══════════════════════════════════════════════════════════════════════════
    section('DUP-1: Create duplicate against production same country blocked');
    resetMockState();
    const rDupProd = await apiCall('POST', '/api/ops/buffer', {
      country: 'fr',
      type: 'create',
      process: { id: 'new_dup_prod', issue: 'PROD-FR-UNIQUE', category: 'Contract', machineType: '', process: 'dup prod' }
    }, OL_A_TOKEN);
    assert('DUP-1  Production duplicate blocked', rDupProd.status === 409,
      `status=${rDupProd.status} body=${JSON.stringify(rDupProd.json)}`);
    assert('DUP-1b duplicate payload is typed', rDupProd.json?.code === 'DUPLICATE_ISSUE_SUBJECT', '');

    section('DUP-2: Create duplicate against Buffer pending same country blocked');
    resetMockState();
    const rDupPending = await apiCall('POST', '/api/ops/buffer', {
      country: 'fr',
      type: 'create',
      process: { id: 'new_dup_pending', issue: 'OL-B-ISSUE', category: 'Contract', machineType: '', process: 'dup pending' }
    }, OL_A_TOKEN);
    assert('DUP-2  Buffer pending duplicate blocked', rDupPending.status === 409,
      `status=${rDupPending.status} body=${JSON.stringify(rDupPending.json)}`);

    section('DUP-3: Create duplicate against Buffer validated same country blocked');
    resetMockState();
    const rDupValidated = await apiCall('POST', '/api/ops/buffer', {
      country: 'fr',
      type: 'create',
      process: { id: 'new_dup_validated', issue: 'OL-A-ISSUE', category: 'Contract', machineType: '', process: 'dup validated' }
    }, MANAGER_A_TOKEN);
    assert('DUP-3  Buffer validated duplicate blocked', rDupValidated.status === 409,
      `status=${rDupValidated.status} body=${JSON.stringify(rDupValidated.json)}`);

    section('DUP-4: Create duplicate against countdown scheduled entry blocked');
    resetMockState({
      'data/ops/pr_schedule.json': {
        fr: { country: 'fr', entry_ids: ['fr_ol_a_001'], created_by: 'ol-a@ibm.com', execute_after: new Date(Date.now() + 60000).toISOString() }
      }
    });
    const rDupScheduled = await apiCall('POST', '/api/ops/buffer', {
      country: 'fr',
      type: 'create',
      process: { id: 'new_dup_sched', issue: 'OL-A-ISSUE', category: 'Contract', machineType: '', process: 'dup scheduled' }
    }, MANAGER_A_TOKEN);
    assert('DUP-4  Scheduled duplicate blocked', rDupScheduled.status === 409,
      `status=${rDupScheduled.status} body=${JSON.stringify(rDupScheduled.json)}`);
    assert('DUP-4b duplicate source identifies scheduled snapshot', rDupScheduled.json?.duplicate?.source === 'scheduled', '');

    section('DUP-5: Create duplicate against active Publish Request blocked');
    resetMockState();
    const rDupPR = await apiCall('POST', '/api/ops/buffer', {
      country: 'fr',
      type: 'create',
      process: { id: 'new_dup_pr', issue: 'PR-TEST', category: 'Contract', machineType: '', process: 'dup pr' }
    }, MANAGER_A_TOKEN);
    assert('DUP-5  Active Publish Request duplicate blocked', rDupPR.status === 409,
      `status=${rDupPR.status} body=${JSON.stringify(rDupPR.json)}`);

    section('DUP-6: Same Issue/Subject in another country allowed');
    resetMockState({
      'config/users.json': [
        { email: 'admin-a@ibm.com',  name: 'Admin A',   role: 'Admin',   countries: ['all'] },
        { email: 'ol-a@ibm.com',     name: 'OL A',      role: 'OL',      countries: ['fr'] },
        { email: 'ol-mea@ibm.com',   name: 'OL MEA',    role: 'OL',      countries: ['mea'] },
        { email: 'ol-it@ibm.com',    name: 'OL IT',     role: 'OL',      countries: ['it'] },
        { email: 'ol-es@ibm.com',    name: 'OL ES',     role: 'OL',      countries: ['es'] }
      ],
      'data/processes/it.json': {
        lastUpdated: '2026-06-01T00:00:00.000Z',
        processes: [
          { id: 'prod_it_001', issue: 'IT-UNIQUE', category: 'Contract', machineType: '', process: 'italy production baseline' }
        ]
      },
      'data/processes/es.json': {
        lastUpdated: '2026-06-01T00:00:00.000Z',
        processes: [
          { id: 'prod_es_001', issue: 'ES-UNIQUE', category: 'Contract', machineType: '', process: 'spain production baseline' }
        ]
      }
    });
    const OL_MEA_TOKEN = mintJwt({ email: 'ol-mea@ibm.com', role: 'OL', iat: now, exp: now + 28800 });
    const OL_IT_TOKEN = mintJwt({ email: 'ol-it@ibm.com', role: 'OL', iat: now, exp: now + 28800 });
    const OL_ES_TOKEN = mintJwt({ email: 'ol-es@ibm.com', role: 'OL', iat: now, exp: now + 28800 });
    const rDupOtherCountry = await apiCall('POST', '/api/ops/buffer', {
      country: 'mea',
      type: 'create',
      process: { id: 'mea_allowed_001', issue: 'PROD-FR-UNIQUE', category: 'Contract', machineType: '', process: 'allowed in mea' }
    }, OL_MEA_TOKEN);
    assert('DUP-6  Same issue in different country allowed', rDupOtherCountry.ok,
      `status=${rDupOtherCountry.status} body=${JSON.stringify(rDupOtherCountry.json)}`);

    section('COPY-DUP-1: Copy to target country without duplicate is allowed');
    resetMockState({
      'config/users.json': [
        { email: 'admin-a@ibm.com',  name: 'Admin A',   role: 'Admin',   countries: ['all'] },
        { email: 'ol-a@ibm.com',     name: 'OL A',      role: 'OL',      countries: ['fr'] },
        { email: 'ol-it@ibm.com',    name: 'OL IT',     role: 'OL',      countries: ['it'] },
        { email: 'ol-es@ibm.com',    name: 'OL ES',     role: 'OL',      countries: ['es'] }
      ],
      'data/processes/it.json': {
        lastUpdated: '2026-06-01T00:00:00.000Z',
        processes: [
          { id: 'prod_it_001', issue: 'IT-UNIQUE', category: 'Contract', machineType: '', process: 'italy production baseline' }
        ]
      }
    });
    const rCopyAllowed = await apiCall('POST', '/api/ops/buffer', {
      country: 'it',
      type: 'create',
      process: { id: 'copy_it_001', issue: 'PROD-FR-UNIQUE', category: 'Contract', machineType: '', process: 'copied into italy' }
    }, OL_IT_TOKEN);
    assert('COPY-DUP-1  Copy create into duplicate-free target country allowed', rCopyAllowed.ok,
      `status=${rCopyAllowed.status} body=${JSON.stringify(rCopyAllowed.json)}`);

    section('COPY-DUP-2: Copy blocked when target country already has duplicate in production');
    resetMockState({
      'config/users.json': [
        { email: 'admin-a@ibm.com',  name: 'Admin A',   role: 'Admin',   countries: ['all'] },
        { email: 'ol-a@ibm.com',     name: 'OL A',      role: 'OL',      countries: ['fr'] },
        { email: 'ol-it@ibm.com',    name: 'OL IT',     role: 'OL',      countries: ['it'] }
      ],
      'data/processes/it.json': {
        lastUpdated: '2026-06-01T00:00:00.000Z',
        processes: [
          { id: 'prod_it_dup_001', issue: 'PROD-FR-UNIQUE', category: 'Contract', machineType: '', process: 'italy duplicate in production' }
        ]
      }
    });
    const rCopyDupProd = await apiCall('POST', '/api/ops/buffer', {
      country: 'it',
      type: 'create',
      process: { id: 'copy_it_dup_prod', issue: 'PROD-FR-UNIQUE', category: 'Contract', machineType: '', process: 'copy blocked by italy prod' }
    }, OL_IT_TOKEN);
    assert('COPY-DUP-2  Copy duplicate against target production blocked', rCopyDupProd.status === 409,
      `status=${rCopyDupProd.status} body=${JSON.stringify(rCopyDupProd.json)}`);

    section('COPY-DUP-3: Copy blocked when target country has duplicate in Buffer pending');
    resetMockState({
      'config/users.json': [
        { email: 'admin-a@ibm.com',  name: 'Admin A',   role: 'Admin',   countries: ['all'] },
        { email: 'ol-it@ibm.com',    name: 'OL IT',     role: 'OL',      countries: ['it'] }
      ],
      'data/ops/buffer.json': {
        it: {
          'ol-it@ibm.com': [
            {
              id: 'it_pending_dup_001',
              type: 'create',
              user: 'ol-it@ibm.com',
              status: 'pending',
              process: { id: 'it_pending_proc_001', issue: 'PROD-FR-UNIQUE', category: 'Contract', machineType: '', process: 'italy pending duplicate' },
              createdAt: new Date().toISOString()
            }
          ]
        }
      }
    });
    const rCopyDupPending = await apiCall('POST', '/api/ops/buffer', {
      country: 'it',
      type: 'create',
      process: { id: 'copy_it_dup_pending', issue: 'PROD-FR-UNIQUE', category: 'Contract', machineType: '', process: 'copy blocked by italy pending' }
    }, OL_IT_TOKEN);
    assert('COPY-DUP-3  Copy duplicate against target pending buffer blocked', rCopyDupPending.status === 409,
      `status=${rCopyDupPending.status} body=${JSON.stringify(rCopyDupPending.json)}`);

    section('COPY-DUP-4: Copy blocked when target country has duplicate in Buffer validated');
    resetMockState({
      'config/users.json': [
        { email: 'admin-a@ibm.com',  name: 'Admin A',   role: 'Admin',   countries: ['all'] },
        { email: 'ol-it@ibm.com',    name: 'OL IT',     role: 'OL',      countries: ['it'] }
      ],
      'data/ops/buffer.json': {
        it: {
          'ol-it@ibm.com': [
            {
              id: 'it_valid_dup_001',
              type: 'create',
              user: 'ol-it@ibm.com',
              status: 'validated',
              process: { id: 'it_valid_proc_001', issue: 'PROD-FR-UNIQUE', category: 'Contract', machineType: '', process: 'italy validated duplicate' },
              createdAt: new Date().toISOString()
            }
          ]
        }
      }
    });
    const rCopyDupValidated = await apiCall('POST', '/api/ops/buffer', {
      country: 'it',
      type: 'create',
      process: { id: 'copy_it_dup_validated', issue: 'PROD-FR-UNIQUE', category: 'Contract', machineType: '', process: 'copy blocked by italy validated' }
    }, OL_IT_TOKEN);
    assert('COPY-DUP-4  Copy duplicate against target validated buffer blocked', rCopyDupValidated.status === 409,
      `status=${rCopyDupValidated.status} body=${JSON.stringify(rCopyDupValidated.json)}`);

    section('COPY-DUP-5: Copy blocked when target country has duplicate in scheduled Publish Request');
    resetMockState({
      'config/users.json': [
        { email: 'admin-a@ibm.com',  name: 'Admin A',   role: 'Admin',   countries: ['all'] },
        { email: 'ol-it@ibm.com',    name: 'OL IT',     role: 'OL',      countries: ['it'] }
      ],
      'data/ops/buffer.json': {
        it: {
          'ol-it@ibm.com': [
            {
              id: 'it_sched_dup_001',
              type: 'create',
              user: 'ol-it@ibm.com',
              status: 'validated',
              process: { id: 'it_sched_proc_001', issue: 'PROD-FR-UNIQUE', category: 'Contract', machineType: '', process: 'italy scheduled duplicate' },
              createdAt: new Date().toISOString()
            }
          ]
        }
      },
      'data/ops/pr_schedule.json': {
        it: { country: 'it', entry_ids: ['it_sched_dup_001'], created_by: 'ol-it@ibm.com', execute_after: new Date(Date.now() + 60000).toISOString() }
      }
    });
    const rCopyDupScheduled = await apiCall('POST', '/api/ops/buffer', {
      country: 'it',
      type: 'create',
      process: { id: 'copy_it_dup_sched', issue: 'PROD-FR-UNIQUE', category: 'Contract', machineType: '', process: 'copy blocked by italy scheduled' }
    }, OL_IT_TOKEN);
    assert('COPY-DUP-5  Copy duplicate against target scheduled request blocked', rCopyDupScheduled.status === 409,
      `status=${rCopyDupScheduled.status} body=${JSON.stringify(rCopyDupScheduled.json)}`);

    section('COPY-DUP-6: Copy blocked when target country has duplicate in active Publish Request');
    resetMockState({
      'config/users.json': [
        { email: 'admin-a@ibm.com',  name: 'Admin A',   role: 'Admin',   countries: ['all'] },
        { email: 'ol-it@ibm.com',    name: 'OL IT',     role: 'OL',      countries: ['it'] }
      ],
      'data/ops/history.json': {
        fr: [
          {
            id: 'hist_fr_001',
            type: 'create',
            user: 'manager-a@ibm.com',
            pr_status: 'pending_merge',
            prNumber: 77,
            process: { id: 'hist_fr_proc_001', issue: 'PR-TEST', category: 'Contract', machineType: '', process: 'fr active pr baseline' }
          }
        ],
        it: [
          {
            id: 'hist_it_001',
            type: 'create',
            user: 'ol-it@ibm.com',
            pr_status: 'pending_merge',
            prNumber: 88,
            process: { id: 'hist_it_proc_001', issue: 'PROD-FR-UNIQUE', category: 'Contract', machineType: '', process: 'italy active pr duplicate' }
          }
        ]
      }
    });
    const rCopyDupActivePR = await apiCall('POST', '/api/ops/buffer', {
      country: 'it',
      type: 'create',
      process: { id: 'copy_it_dup_pr', issue: 'PROD-FR-UNIQUE', category: 'Contract', machineType: '', process: 'copy blocked by italy active pr' }
    }, OL_IT_TOKEN);
    assert('COPY-DUP-6  Copy duplicate against target active Publish Request blocked', rCopyDupActivePR.status === 409,
      `status=${rCopyDupActivePR.status} body=${JSON.stringify(rCopyDupActivePR.json)}`);

    section('COPY-DUP-7: Multi-target copy behavior remains country-scoped');
    resetMockState({
      'config/users.json': [
        { email: 'admin-a@ibm.com',  name: 'Admin A',   role: 'Admin',   countries: ['all'] },
        { email: 'ol-it@ibm.com',    name: 'OL IT',     role: 'OL',      countries: ['it'] },
        { email: 'ol-es@ibm.com',    name: 'OL ES',     role: 'OL',      countries: ['es'] }
      ],
      'data/processes/it.json': {
        lastUpdated: '2026-06-01T00:00:00.000Z',
        processes: [
          { id: 'prod_it_dup_001', issue: 'PROD-FR-UNIQUE', category: 'Contract', machineType: '', process: 'italy duplicate in production' }
        ]
      },
      'data/processes/es.json': {
        lastUpdated: '2026-06-01T00:00:00.000Z',
        processes: [
          { id: 'prod_es_001', issue: 'ES-UNIQUE', category: 'Contract', machineType: '', process: 'spain production baseline' }
        ]
      }
    });
    const rCopyMultiBlocked = await apiCall('POST', '/api/ops/buffer', {
      country: 'it',
      type: 'create',
      process: { id: 'copy_multi_it_001', issue: 'PROD-FR-UNIQUE', category: 'Contract', machineType: '', process: 'copy multi blocked in italy' }
    }, OL_IT_TOKEN);
    const rCopyMultiAllowed = await apiCall('POST', '/api/ops/buffer', {
      country: 'es',
      type: 'create',
      process: { id: 'copy_multi_es_001', issue: 'PROD-FR-UNIQUE', category: 'Contract', machineType: '', process: 'copy multi allowed in spain' }
    }, OL_ES_TOKEN);
    assert('COPY-DUP-7  Multi-target blocked country stays blocked', rCopyMultiBlocked.status === 409,
      `status=${rCopyMultiBlocked.status} body=${JSON.stringify(rCopyMultiBlocked.json)}`);
    assert('COPY-DUP-7b Multi-target duplicate-free country succeeds', rCopyMultiAllowed.ok,
      `status=${rCopyMultiAllowed.status} body=${JSON.stringify(rCopyMultiAllowed.json)}`);

    section('COPY-DUP-8: Source-country duplicate alone does not block target-country copy');
    resetMockState({
      'config/users.json': [
        { email: 'admin-a@ibm.com',  name: 'Admin A',   role: 'Admin',   countries: ['all'] },
        { email: 'ol-it@ibm.com',    name: 'OL IT',     role: 'OL',      countries: ['it'] }
      ],
      'data/processes/it.json': {
        lastUpdated: '2026-06-01T00:00:00.000Z',
        processes: [
          { id: 'prod_it_001', issue: 'IT-UNIQUE', category: 'Contract', machineType: '', process: 'italy production baseline' }
        ]
      }
    });
    const rCopySourceOnly = await apiCall('POST', '/api/ops/buffer', {
      country: 'it',
      type: 'create',
      process: { id: 'copy_source_only_001', issue: 'PROD-FR-UNIQUE', category: 'Contract', machineType: '', process: 'copy allowed because only source country matches' }
    }, OL_IT_TOKEN);
    assert('COPY-DUP-8  Source-country duplicate alone does not block target', rCopySourceOnly.ok,
      `status=${rCopySourceOnly.status} body=${JSON.stringify(rCopySourceOnly.json)}`);

    section('DUP-7: Update same process keeping same Issue/Subject allowed');
    resetMockState();
    const rUpdateKeepOwn = await apiCall('POST', '/api/ops/buffer', {
      country: 'fr',
      type: 'update',
      process: { id: 'prod_fr_001', originalProcessId: 'prod_fr_001', issue: 'PROD-FR-UNIQUE', category: 'Contract', machineType: '', process: 'updated text' }
    }, MANAGER_A_TOKEN);
    assert('DUP-7  Update keeping own issue allowed', rUpdateKeepOwn.ok,
      `status=${rUpdateKeepOwn.status} body=${JSON.stringify(rUpdateKeepOwn.json)}`);

    section('DUP-8: Update changing Issue/Subject to another same-country active subject blocked');
    resetMockState();
    const rUpdateToDuplicate = await apiCall('POST', '/api/ops/buffer', {
      country: 'fr',
      type: 'update',
      process: { id: 'prod_fr_002', originalProcessId: 'prod_fr_002', issue: 'PROD-FR-UNIQUE', category: 'Contract', machineType: '', process: 'dup change' }
    }, MANAGER_A_TOKEN);
    assert('DUP-8  Update to another active issue blocked', rUpdateToDuplicate.status === 409,
      `status=${rUpdateToDuplicate.status} body=${JSON.stringify(rUpdateToDuplicate.json)}`);

    section('DUP-9: Buffer edit update changing Issue/Subject to duplicate blocked');
    resetMockState({
      'data/ops/buffer.json': {
        fr: {
          'ol-a@ibm.com': [
            {
              id: 'buf_update_001',
              type: 'update',
              originalProcessId: 'prod_fr_002',
              user: 'ol-a@ibm.com',
              status: 'pending',
              process: { id: 'buf_update_001', originalProcessId: 'prod_fr_002', issue: 'PROD-FR-KEEP', category: 'Contract', machineType: '', process: 'draft' },
              createdAt: new Date().toISOString()
            }
          ]
        }
      }
    });
    const editedBufferDup = JSON.parse(JSON.stringify(mockState['data/ops/buffer.json']));
    editedBufferDup.fr['ol-a@ibm.com'][0].process.issue = 'PROD-FR-UNIQUE';
    const rBufferEditDup = await apiCall('PUT', '/api/ops/buffer', {
      buffer: editedBufferDup,
      editEntryId: 'buf_update_001'
    }, OL_A_TOKEN);
    assert('DUP-9  Buffer edit duplicate blocked', rBufferEditDup.status === 409,
      `status=${rBufferEditDup.status} body=${JSON.stringify(rBufferEditDup.json)}`);

    section('DUP-10: Buffer edit create to duplicate production same-country blocked');
    resetMockState({
      'data/ops/buffer.json': {
        fr: {
          'ol-a@ibm.com': [
            {
              id: 'buf_create_001',
              type: 'create',
              user: 'ol-a@ibm.com',
              status: 'pending',
              process: { id: 'buf_create_001', issue: 'TEMP DUP TEST 0507', category: 'Contract', machineType: '', process: 'draft create' },
              createdAt: new Date().toISOString()
            }
          ]
        }
      }
    });
    const editedCreateVsProd = JSON.parse(JSON.stringify(mockState['data/ops/buffer.json']));
    editedCreateVsProd.fr['ol-a@ibm.com'][0].process.issue = 'PROD-FR-UNIQUE';
    const rBufferCreateVsProd = await apiCall('PUT', '/api/ops/buffer', {
      buffer: editedCreateVsProd,
      editEntryId: 'buf_create_001'
    }, OL_A_TOKEN);
    assert('DUP-10  Buffer create edit duplicate vs production blocked', rBufferCreateVsProd.status === 409,
      `status=${rBufferCreateVsProd.status} body=${JSON.stringify(rBufferCreateVsProd.json)}`);

    section('DUP-11: Buffer edit create to duplicate Buffer pending same-country blocked');
    resetMockState({
      'data/ops/buffer.json': {
        fr: {
          'ol-a@ibm.com': [
            {
              id: 'buf_create_001',
              type: 'create',
              user: 'ol-a@ibm.com',
              status: 'pending',
              process: { id: 'buf_create_001', issue: 'TEMP DUP TEST 0507', category: 'Contract', machineType: '', process: 'draft create' },
              createdAt: new Date().toISOString()
            }
          ],
          'ol-b@ibm.com': [
            {
              id: 'fr_ol_b_001',
              type: 'create',
              user: 'ol-b@ibm.com',
              status: 'pending',
              process: { id: 'fr_ol_b_001', issue: 'OL-B-ISSUE', category: 'Contract', machineType: '', process: 'pending duplicate target' },
              createdAt: new Date().toISOString()
            }
          ]
        }
      }
    });
    const editedCreateVsPending = JSON.parse(JSON.stringify(mockState['data/ops/buffer.json']));
    editedCreateVsPending.fr['ol-a@ibm.com'][0].process.issue = 'OL-B-ISSUE';
    const rBufferCreateVsPending = await apiCall('PUT', '/api/ops/buffer', {
      buffer: editedCreateVsPending,
      editEntryId: 'buf_create_001'
    }, OL_A_TOKEN);
    assert('DUP-11  Buffer create edit duplicate vs pending blocked', rBufferCreateVsPending.status === 409,
      `status=${rBufferCreateVsPending.status} body=${JSON.stringify(rBufferCreateVsPending.json)}`);

    section('DUP-12: Buffer edit create to duplicate Buffer validated same-country blocked');
    resetMockState({
      'data/ops/buffer.json': {
        fr: {
          'ol-a@ibm.com': [
            {
              id: 'buf_create_001',
              type: 'create',
              user: 'ol-a@ibm.com',
              status: 'pending',
              process: { id: 'buf_create_001', issue: 'TEMP DUP TEST 0507', category: 'Contract', machineType: '', process: 'draft create' },
              createdAt: new Date().toISOString()
            },
            {
              id: 'fr_ol_a_001',
              type: 'create',
              user: 'ol-a@ibm.com',
              status: 'validated',
              process: { id: 'fr_ol_a_001', issue: 'OL-A-ISSUE', category: 'Contract', machineType: '', process: 'validated duplicate target' },
              createdAt: new Date().toISOString()
            }
          ]
        }
      }
    });
    const editedCreateVsValidated = JSON.parse(JSON.stringify(mockState['data/ops/buffer.json']));
    editedCreateVsValidated.fr['ol-a@ibm.com'][0].process.issue = 'OL-A-ISSUE';
    const rBufferCreateVsValidated = await apiCall('PUT', '/api/ops/buffer', {
      buffer: editedCreateVsValidated,
      editEntryId: 'buf_create_001'
    }, OL_A_TOKEN);
    assert('DUP-12  Buffer create edit duplicate vs validated blocked', rBufferCreateVsValidated.status === 409,
      `status=${rBufferCreateVsValidated.status} body=${JSON.stringify(rBufferCreateVsValidated.json)}`);

    section('DUP-13: Buffer edit create to duplicate scheduled same-country blocked');
    resetMockState({
      'data/ops/buffer.json': {
        fr: {
          'ol-a@ibm.com': [
            {
              id: 'buf_create_001',
              type: 'create',
              user: 'ol-a@ibm.com',
              status: 'pending',
              process: { id: 'buf_create_001', issue: 'TEMP DUP TEST 0507', category: 'Contract', machineType: '', process: 'draft create' },
              createdAt: new Date().toISOString()
            },
            {
              id: 'fr_sched_001',
              type: 'create',
              user: 'ol-a@ibm.com',
              status: 'validated',
              process: { id: 'fr_sched_001', issue: 'SCHEDULED-DUP', category: 'Contract', machineType: '', process: 'scheduled duplicate target' },
              createdAt: new Date().toISOString()
            }
          ]
        }
      },
      'data/ops/pr_schedule.json': {
        fr: { country: 'fr', entry_ids: ['fr_sched_001'], created_by: 'ol-a@ibm.com', execute_after: new Date(Date.now() + 60000).toISOString() }
      }
    });
    const editedCreateVsScheduled = JSON.parse(JSON.stringify(mockState['data/ops/buffer.json']));
    editedCreateVsScheduled.fr['ol-a@ibm.com'][0].process.issue = 'SCHEDULED-DUP';
    const rBufferCreateVsScheduled = await apiCall('PUT', '/api/ops/buffer', {
      buffer: editedCreateVsScheduled,
      editEntryId: 'buf_create_001'
    }, OL_A_TOKEN);
    assert('DUP-13  Buffer create edit duplicate vs scheduled blocked', rBufferCreateVsScheduled.status === 409,
      `status=${rBufferCreateVsScheduled.status} body=${JSON.stringify(rBufferCreateVsScheduled.json)}`);

    section('DUP-14: Buffer edit create to duplicate active Publish Request blocked');
    resetMockState({
      'data/ops/buffer.json': {
        fr: {
          'ol-a@ibm.com': [
            {
              id: 'buf_create_001',
              type: 'create',
              user: 'ol-a@ibm.com',
              status: 'pending',
              process: { id: 'buf_create_001', issue: 'TEMP DUP TEST 0507', category: 'Contract', machineType: '', process: 'draft create' },
              createdAt: new Date().toISOString()
            }
          ]
        }
      },
      'data/ops/history.json': {
        fr: [
          {
            id: 'fr_pr_dup_001',
            type: 'create',
            user: 'manager-a@ibm.com',
            pr_status: 'pending_merge',
            prNumber: PR_NUM,
            process: { id: 'fr_pr_dup_001', issue: 'PR-TEST', category: 'Contract', machineType: '', process: 'active pr duplicate target' }
          }
        ]
      }
    });
    const editedCreateVsPR = JSON.parse(JSON.stringify(mockState['data/ops/buffer.json']));
    editedCreateVsPR.fr['ol-a@ibm.com'][0].process.issue = 'PR-TEST';
    const rBufferCreateVsPR = await apiCall('PUT', '/api/ops/buffer', {
      buffer: editedCreateVsPR,
      editEntryId: 'buf_create_001'
    }, OL_A_TOKEN);
    assert('DUP-14  Buffer create edit duplicate vs active Publish Request blocked', rBufferCreateVsPR.status === 409,
      `status=${rBufferCreateVsPR.status} body=${JSON.stringify(rBufferCreateVsPR.json)}`);

    section('DUP-15: Buffer edit create same Issue/Subject in another country allowed');
    resetMockState({
      'data/ops/buffer.json': {
        fr: {
          'ol-a@ibm.com': [
            {
              id: 'buf_create_001',
              type: 'create',
              user: 'ol-a@ibm.com',
              status: 'pending',
              process: { id: 'buf_create_001', issue: 'TEMP DUP TEST 0507', category: 'Contract', machineType: '', process: 'draft create' },
              createdAt: new Date().toISOString()
            }
          ]
        }
      },
      'data/processes/mea.json': {
        processes: [
          { id: 'prod_mea_dup_001', issue: 'MEA-UNIQUE', category: 'Contract', machineType: '', process: 'other country duplicate baseline' }
        ]
      }
    });
    const editedCreateOtherCountry = JSON.parse(JSON.stringify(mockState['data/ops/buffer.json']));
    editedCreateOtherCountry.fr['ol-a@ibm.com'][0].process.issue = 'MEA-UNIQUE';
    const rBufferCreateOtherCountry = await apiCall('PUT', '/api/ops/buffer', {
      buffer: editedCreateOtherCountry,
      editEntryId: 'buf_create_001'
    }, OL_A_TOKEN);
    assert('DUP-15  Buffer create edit same issue in another country allowed', rBufferCreateOtherCountry.ok,
      `status=${rBufferCreateOtherCountry.status} body=${JSON.stringify(rBufferCreateOtherCountry.json)}`);

    section('DUP-16: Buffer edit create unique non-duplicate subject saves');
    resetMockState({
      'data/ops/buffer.json': {
        fr: {
          'ol-a@ibm.com': [
            {
              id: 'buf_create_001',
              type: 'create',
              user: 'ol-a@ibm.com',
              status: 'pending',
              process: { id: 'buf_create_001', issue: 'TEMP DUP TEST 0507', category: 'Contract', machineType: '', process: 'draft create' },
              createdAt: new Date().toISOString()
            }
          ]
        }
      }
    });
    const editedCreateUnique = JSON.parse(JSON.stringify(mockState['data/ops/buffer.json']));
    editedCreateUnique.fr['ol-a@ibm.com'][0].process.issue = 'UNIQUE-BUFFER-CREATE-EDIT';
    const rBufferCreateUnique = await apiCall('PUT', '/api/ops/buffer', {
      buffer: editedCreateUnique,
      editEntryId: 'buf_create_001'
    }, OL_A_TOKEN);
    assert('DUP-16  Buffer create edit unique issue saves', rBufferCreateUnique.ok,
      `status=${rBufferCreateUnique.status} body=${JSON.stringify(rBufferCreateUnique.json)}`);
    assert('DUP-16b edited create entry persisted unique issue',
      mockState['data/ops/buffer.json']?.fr?.['ol-a@ibm.com']?.[0]?.process?.issue === 'UNIQUE-BUFFER-CREATE-EDIT', '');

    section('DUP-17: Update same original process keeping own Issue/Subject allowed on Buffer edit');
    resetMockState({
      'data/ops/buffer.json': {
        fr: {
          'ol-a@ibm.com': [
            {
              id: 'buf_update_001',
              type: 'update',
              originalProcessId: 'prod_fr_001',
              user: 'ol-a@ibm.com',
              status: 'pending',
              process: { id: 'buf_update_001', originalProcessId: 'prod_fr_001', issue: 'PROD-FR-UNIQUE', category: 'Contract', machineType: '', process: 'update keep own issue' },
              createdAt: new Date().toISOString()
            }
          ]
        }
      }
    });
    const editedUpdateOwn = JSON.parse(JSON.stringify(mockState['data/ops/buffer.json']));
    editedUpdateOwn.fr['ol-a@ibm.com'][0].process.process = 'updated text';
    const rBufferUpdateOwn = await apiCall('PUT', '/api/ops/buffer', {
      buffer: editedUpdateOwn,
      editEntryId: 'buf_update_001'
    }, OL_A_TOKEN);
    assert('DUP-17  Buffer update edit keeping own issue allowed', rBufferUpdateOwn.ok,
      `status=${rBufferUpdateOwn.status} body=${JSON.stringify(rBufferUpdateOwn.json)}`);

    section('DUP-18: Update changing to another same-country Issue/Subject blocked on Buffer edit');
    resetMockState({
      'data/ops/buffer.json': {
        fr: {
          'ol-a@ibm.com': [
            {
              id: 'buf_update_001',
              type: 'update',
              originalProcessId: 'prod_fr_002',
              user: 'ol-a@ibm.com',
              status: 'pending',
              process: { id: 'buf_update_001', originalProcessId: 'prod_fr_002', issue: 'PROD-FR-KEEP', category: 'Contract', machineType: '', process: 'draft update' },
              createdAt: new Date().toISOString()
            }
          ]
        }
      }
    });
    const editedUpdateDuplicate = JSON.parse(JSON.stringify(mockState['data/ops/buffer.json']));
    editedUpdateDuplicate.fr['ol-a@ibm.com'][0].process.issue = 'PROD-FR-UNIQUE';
    const rBufferUpdateDuplicate = await apiCall('PUT', '/api/ops/buffer', {
      buffer: editedUpdateDuplicate,
      editEntryId: 'buf_update_001'
    }, OL_A_TOKEN);
    assert('DUP-18  Buffer update edit to another active issue blocked', rBufferUpdateDuplicate.status === 409,
      `status=${rBufferUpdateDuplicate.status} body=${JSON.stringify(rBufferUpdateDuplicate.json)}`);

    section('DUP-19: Legacy update entry without originalProcessId is normalized from process.id');
    resetMockState({
      'data/ops/buffer.json': {
        fr: {
          'ol-a@ibm.com': [
            {
              id: 'legacy_update_001',
              type: 'update',
              user: 'ol-a@ibm.com',
              status: 'pending',
              process: { id: 'prod_fr_002', issue: 'PROD-FR-KEEP', category: 'Contract', machineType: '', process: 'legacy update draft' },
              createdAt: new Date().toISOString()
            }
          ]
        }
      }
    });
    const legacyUpdateBuffer = JSON.parse(JSON.stringify(mockState['data/ops/buffer.json']));
    legacyUpdateBuffer.fr['ol-a@ibm.com'][0].process.issue = 'UNIQUE-LEGACY-UPDATE';
    const rLegacyUpdateNorm = await apiCall('PUT', '/api/ops/buffer', {
      buffer: legacyUpdateBuffer,
      editEntryId: 'legacy_update_001'
    }, OL_A_TOKEN);
    assert('DUP-10  Legacy update normalized successfully', rLegacyUpdateNorm.ok,
      `status=${rLegacyUpdateNorm.status} body=${JSON.stringify(rLegacyUpdateNorm.json)}`);
    assert('DUP-10b originalProcessId backfilled on entry',
      mockState['data/ops/buffer.json']?.fr?.['ol-a@ibm.com']?.[0]?.originalProcessId === 'prod_fr_002', '');
    assert('DUP-10c originalProcessId backfilled on process',
      mockState['data/ops/buffer.json']?.fr?.['ol-a@ibm.com']?.[0]?.process?.originalProcessId === 'prod_fr_002', '');

    section('DUP-11: Legacy delete entry without originalProcessId is normalized from process.id');
    resetMockState({
      'data/ops/buffer.json': {
        fr: {
          'ol-a@ibm.com': [
            {
              id: 'legacy_delete_001',
              type: 'delete',
              user: 'ol-a@ibm.com',
              status: 'pending',
              process: { id: 'prod_fr_001', issue: 'PROD-FR-UNIQUE' },
              createdAt: new Date().toISOString()
            }
          ]
        }
      }
    });
    const legacyDeleteBuffer = JSON.parse(JSON.stringify(mockState['data/ops/buffer.json']));
    const rLegacyDeleteNorm = await apiCall('PUT', '/api/ops/buffer', {
      buffer: legacyDeleteBuffer,
      editEntryId: 'legacy_delete_001'
    }, OL_A_TOKEN);
    assert('DUP-11  Legacy delete normalized successfully', rLegacyDeleteNorm.ok,
      `status=${rLegacyDeleteNorm.status} body=${JSON.stringify(rLegacyDeleteNorm.json)}`);
    assert('DUP-11b originalProcessId backfilled on delete entry',
      mockState['data/ops/buffer.json']?.fr?.['ol-a@ibm.com']?.[0]?.originalProcessId === 'prod_fr_001', '');

    section('DUP-12: Create entry does not require originalProcessId');
    resetMockState({
      'data/ops/buffer.json': {
        fr: {
          'ol-a@ibm.com': [
            {
              id: 'create_entry_001',
              type: 'create',
              user: 'ol-a@ibm.com',
              status: 'pending',
              process: { id: 'create_entry_001', issue: 'CREATE-UNIQUE', category: 'Contract', machineType: '', process: 'create draft' },
              createdAt: new Date().toISOString()
            }
          ]
        }
      }
    });
    const createBuffer = JSON.parse(JSON.stringify(mockState['data/ops/buffer.json']));
    createBuffer.fr['ol-a@ibm.com'][0].process.issue = 'CREATE-UNIQUE-EDIT';
    const rCreateNoOriginal = await apiCall('PUT', '/api/ops/buffer', {
      buffer: createBuffer,
      editEntryId: 'create_entry_001'
    }, OL_A_TOKEN);
    assert('DUP-12  Create entry save does not require originalProcessId', rCreateNoOriginal.ok,
      `status=${rCreateNoOriginal.status} body=${JSON.stringify(rCreateNoOriginal.json)}`);

    section('DUP-13: Unresolvable existing workflow returns MISSING_ORIGINAL_PROCESS_ID details');
    resetMockState({
      'data/ops/buffer.json': {
        fr: {
          'ol-a@ibm.com': [
            {
              id: 'broken_update_001',
              type: 'update',
              user: 'ol-a@ibm.com',
              status: 'pending',
              process: { issue: 'BROKEN-UPDATE', category: 'Contract', machineType: '', process: 'broken draft' },
              createdAt: new Date().toISOString()
            }
          ]
        }
      }
    });
    const brokenBuffer = JSON.parse(JSON.stringify(mockState['data/ops/buffer.json']));
    const rBrokenIdentity = await apiCall('PUT', '/api/ops/buffer', {
      buffer: brokenBuffer,
      editEntryId: 'broken_update_001'
    }, OL_A_TOKEN);
    assert('DUP-13  Unresolvable workflow returns 400', rBrokenIdentity.status === 400,
      `status=${rBrokenIdentity.status} body=${JSON.stringify(rBrokenIdentity.json)}`);
    assert('DUP-13b returns MISSING_ORIGINAL_PROCESS_ID code', rBrokenIdentity.json?.code === 'MISSING_ORIGINAL_PROCESS_ID', '');
    assert('DUP-13c diagnostic entryId included', rBrokenIdentity.json?.details?.entryId === 'broken_update_001', '');

    // ══════════════════════════════════════════════════════════════════════════
    // LOCK-1..7: Existing process workflow lock by originalProcessId
    // ══════════════════════════════════════════════════════════════════════════
    section('LOCK-1: Update entry locks by original process ID');
    resetMockState();
    const rLockUpdate = await apiCall('POST', '/api/ops/buffer', {
      country: 'fr',
      type: 'update',
      process: { id: 'prod_fr_001', originalProcessId: 'prod_fr_001', issue: 'PROD-FR-UNIQUE', category: 'Contract', machineType: '', process: 'lock update' }
    }, OL_A_TOKEN);
    assert('LOCK-1  Update entry created', rLockUpdate.ok,
      `status=${rLockUpdate.status} body=${JSON.stringify(rLockUpdate.json)}`);
    assert('LOCK-1b originalProcessId stored on entry', rLockUpdate.json?.entry?.originalProcessId === 'prod_fr_001', '');

    section('LOCK-2: Second update/delete on same originalProcessId blocked');
    const rLockSecond = await apiCall('POST', '/api/ops/buffer', {
      country: 'fr',
      type: 'delete',
      process: { id: 'prod_fr_001', originalProcessId: 'prod_fr_001', issue: 'PROD-FR-UNIQUE' }
    }, MANAGER_A_TOKEN);
    assert('LOCK-2  Second workflow blocked', rLockSecond.status === 409,
      `status=${rLockSecond.status} body=${JSON.stringify(rLockSecond.json)}`);

    section('LOCK-3: Changing Issue/Subject during update does not unlock original process');
    resetMockState({
      'data/ops/buffer.json': {
        fr: {
          'ol-a@ibm.com': [
            {
              id: 'buf_update_lock_1',
              type: 'update',
              originalProcessId: 'prod_fr_001',
              user: 'ol-a@ibm.com',
              status: 'pending',
              process: { id: 'buf_update_lock_1', originalProcessId: 'prod_fr_001', issue: 'PROD-FR-RENAMED', category: 'Contract', machineType: '', process: 'renamed draft' },
              createdAt: new Date().toISOString()
            }
          ]
        }
      }
    });
    const rLockRenameStillLocked = await apiCall('POST', '/api/ops/buffer', {
      country: 'fr',
      type: 'delete',
      process: { id: 'prod_fr_001', originalProcessId: 'prod_fr_001', issue: 'PROD-FR-UNIQUE' }
    }, MANAGER_A_TOKEN);
    assert('LOCK-3  Renamed draft still keeps original process locked', rLockRenameStillLocked.status === 409,
      `status=${rLockRenameStillLocked.status} body=${JSON.stringify(rLockRenameStillLocked.json)}`);

    section('LOCK-4: Removing pre-PR Buffer entry unlocks original process');
    resetMockState({
      'data/ops/buffer.json': {
        fr: {
          'ol-a@ibm.com': [
            {
              id: 'buf_update_unlock_1',
              type: 'update',
              originalProcessId: 'prod_fr_001',
              user: 'ol-a@ibm.com',
              status: 'pending',
              process: { id: 'buf_update_unlock_1', originalProcessId: 'prod_fr_001', issue: 'PROD-FR-UNIQUE', category: 'Contract', machineType: '', process: 'draft' },
              createdAt: new Date().toISOString()
            }
          ]
        }
      }
    });
    const rCancelLock = await apiCall('POST', '/api/ops/cancel', { country: 'fr', user: 'ol-a@ibm.com', index: 0 }, OL_A_TOKEN);
    assert('LOCK-4  Cancel pre-PR entry succeeds', rCancelLock.ok,
      `status=${rCancelLock.status} body=${JSON.stringify(rCancelLock.json)}`);
    const rAfterCancelUnlock = await apiCall('POST', '/api/ops/buffer', {
      country: 'fr',
      type: 'delete',
      process: { id: 'prod_fr_001', originalProcessId: 'prod_fr_001', issue: 'PROD-FR-UNIQUE' }
    }, MANAGER_A_TOKEN);
    assert('LOCK-4b  New workflow allowed after cancel unlock', rAfterCancelUnlock.ok,
      `status=${rAfterCancelUnlock.status} body=${JSON.stringify(rAfterCancelUnlock.json)}`);

    section('LOCK-5: Active Publish Request keeps process locked');
    resetMockState({
      'data/ops/history.json': {
        fr: [
          { id: 'hist_lock_001', type: 'update', originalProcessId: 'prod_fr_001', user: 'ol-a@ibm.com', status: 'validated',
            pr_status: 'pending_merge', prNumber: PR_NUM, branchName: 'ops/fr/20260710-1000',
            process: { id: 'hist_lock_001', originalProcessId: 'prod_fr_001', issue: 'PROD-FR-RENAMED', category: 'Contract', machineType: '', process: 'pending merge' } }
        ]
      }
    });
    const rActivePRLock = await apiCall('POST', '/api/ops/buffer', {
      country: 'fr',
      type: 'delete',
      process: { id: 'prod_fr_001', originalProcessId: 'prod_fr_001', issue: 'PROD-FR-UNIQUE' }
    }, MANAGER_A_TOKEN);
    assert('LOCK-5  Active Publish Request keeps lock', rActivePRLock.status === 409,
      `status=${rActivePRLock.status} body=${JSON.stringify(rActivePRLock.json)}`);

    section('LOCK-6: Admin reject unlocks original process');
    resetMockState({
      'data/ops/history.json': {
        fr: [
          { id: 'hist_reject_001', type: 'update', originalProcessId: 'prod_fr_001', user: 'ol-a@ibm.com', status: 'validated',
            pr_status: 'pending_merge', prNumber: PR_NUM, prUrl: `https://github.ibm.com/nlabib/process-finder/pull/${PR_NUM}`,
            branchName: 'ops/fr/20260710-1000',
            process: { id: 'hist_reject_001', originalProcessId: 'prod_fr_001', issue: 'PROD-FR-RENAMED', category: 'Contract', machineType: '', process: 'pending reject' } }
        ]
      }
    });
    const rRejectUnlock = await apiCall('POST', '/api/admin/pr/close', { country: 'fr', prNumber: PR_NUM }, ADMIN_A_TOKEN);
    assert('LOCK-6  Reject succeeds', rRejectUnlock.ok,
      `status=${rRejectUnlock.status} body=${JSON.stringify(rRejectUnlock.json)}`);
    const rAfterRejectUnlock = await apiCall('POST', '/api/ops/buffer', {
      country: 'fr',
      type: 'update',
      process: { id: 'prod_fr_001', originalProcessId: 'prod_fr_001', issue: 'PROD-FR-UNIQUE', category: 'Contract', machineType: '', process: 'new draft after reject' }
    }, MANAGER_A_TOKEN);
    assert('LOCK-6b  Original process unlocked after reject', rAfterRejectUnlock.ok,
      `status=${rAfterRejectUnlock.status} body=${JSON.stringify(rAfterRejectUnlock.json)}`);

    section('LOCK-7: Admin approve modify unlocks new version');
    resetMockState({
      'data/ops/history.json': {
        fr: [
          { id: 'hist_approve_001', type: 'update', originalProcessId: 'prod_fr_001', user: 'ol-a@ibm.com', status: 'validated',
            pr_status: 'pending_merge', prNumber: PR_NUM, prUrl: `https://github.ibm.com/nlabib/process-finder/pull/${PR_NUM}`,
            branchName: 'ops/fr/20260710-1000',
            process: { id: 'hist_approve_001', originalProcessId: 'prod_fr_001', issue: 'PROD-FR-RENAMED', category: 'Contract', machineType: '', process: 'pending approve' } },
          { id: 'hist_delete_001', type: 'delete', originalProcessId: 'prod_fr_002', user: 'ol-a@ibm.com', status: 'validated',
            pr_status: 'pending_merge', prNumber: PR_NUM, prUrl: `https://github.ibm.com/nlabib/process-finder/pull/${PR_NUM}`,
            branchName: 'ops/fr/20260710-1000',
            process: { id: 'hist_delete_001', originalProcessId: 'prod_fr_002', issue: 'PROD-FR-KEEP' } }
        ]
      }
    });
    const rApproveUnlock = await apiCall('POST', '/api/admin/pr/approve', { country: 'fr', prNumber: PR_NUM }, ADMIN_A_TOKEN);
    assert('LOCK-7  Approve succeeds', rApproveUnlock.ok,
      `status=${rApproveUnlock.status} body=${JSON.stringify(rApproveUnlock.json)}`);
    const histAfterApprove = mockState['data/ops/history.json']?.fr || [];
    assert('LOCK-7b  Modify entry marked merged', histAfterApprove.some(h => h.id === 'hist_approve_001' && h.pr_status === 'merged'), '');
    assert('LOCK-7c  Delete entry marked merged', histAfterApprove.some(h => h.id === 'hist_delete_001' && h.pr_status === 'merged'), '');

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
