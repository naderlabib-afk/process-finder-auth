#!/usr/bin/env node
/**
 * test-admin-approve-reject.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Local validation for the OPS-based Admin Approve & Publish / Reject Request
 * lifecycle (POST /api/admin/pr/approve and POST /api/admin/pr/close).
 *
 * What this tests:
 *   AA-1  Admin can approve a pending_merge Publish Request
 *   AA-2  Approve calls GitHub merge API (PUT /pulls/:n/merge)
 *   AA-3  Approve updates History pr_status → merged
 *   AA-4  Approve writes request-approved Logs with real Admin email
 *   AA-5  Approve returns success, country, prNumber, mergedCount, sha
 *   AA-6  OL cannot approve → 403
 *   AA-7  Manager cannot approve → 403
 *   AR-1  Admin can reject a pending_merge Publish Request
 *   AR-2  Reject calls GitHub close API (PATCH /pulls/:n)
 *   AR-3  Reject updates History pr_status → refused
 *   AR-4  Reject stores rejectionReason
 *   AR-5  Reject writes request-rejected Logs with real Admin email
 *   AR-6  OL cannot reject → 403
 *   AR-7  Manager cannot reject → 403
 *   AR-8  Reject does not restore entries to Buffer
 *   DYN-1 Dynamic country — different country key works without code changes
 *
 * Strategy: same harness pattern as test-phase1-local.js.
 *   - Starts server.js on port 3101 with JWT_SECRET + mock GitHub API.
 *   - Mock GitHub API on port 3100 handles PR GET, merge PUT, close PATCH.
 *   - All state mutations verified against mockState after calls.
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
const TEST_JWT_SECRET = 'admin-approve-reject-test-secret-do-not-use-in-prod';

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
const ADMIN_TOKEN   = mintJwt({ email: 'admin@ibm.com',   role: 'Admin',   iat: now, exp: now + 28800 });
const OL_TOKEN      = mintJwt({ email: 'ol@ibm.com',      role: 'OL',      iat: now, exp: now + 28800 });
const MANAGER_TOKEN = mintJwt({ email: 'manager@ibm.com', role: 'Manager', iat: now, exp: now + 28800 });

const SERVER_PORT  = 3101;
const MOCK_PORT    = 3100;
const TEST_COUNTRY = 'fr';
const TEST_PR      = 55;

// ── Mock GitHub state ──────────────────────────────────────────────────────────
let mockState = {};
// Track which GitHub API calls were made
let _githubCalls = [];

function resetMockState() {
  _githubCalls = [];
  mockState = {
    'data/ops/buffer.json': {
      fr:  {},
      mea: {}
    },
    'data/ops/history.json': {
      fr: [
        {
          id: 'fr_aa_001',
          status: 'validated',
          pr_status: 'pending_merge',
          prNumber: TEST_PR,
          prUrl: `https://github.ibm.com/nlabib/process-finder/pull/${TEST_PR}`,
          branchName: 'ops/fr/20260710-1000',
          type: 'create',
          user: 'ol@ibm.com',
          process: { issue: 'AA-TEST-ISSUE', id: 'fr_aa_001', category: 'Test', machineType: 'All', process: 'Test process' }
        },
        {
          id: 'fr_aa_002',
          status: 'validated',
          pr_status: 'pending_merge',
          prNumber: TEST_PR,
          prUrl: `https://github.ibm.com/nlabib/process-finder/pull/${TEST_PR}`,
          branchName: 'ops/fr/20260710-1000',
          type: 'update',
          user: 'ol@ibm.com',
          process: { issue: 'AA-TEST-ISSUE-2', id: 'fr_aa_002', category: 'Test', machineType: 'All', process: 'Test process 2' }
        }
      ],
      mea: [
        {
          id: 'mea_aa_001',
          status: 'validated',
          pr_status: 'pending_merge',
          prNumber: 77,
          prUrl: 'https://github.ibm.com/nlabib/process-finder/pull/77',
          branchName: 'ops/mea/20260710-1100',
          type: 'create',
          user: 'ol-mea@ibm.com',
          process: { issue: 'MEA-TEST', id: 'mea_aa_001', category: 'Test', machineType: 'All', process: 'MEA test' }
        }
      ]
    },
    'data/ops/pr_schedule.json': {},
    'config/users.json': [
      { email: 'admin@ibm.com',   role: 'Admin',   countries: ['all'] },
      { email: 'ol@ibm.com',      role: 'OL',      countries: ['fr'] },
      { email: 'manager@ibm.com', role: 'Manager', countries: ['fr', 'mea'] },
      { email: 'ol-mea@ibm.com',  role: 'OL',      countries: ['mea'] }
    ],
    'data/logs/activity_logs.json': [],
    _openPRs: [
      {
        number: TEST_PR,
        state: 'open',
        html_url: `https://github.ibm.com/nlabib/process-finder/pull/${TEST_PR}`,
        head: { ref: 'ops/fr/20260710-1000' },
        merged_at: null,
        closed_at: null
      },
      {
        number: 77,
        state: 'open',
        html_url: 'https://github.ibm.com/nlabib/process-finder/pull/77',
        head: { ref: 'ops/mea/20260710-1100' },
        merged_at: null,
        closed_at: null
      }
    ],
    _prDetails: {},
    _commits: []
  };
}
resetMockState();

// ── Mock GitHub API HTTP server ────────────────────────────────────────────────
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

    // ── GET /repos/.../contents/:path ───────────────────────────────────────
    if (m === 'GET' && p.includes('/contents/')) {
      const match = p.match(/\/repos\/[^/]+\/[^/]+\/contents\/(.+)/);
      if (match) {
        const filePath = match[1];
        if (mockState[filePath] !== undefined) {
          return send(200, {
            path: filePath, sha: 'mock-sha-' + filePath.replace(/\//g, '-'),
            content: encodeFileContent(mockState[filePath]) + '\n', encoding: 'base64'
          });
        }
        return send(404, { message: 'Not Found' });
      }
    }

    // ── PUT /repos/.../contents/:path (write) ────────────────────────────────
    if (m === 'PUT' && p.includes('/contents/')) {
      const match = p.match(/\/repos\/[^/]+\/[^/]+\/contents\/(.+)/);
      if (match) {
        const filePath = match[1];
        let parsed;
        try { parsed = JSON.parse(body); } catch { parsed = {}; }
        if (parsed.content) {
          try {
            const decoded = Buffer.from(parsed.content, 'base64').toString('utf8');
            mockState[filePath] = JSON.parse(decoded);
            mockState._commits.push({ path: filePath, message: parsed.message, ts: new Date().toISOString() });
          } catch {}
        }
        return send(200, { content: { path: filePath, sha: 'mock-sha-new' }, commit: { sha: 'abc123' } });
      }
    }

    // ── GET /repos/.../pulls/:number ─────────────────────────────────────────
    const prGetMatch = m === 'GET' && p.match(/\/pulls\/(\d+)$/);
    if (prGetMatch) {
      const num = parseInt(prGetMatch[1], 10);
      const pr  = (mockState._openPRs || []).find(x => x.number === num);
      if (pr) return send(200, pr);
      return send(404, { message: 'Not Found' });
    }

    // ── PUT /repos/.../pulls/:number/merge (squash-merge) ────────────────────
    const mergeMatch = m === 'PUT' && p.match(/\/pulls\/(\d+)\/merge$/);
    if (mergeMatch) {
      const num = parseInt(mergeMatch[1], 10);
      const pr  = (mockState._openPRs || []).find(x => x.number === num);
      if (!pr) return send(404, { message: 'Not Found' });
      if (pr.state !== 'open') return send(405, { message: 'Pull Request is not open' });
      // Mark merged
      pr.state     = 'closed';
      pr.merged_at = new Date().toISOString();
      return send(200, { sha: 'merge-sha-' + num, merged: true, message: 'Pull Request successfully merged' });
    }

    // ── PATCH /repos/.../pulls/:number (close PR) ────────────────────────────
    const patchMatch = m === 'PATCH' && p.match(/\/pulls\/(\d+)$/);
    if (patchMatch) {
      const num = parseInt(patchMatch[1], 10);
      const pr  = (mockState._openPRs || []).find(x => x.number === num);
      if (!pr) return send(404, { message: 'Not Found' });
      pr.state     = 'closed';
      pr.closed_at = new Date().toISOString();
      return send(200, { ...pr });
    }

    // Fallback
    send(404, { message: `Mock: no handler for ${m} ${p}` });
  });
});

// ── HTTP client helper ─────────────────────────────────────────────────────────
function apiCall(method, urlPath, bodyObj, token = ADMIN_TOKEN) {
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
        let json;
        try { json = JSON.parse(data); } catch { json = null; }
        resolve({ status: res.statusCode, ok: res.statusCode >= 200 && res.statusCode < 300, json });
      });
    });
    req.on('error', reject);
    req.end(bodyStr);
  });
}

// ── Wait for port ──────────────────────────────────────────────────────────────
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
  // Start mock server
  await new Promise(r => mockServer.listen(MOCK_PORT, r));

  // Start server under test
  const serverProc = fork(path.join(__dirname, 'server.js'), [], {
    env: {
      ...process.env,
      PORT:             String(SERVER_PORT),
      JWT_SECRET:       TEST_JWT_SECRET,
      GITHUB_TOKEN:     'mock-token',
      GITHUB_OWNER:     'nlabib',
      GITHUB_REPO:      'process-finder',
      GITHUB_BRANCH:    'main',
      GITHUB_API_BASE:  `http://localhost:${MOCK_PORT}`,
      DISABLE_PR_CREATION: 'false',
      EMAIL_SEND_MODE:  'mock'
    },
    silent: true
  });
  serverProc.stdout?.on('data', () => {});
  serverProc.stderr?.on('data', d => {
    const msg = d.toString();
    if (!msg.includes('[server]') && !msg.includes('[OPS')) return;
  });

  try {
    await waitForPort(SERVER_PORT);

    // ════════════════════════════════════════════════════════════════════════
    // TEST AA-1 through AA-5: Admin approve — success path
    // ════════════════════════════════════════════════════════════════════════
    section('Test AA-1..5: Admin Approve & Publish — success');

    resetMockState();
    const rApprove = await apiCall('POST', '/api/admin/pr/approve', { country: TEST_COUNTRY, prNumber: TEST_PR });
    assert('AA-1  POST /api/admin/pr/approve returns 200', rApprove.ok, `status=${rApprove.status} body=${JSON.stringify(rApprove.json)}`);
    assert('AA-2  success flag is true', rApprove.json?.success === true, `json=${JSON.stringify(rApprove.json)}`);
    assert('AA-3  mergedCount = 2 (both pending_merge entries updated)', rApprove.json?.mergedCount === 2, `mergedCount=${rApprove.json?.mergedCount}`);
    assert('AA-4  sha is returned', typeof rApprove.json?.sha === 'string', `sha=${rApprove.json?.sha}`);
    assert('AA-5  country + prNumber echoed in response', rApprove.json?.country === TEST_COUNTRY && rApprove.json?.prNumber === TEST_PR, `json=${JSON.stringify(rApprove.json)}`);

    // Verify History was updated in mock state
    await sleep(400);
    const histAfterApprove = mockState['data/ops/history.json']?.fr || [];
    const mergedEntries = histAfterApprove.filter(h => h.prNumber === TEST_PR && h.pr_status === 'merged');
    assert('AA-3b History entries updated to pr_status=merged', mergedEntries.length === 2, `mergedEntries=${mergedEntries.length}`);
    assert('AA-3c approvedBy set to admin email', mergedEntries.every(h => h.approvedBy === 'admin@ibm.com'), `approvedBy=${mergedEntries.map(h => h.approvedBy)}`);

    // Verify GitHub merge API was called
    const mergeCalls = _githubCalls.filter(c => c.method === 'PUT' && c.path.includes(`/pulls/${TEST_PR}/merge`));
    assert('AA-2b GitHub merge PUT was called', mergeCalls.length >= 1, `mergeCalls=${mergeCalls.length}`);

    // Verify Logs written
    await sleep(300);
    const logsAfterApprove = mockState['data/logs/activity_logs.json'] || [];
    const approveLog = logsAfterApprove.find(l => l.event === 'request-approved' && l.prNumber === TEST_PR);
    assert('AA-4b request-approved Logs event written', !!approveLog, `logs=${JSON.stringify(logsAfterApprove)}`);
    assert('AA-4c Logs event records Admin email (not hardcoded)', approveLog?.by === 'admin@ibm.com', `by=${approveLog?.by}`);
    assert('AA-4d Logs event has country', approveLog?.country === TEST_COUNTRY, `country=${approveLog?.country}`);

    // ════════════════════════════════════════════════════════════════════════
    // TEST AA-6: OL cannot approve → 403
    // ════════════════════════════════════════════════════════════════════════
    section('Test AA-6: OL cannot approve → 403');

    resetMockState();
    const rOLApprove = await apiCall('POST', '/api/admin/pr/approve', { country: TEST_COUNTRY, prNumber: TEST_PR }, OL_TOKEN);
    assert('AA-6  OL → 403', rOLApprove.status === 403, `status=${rOLApprove.status}`);

    // ════════════════════════════════════════════════════════════════════════
    // TEST AA-7: Manager cannot approve → 403
    // ════════════════════════════════════════════════════════════════════════
    section('Test AA-7: Manager cannot approve → 403');

    const rMgrApprove = await apiCall('POST', '/api/admin/pr/approve', { country: TEST_COUNTRY, prNumber: TEST_PR }, MANAGER_TOKEN);
    assert('AA-7  Manager → 403', rMgrApprove.status === 403, `status=${rMgrApprove.status}`);

    // ════════════════════════════════════════════════════════════════════════
    // TEST AR-1 through AR-5: Admin reject — success path
    // ════════════════════════════════════════════════════════════════════════
    section('Test AR-1..5: Admin Reject Request — success');

    resetMockState();
    const reason = 'Incorrect process data — needs revision';
    const rReject = await apiCall('POST', '/api/admin/pr/close', { country: TEST_COUNTRY, prNumber: TEST_PR, reason });
    assert('AR-1  POST /api/admin/pr/close returns 200', rReject.ok, `status=${rReject.status} body=${JSON.stringify(rReject.json)}`);
    assert('AR-2  success flag is true', rReject.json?.success === true, `json=${JSON.stringify(rReject.json)}`);
    assert('AR-3  refusedCount = 2 (both pending_merge entries updated)', rReject.json?.refusedCount === 2, `refusedCount=${rReject.json?.refusedCount}`);
    assert('AR-4  country + prNumber echoed in response', rReject.json?.country === TEST_COUNTRY && rReject.json?.prNumber === TEST_PR, `json=${JSON.stringify(rReject.json)}`);

    // Verify GitHub close PATCH was called
    const closeCalls = _githubCalls.filter(c => c.method === 'PATCH' && c.path.includes(`/pulls/${TEST_PR}`));
    assert('AR-2b GitHub close PATCH was called', closeCalls.length >= 1, `closeCalls=${closeCalls.length}`);

    // Verify History was updated
    await sleep(400);
    const histAfterReject = mockState['data/ops/history.json']?.fr || [];
    const refusedEntries = histAfterReject.filter(h => h.prNumber === TEST_PR && h.pr_status === 'refused');
    assert('AR-3b History entries updated to pr_status=refused', refusedEntries.length === 2, `refusedEntries=${refusedEntries.length}`);
    assert('AR-3c rejectedBy set to admin email', refusedEntries.every(h => h.rejectedBy === 'admin@ibm.com'), `rejectedBy=${refusedEntries.map(h => h.rejectedBy)}`);
    assert('AR-4b rejectionReason stored', refusedEntries.every(h => h.rejectionReason === reason), `reasons=${refusedEntries.map(h => h.rejectionReason)}`);

    // Verify Logs written
    await sleep(300);
    const logsAfterReject = mockState['data/logs/activity_logs.json'] || [];
    const rejectLog = logsAfterReject.find(l => l.event === 'request-rejected' && l.prNumber === TEST_PR);
    assert('AR-5  request-rejected Logs event written', !!rejectLog, `logs=${JSON.stringify(logsAfterReject)}`);
    assert('AR-5b Logs event records Admin email (not hardcoded)', rejectLog?.by === 'admin@ibm.com', `by=${rejectLog?.by}`);
    assert('AR-5c Logs event has country', rejectLog?.country === TEST_COUNTRY, `country=${rejectLog?.country}`);
    assert('AR-5d Logs event has rejectionReason', rejectLog?.rejectionReason === reason, `reason=${rejectLog?.rejectionReason}`);

    // Verify Buffer was NOT modified (entries already in History, Buffer stays clean)
    const bufAfterReject = mockState['data/ops/buffer.json']?.fr || {};
    const bufEntries = Object.values(bufAfterReject).flat();
    assert('AR-8  Buffer not modified — refused entries not restored to Buffer', bufEntries.length === 0, `bufEntries=${bufEntries.length}`);

    // ════════════════════════════════════════════════════════════════════════
    // TEST AR-6: OL cannot reject → 403
    // ════════════════════════════════════════════════════════════════════════
    section('Test AR-6: OL cannot reject → 403');

    resetMockState();
    const rOLReject = await apiCall('POST', '/api/admin/pr/close', { country: TEST_COUNTRY, prNumber: TEST_PR, reason: 'test' }, OL_TOKEN);
    assert('AR-6  OL → 403', rOLReject.status === 403, `status=${rOLReject.status}`);

    // ════════════════════════════════════════════════════════════════════════
    // TEST AR-7: Manager cannot reject → 403
    // ════════════════════════════════════════════════════════════════════════
    section('Test AR-7: Manager cannot reject → 403');

    const rMgrReject = await apiCall('POST', '/api/admin/pr/close', { country: TEST_COUNTRY, prNumber: TEST_PR, reason: 'test' }, MANAGER_TOKEN);
    assert('AR-7  Manager → 403', rMgrReject.status === 403, `status=${rMgrReject.status}`);

    // ════════════════════════════════════════════════════════════════════════
    // TEST DYN-1: Dynamic country — MEA works without code changes
    // ════════════════════════════════════════════════════════════════════════
    section('Test DYN-1: Dynamic country (mea) — approve works');

    resetMockState();
    const rMEAApprove = await apiCall('POST', '/api/admin/pr/approve', { country: 'mea', prNumber: 77 });
    assert('DYN-1  Admin can approve PR #77 for mea', rMEAApprove.ok, `status=${rMEAApprove.status} body=${JSON.stringify(rMEAApprove.json)}`);
    assert('DYN-1b mergedCount = 1 for mea', rMEAApprove.json?.mergedCount === 1, `mergedCount=${rMEAApprove.json?.mergedCount}`);

    await sleep(400);
    const meaHistAfter = mockState['data/ops/history.json']?.mea || [];
    const meaMerged = meaHistAfter.filter(h => h.pr_status === 'merged');
    assert('DYN-1c mea History updated to merged', meaMerged.length === 1, `meaMerged=${meaMerged.length}`);

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
