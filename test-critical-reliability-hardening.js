#!/usr/bin/env node
/**
 * test-critical-reliability-hardening.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Regression tests for the 2026-08-20 incident hardening PR.
 *
 * Covers two independent defects fixed in that PR:
 *
 *   (A) config/users.json read failures must never be misreported as
 *       "unauthorized". Deterministic contract (see _readUsersConfigStrict
 *       in server.js):
 *         GitHub 401/403 (non-retryable)        -> 502 AUTH_CONFIG_UNAVAILABLE
 *         GitHub timeout/5xx, retries exhausted  -> 503 AUTH_CONFIG_UNAVAILABLE
 *         config/users.json missing (404)        -> 500 CONFIG_MISSING
 *         invalid JSON / non-array JSON            -> 500 CONFIG_INVALID
 *         successful, valid array                 -> existing behavior unchanged
 *       Applied to: GET /api/config/users, POST /send-otp,
 *                   POST /api/auth/session, GET /api/ops/users.
 *
 *   (B) commitJsonToMainBranch() return values must be checked at every
 *       Buffer / edit-lock write call site so a failed GitHub write never
 *       produces {success:true}.
 *       Applied to: POST /api/ops/buffer, PUT /api/ops/buffer,
 *                   PATCH /api/ops/buffer/edit-lock (release + acquire),
 *                   PATCH /api/ops/process/edit-lock (release + acquire),
 *                   POST /api/ops/cancel.
 *
 * Strategy: forks server.js as a child process, points GITHUB_API_BASE at a
 * local mock GitHub API server whose config/users.json GET response and
 * Buffer/lock-file PUT response are individually controllable per test via
 * queued mock responses.
 *
 * Safe: no real GitHub calls, no real commits, no production data touched.
 * Run with:  node test-critical-reliability-hardening.js
 * Exit 0 = all passed. Non-zero = at least one failed.
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
    console.log(`  \u2705 ${label}`);
    _pass++;
  } else {
    const msg = `${label}${extra ? ' \u2014 ' + extra : ''}`;
    console.error(`  \u274c ${msg}`);
    _failures.push(msg);
    _fail++;
  }
}

function section(title) {
  console.log(`\n\u2500\u2500 ${title} ${'\u2500'.repeat(Math.max(0, 60 - title.length))}`);
}

// ── JWT helpers (mint tokens locally with the same shared secret injected
// into the forked server) ───────────────────────────────────────────────────
const TEST_JWT_SECRET = 'critical-reliability-test-secret-do-not-use-in-prod';

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

const nowSec = Math.floor(Date.now() / 1000);
const ADMIN_TOKEN = mintJwt({ email: 'admin@ibm.com', role: 'Admin', globalWrite: false, iat: nowSec, exp: nowSec + 28800 });

// otpToken minted directly (bypasses /send-otp + /verify-otp), same pattern
// used for session tokens elsewhere in the test suite.
function mintOtpToken(email) {
  return mintJwt({
    type: 'otp-verified', email,
    jti: crypto.randomBytes(8).toString('hex'),
    iat: nowSec, exp: nowSec + 300
  });
}

const SERVER_PORT      = 3111;
const MOCK_PORT        = 3110;
const REGISTERED_EMAIL = 'admin@ibm.com';
const VALID_USERS = [
  { email: 'admin@ibm.com', name: 'Admin', role: 'Admin', countries: ['all'] },
  { email: 'ol-a@ibm.com',  name: 'OL A',  role: 'OL',    countries: ['fr'] }
];

const VALID_BUFFER = {
  fr: {
    'ol-a@ibm.com': [
      {
        id: 'fr_test_pending', type: 'create', user: 'ol-a@ibm.com', status: 'pending',
        process: { id: 'fr_test_pending', issue: 'TEST-ISSUE', category: 'Contract', machineType: '', process: 'content' },
        createdAt: new Date().toISOString()
      }
    ]
  }
};

const VALID_PROCESS_LOCKS = {};

// ── Mock GitHub API server ──────────────────────────────────────────────────
// Each test controls exactly what the mock returns for:
//   - GET .../contents/config%2Fusers.json     (queued response, see below)
//   - PUT .../contents/data%2Fops%2Fbuffer.json or process_edit_locks.json
// All other paths return sane defaults so unrelated code paths
// (country-scope checks, schedule/history reads, etc.) don't block the test.

let _usersJsonResponse = null;   // { status, body } | { status, rawBody } — controls GET config/users.json
let _writeResponse     = null;   // { status } — controls PUT for buffer.json / process_edit_locks.json
let _writeCallCount    = 0;
let _activityLogWrites = [];     // captures any POST-like writes to data/logs/activity_logs.json

function encodeFileContent(obj) {
  const str = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
  return Buffer.from(str).toString('base64');
}

function setUsersJsonResponse(resp) { _usersJsonResponse = resp; }
function setWriteResponse(resp)     { _writeResponse = resp; }
function resetMock() {
  _usersJsonResponse = { status: 200, body: VALID_USERS };
  _writeResponse     = { status: 200 };
  _writeCallCount     = 0;
  _activityLogWrites  = [];
}
resetMock();

const _defaultState = {
  'data/ops/buffer.json':          () => JSON.parse(JSON.stringify(VALID_BUFFER)),
  'data/ops/history.json':         () => ({}),
  'data/ops/pr_schedule.json':     () => ({}),
  'data/ops/process_edit_locks.json': () => JSON.parse(JSON.stringify(VALID_PROCESS_LOCKS)),
  'config/countries.json':         () => ([{ key: 'fr', name: 'France', code: 'FR' }]),
  'data/logs/activity_logs.json':  () => ([]),
  'data/ops/admin-audit.json':     () => ([])
};

const mockServer = http.createServer((req, res) => {
  let body = '';
  req.on('data', c => { body += c; });
  req.on('end', () => {
    const send = (status, obj) => {
      const data = typeof obj === 'string' ? obj : JSON.stringify(obj);
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

        if (filePath === 'config/users.json') {
          const r = _usersJsonResponse;
          if (r.status === 404) return send(404, { message: 'Not Found' });
          if (r.status >= 500 && r.status < 600) return send(r.status, { message: 'Internal Server Error' });
          if (r.status !== 200) return send(r.status, { message: r.message || 'Forbidden' });
          // 200 — either a well-formed content envelope, or a raw malformed body
          if (r.rawBody !== undefined) {
            return send(200, { path: filePath, sha: 'sha-users', content: Buffer.from(r.rawBody).toString('base64'), encoding: 'base64' });
          }
          return send(200, { path: filePath, sha: 'sha-users', content: encodeFileContent(r.body), encoding: 'base64' });
        }

        if (_defaultState[filePath]) {
          return send(200, {
            path: filePath, sha: 'sha-' + filePath.replace(/\//g, '-'),
            content: encodeFileContent(_defaultState[filePath]()), encoding: 'base64'
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
        _writeCallCount++;
        if (filePath === 'data/logs/activity_logs.json') {
          let parsed; try { parsed = JSON.parse(body); } catch { parsed = {}; }
          _activityLogWrites.push(parsed);
        }
        const r = _writeResponse;
        if (r.status !== 200 && r.status !== 201) {
          return send(r.status, { message: r.message || 'Forbidden' });
        }
        return send(200, { content: { path: filePath, sha: 'new-sha' }, commit: { sha: 'abc123' } });
      }
    }

    // GET /repos/.../git/refs/heads/:branch  (needed by commitJsonToMainBranch elsewhere)
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
    const bodyStr = bodyObj !== undefined ? JSON.stringify(bodyObj) : '';
    const opts = {
      hostname: 'localhost',
      port: SERVER_PORT,
      path: urlPath,
      method,
      headers: {
        'Content-Type':   'application/json',
        'Content-Length': Buffer.byteLength(bodyStr),
        ...(token ? { 'Authorization': `Bearer ${token}` } : {})
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

// ── Main ───────────────────────────────────────────────────────────────────────
(async () => {
  await new Promise(r => mockServer.listen(MOCK_PORT, '127.0.0.1', r));
  console.log(`[mock] GitHub API mock listening on port ${MOCK_PORT}`);

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
  serverProc.stdout?.on('data', () => {});
  serverProc.stderr?.on('data', () => {});

  try {
    await waitForPort(SERVER_PORT);
    console.log(`[server] listening on port ${SERVER_PORT}`);

    // ═══════════════════════════════════════════════════════════════════════
    // GROUP A — GET /api/config/users strict-read contract
    // ═══════════════════════════════════════════════════════════════════════

    section('A1. GET /api/config/users — GitHub 403 -> 502 AUTH_CONFIG_UNAVAILABLE, never []');
    {
      resetMock();
      setUsersJsonResponse({ status: 403, message: 'Bad credentials' });
      const r = await apiCall('GET', '/api/config/users', undefined, null);
      assert('status is 502', r.status === 502, `got ${r.status}`);
      assert('error code is AUTH_CONFIG_UNAVAILABLE', r.json?.error === 'AUTH_CONFIG_UNAVAILABLE', JSON.stringify(r.json));
      assert('response is not an empty array', !Array.isArray(r.json), JSON.stringify(r.json));
    }

    section('A2. GET /api/config/users — GitHub 401 -> 502 AUTH_CONFIG_UNAVAILABLE');
    {
      resetMock();
      setUsersJsonResponse({ status: 401, message: 'Bad credentials' });
      const r = await apiCall('GET', '/api/config/users', undefined, null);
      assert('status is 502', r.status === 502, `got ${r.status}`);
      assert('error code is AUTH_CONFIG_UNAVAILABLE', r.json?.error === 'AUTH_CONFIG_UNAVAILABLE', JSON.stringify(r.json));
    }

    section('A3. GET /api/config/users — exhausted 503 retries -> 503 AUTH_CONFIG_UNAVAILABLE, never []');
    {
      resetMock();
      // fetchGitHubJsonStrict retries transient 502/503/504 up to 3 attempts;
      // the mock has no per-attempt queue, so returning 503 for every GET
      // simulates "still failing after retries".
      setUsersJsonResponse({ status: 503, message: 'Service Unavailable' });
      const r = await apiCall('GET', '/api/config/users', undefined, null);
      assert('status is 503', r.status === 503, `got ${r.status}`);
      assert('error code is AUTH_CONFIG_UNAVAILABLE', r.json?.error === 'AUTH_CONFIG_UNAVAILABLE', JSON.stringify(r.json));
      assert('response is not an empty array', !Array.isArray(r.json), JSON.stringify(r.json));
    }

    section('A4. GET /api/config/users — GitHub 404 -> 500 CONFIG_MISSING');
    {
      resetMock();
      setUsersJsonResponse({ status: 404 });
      const r = await apiCall('GET', '/api/config/users', undefined, null);
      assert('status is 500', r.status === 500, `got ${r.status}`);
      assert('error code is CONFIG_MISSING', r.json?.error === 'CONFIG_MISSING', JSON.stringify(r.json));
    }

    section('A5. GET /api/config/users — invalid JSON body -> 500 CONFIG_INVALID');
    {
      resetMock();
      setUsersJsonResponse({ status: 200, rawBody: '{not valid json' });
      const r = await apiCall('GET', '/api/config/users', undefined, null);
      assert('status is 500', r.status === 500, `got ${r.status}`);
      assert('error code is CONFIG_INVALID', r.json?.error === 'CONFIG_INVALID', JSON.stringify(r.json));
    }

    section('A6. GET /api/config/users — valid but non-array JSON -> 500 CONFIG_INVALID');
    {
      resetMock();
      setUsersJsonResponse({ status: 200, body: { not: 'an array' } });
      const r = await apiCall('GET', '/api/config/users', undefined, null);
      assert('status is 500', r.status === 500, `got ${r.status}`);
      assert('error code is CONFIG_INVALID', r.json?.error === 'CONFIG_INVALID', JSON.stringify(r.json));
    }

    section('A7. GET /api/config/users — valid array -> unchanged success response');
    {
      resetMock();
      setUsersJsonResponse({ status: 200, body: VALID_USERS });
      const r = await apiCall('GET', '/api/config/users', undefined, null);
      assert('status is 200', r.status === 200, `got ${r.status}`);
      assert('response is an array', Array.isArray(r.json), JSON.stringify(r.json));
      assert('countries stripped from public response', r.json.every(u => !('countries' in u)), JSON.stringify(r.json));
      assert('contains admin@ibm.com', r.json.some(u => u.email === 'admin@ibm.com'), JSON.stringify(r.json));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // GROUP B — GET /api/ops/users strict-read contract (authenticated)
    // ═══════════════════════════════════════════════════════════════════════

    section('B1. GET /api/ops/users — GitHub 403 -> 502 AUTH_CONFIG_UNAVAILABLE, never []');
    {
      resetMock();
      setUsersJsonResponse({ status: 403, message: 'Bad credentials' });
      const r = await apiCall('GET', '/api/ops/users', undefined, ADMIN_TOKEN);
      assert('status is 502', r.status === 502, `got ${r.status}`);
      assert('error code is AUTH_CONFIG_UNAVAILABLE', r.json?.error === 'AUTH_CONFIG_UNAVAILABLE', JSON.stringify(r.json));
      assert('response is not an empty array', !Array.isArray(r.json), JSON.stringify(r.json));
    }

    section('B2. GET /api/ops/users — unauthenticated request -> 401 (unchanged)');
    {
      resetMock();
      const r = await apiCall('GET', '/api/ops/users', undefined, null);
      assert('status is 401', r.status === 401, `got ${r.status}`);
    }

    section('B3. GET /api/ops/users — valid array, authenticated Admin -> unchanged success (full records)');
    {
      resetMock();
      setUsersJsonResponse({ status: 200, body: VALID_USERS });
      const r = await apiCall('GET', '/api/ops/users', undefined, ADMIN_TOKEN);
      assert('status is 200', r.status === 200, `got ${r.status}`);
      assert('response is full user records (countries present)', r.json.every(u => 'countries' in u), JSON.stringify(r.json));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // GROUP C — POST /send-otp strict-read contract
    // ═══════════════════════════════════════════════════════════════════════

    section('C1. POST /send-otp — GitHub 403 -> 502 AUTH_CONFIG_UNAVAILABLE, never "Email not authorized"');
    {
      resetMock();
      setUsersJsonResponse({ status: 403, message: 'Bad credentials' });
      const r = await apiCall('POST', '/send-otp', { email: REGISTERED_EMAIL }, null);
      assert('status is 502', r.status === 502, `got ${r.status}`);
      assert('error code is AUTH_CONFIG_UNAVAILABLE', r.json?.error === 'AUTH_CONFIG_UNAVAILABLE', JSON.stringify(r.json));
      assert('message is not "Email not authorized"', r.json?.error !== 'Email not authorized', JSON.stringify(r.json));
    }

    section('C2. POST /send-otp — exhausted timeout/5xx -> 503 AUTH_CONFIG_UNAVAILABLE');
    {
      resetMock();
      setUsersJsonResponse({ status: 503, message: 'Service Unavailable' });
      const r = await apiCall('POST', '/send-otp', { email: REGISTERED_EMAIL }, null);
      assert('status is 503', r.status === 503, `got ${r.status}`);
      assert('error code is AUTH_CONFIG_UNAVAILABLE', r.json?.error === 'AUTH_CONFIG_UNAVAILABLE', JSON.stringify(r.json));
    }

    section('C3. POST /send-otp — 404 -> 500 CONFIG_MISSING');
    {
      resetMock();
      setUsersJsonResponse({ status: 404 });
      const r = await apiCall('POST', '/send-otp', { email: REGISTERED_EMAIL }, null);
      assert('status is 500', r.status === 500, `got ${r.status}`);
      assert('error code is CONFIG_MISSING', r.json?.error === 'CONFIG_MISSING', JSON.stringify(r.json));
    }

    section('C4. POST /send-otp — invalid JSON -> 500 CONFIG_INVALID');
    {
      resetMock();
      setUsersJsonResponse({ status: 200, rawBody: 'not json at all' });
      const r = await apiCall('POST', '/send-otp', { email: REGISTERED_EMAIL }, null);
      assert('status is 500', r.status === 500, `got ${r.status}`);
      assert('error code is CONFIG_INVALID', r.json?.error === 'CONFIG_INVALID', JSON.stringify(r.json));
    }

    section('C5. POST /send-otp — valid array, unregistered email -> unchanged 400 "Email not authorized"');
    {
      resetMock();
      setUsersJsonResponse({ status: 200, body: VALID_USERS });
      const r = await apiCall('POST', '/send-otp', { email: 'not-a-user@ibm.com' }, null);
      assert('status is 400', r.status === 400, `got ${r.status}`);
      assert('error is "Email not authorized"', r.json?.error === 'Email not authorized', JSON.stringify(r.json));
    }

    section('C6. POST /send-otp — valid array, registered email -> unchanged 200 success (mock email mode)');
    {
      resetMock();
      setUsersJsonResponse({ status: 200, body: VALID_USERS });
      const r = await apiCall('POST', '/send-otp', { email: REGISTERED_EMAIL }, null);
      assert('status is 200', r.status === 200, `got ${r.status}`);
      assert('success is true', r.json?.success === true, JSON.stringify(r.json));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // GROUP D — POST /api/auth/session strict-read contract
    // ═══════════════════════════════════════════════════════════════════════

    section('D1. POST /api/auth/session — GitHub 403 -> 502 AUTH_CONFIG_UNAVAILABLE, never "Unauthorized"');
    {
      resetMock();
      setUsersJsonResponse({ status: 403, message: 'Bad credentials' });
      const otpToken = mintOtpToken(REGISTERED_EMAIL);
      const r = await apiCall('POST', '/api/auth/session', { email: REGISTERED_EMAIL, otpToken }, null);
      assert('status is 502', r.status === 502, `got ${r.status}`);
      assert('error code is AUTH_CONFIG_UNAVAILABLE', r.json?.error === 'AUTH_CONFIG_UNAVAILABLE', JSON.stringify(r.json));
      assert('message is not "Unauthorized"', r.json?.error !== 'Unauthorized', JSON.stringify(r.json));
    }

    section('D2. POST /api/auth/session — exhausted 5xx -> 503 AUTH_CONFIG_UNAVAILABLE');
    {
      resetMock();
      setUsersJsonResponse({ status: 502, message: 'Bad Gateway' });
      const otpToken = mintOtpToken(REGISTERED_EMAIL);
      const r = await apiCall('POST', '/api/auth/session', { email: REGISTERED_EMAIL, otpToken }, null);
      assert('status is 503', r.status === 503, `got ${r.status}`);
      assert('error code is AUTH_CONFIG_UNAVAILABLE', r.json?.error === 'AUTH_CONFIG_UNAVAILABLE', JSON.stringify(r.json));
    }

    section('D3. POST /api/auth/session — 404 -> 500 CONFIG_MISSING');
    {
      resetMock();
      setUsersJsonResponse({ status: 404 });
      const otpToken = mintOtpToken(REGISTERED_EMAIL);
      const r = await apiCall('POST', '/api/auth/session', { email: REGISTERED_EMAIL, otpToken }, null);
      assert('status is 500', r.status === 500, `got ${r.status}`);
      assert('error code is CONFIG_MISSING', r.json?.error === 'CONFIG_MISSING', JSON.stringify(r.json));
    }

    section('D4. POST /api/auth/session — invalid JSON -> 500 CONFIG_INVALID');
    {
      resetMock();
      setUsersJsonResponse({ status: 200, rawBody: '{broken' });
      const otpToken = mintOtpToken(REGISTERED_EMAIL);
      const r = await apiCall('POST', '/api/auth/session', { email: REGISTERED_EMAIL, otpToken }, null);
      assert('status is 500', r.status === 500, `got ${r.status}`);
      assert('error code is CONFIG_INVALID', r.json?.error === 'CONFIG_INVALID', JSON.stringify(r.json));
    }

    section('D5. POST /api/auth/session — valid array, unauthorized email -> unchanged 403 "Unauthorized"');
    {
      resetMock();
      setUsersJsonResponse({ status: 200, body: VALID_USERS });
      const otpToken = mintOtpToken('not-a-user@ibm.com');
      const r = await apiCall('POST', '/api/auth/session', { email: 'not-a-user@ibm.com', otpToken }, null);
      assert('status is 403', r.status === 403, `got ${r.status}`);
      assert('error is "Unauthorized"', r.json?.error === 'Unauthorized', JSON.stringify(r.json));
    }

    section('D6. POST /api/auth/session — valid array, authorized email -> unchanged 200 session issued');
    {
      resetMock();
      setUsersJsonResponse({ status: 200, body: VALID_USERS });
      const otpToken = mintOtpToken(REGISTERED_EMAIL);
      const r = await apiCall('POST', '/api/auth/session', { email: REGISTERED_EMAIL, otpToken }, null);
      assert('status is 200', r.status === 200, `got ${r.status}`);
      assert('success is true', r.json?.success === true, JSON.stringify(r.json));
      assert('role is Admin', r.json?.role === 'Admin', JSON.stringify(r.json));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // GROUP E — Buffer / edit-lock write-failure guards (7 call sites)
    // Each site must: (1) return non-2xx on a failed commit, (2) never
    // return {success:true}, (3) leave activity-log writes uncalled when the
    // primary write failed (no downstream success audit for a failed write).
    // ═══════════════════════════════════════════════════════════════════════

    section('E1. POST /api/ops/buffer — failed commit -> 502, never {success:true}');
    {
      resetMock();
      setWriteResponse({ status: 403, message: 'Forbidden' });
      const r = await apiCall('POST', '/api/ops/buffer', {
        country: 'fr', type: 'create',
        process: { category: 'Contract', issue: 'NEW-ISSUE', process: 'content', machineType: '' }
      }, ADMIN_TOKEN);
      assert('status is not 2xx', !r.ok, `got ${r.status}`);
      assert('status is 502', r.status === 502, `got ${r.status}`);
      assert('response is not {success:true}', r.json?.success !== true, JSON.stringify(r.json));
    }

    section('E2. POST /api/ops/buffer — successful commit -> unchanged {success:true, entry}');
    {
      resetMock();
      setWriteResponse({ status: 200 });
      const r = await apiCall('POST', '/api/ops/buffer', {
        country: 'fr', type: 'create',
        process: { category: 'Contract', issue: 'NEW-ISSUE-2', process: 'content', machineType: '' }
      }, ADMIN_TOKEN);
      assert('status is 200', r.status === 200, `got ${r.status}`);
      assert('response is {success:true}', r.json?.success === true, JSON.stringify(r.json));
      assert('entry is present', !!r.json?.entry, JSON.stringify(r.json));
    }

    section('E3. PUT /api/ops/buffer — failed commit -> 502, never {success:true}');
    {
      resetMock();
      setWriteResponse({ status: 403, message: 'Forbidden' });
      const buf = { fr: { 'ol-a@ibm.com': [
        { ...VALID_BUFFER.fr['ol-a@ibm.com'][0], process: { ...VALID_BUFFER.fr['ol-a@ibm.com'][0].process, issue: 'EDITED-ISSUE' } }
      ] } };
      const r = await apiCall('PUT', '/api/ops/buffer', { buffer: buf, editEntryId: 'fr_test_pending' }, ADMIN_TOKEN);
      assert('status is not 2xx', !r.ok, `got ${r.status}`);
      assert('status is 502', r.status === 502, `got ${r.status}`);
      assert('response is not {success:true}', r.json?.success !== true, JSON.stringify(r.json));
    }

    section('E4. PUT /api/ops/buffer — successful commit -> unchanged {success:true}');
    {
      resetMock();
      setWriteResponse({ status: 200 });
      const buf = { fr: { 'ol-a@ibm.com': [
        { ...VALID_BUFFER.fr['ol-a@ibm.com'][0], process: { ...VALID_BUFFER.fr['ol-a@ibm.com'][0].process, issue: 'EDITED-ISSUE-2' } }
      ] } };
      const r = await apiCall('PUT', '/api/ops/buffer', { buffer: buf, editEntryId: 'fr_test_pending' }, ADMIN_TOKEN);
      assert('status is 200', r.status === 200, `got ${r.status}`);
      assert('response is {success:true}', r.json?.success === true, JSON.stringify(r.json));
    }

    section('E5. PATCH /api/ops/buffer/edit-lock (acquire) — failed commit -> 502, never {success:true}');
    {
      resetMock();
      setWriteResponse({ status: 403, message: 'Forbidden' });
      const r = await apiCall('PATCH', '/api/ops/buffer/edit-lock', {
        country: 'fr', user: 'ol-a@ibm.com', index: 0, action: 'acquire'
      }, ADMIN_TOKEN);
      assert('status is not 2xx', !r.ok, `got ${r.status}`);
      assert('status is 502', r.status === 502, `got ${r.status}`);
      assert('response is not {success:true}', r.json?.success !== true, JSON.stringify(r.json));
    }

    section('E6. PATCH /api/ops/buffer/edit-lock (release) — failed commit -> 502, never {success:true}');
    {
      resetMock();
      setWriteResponse({ status: 403, message: 'Forbidden' });
      const r = await apiCall('PATCH', '/api/ops/buffer/edit-lock', {
        country: 'fr', user: 'ol-a@ibm.com', index: 0, action: 'release'
      }, ADMIN_TOKEN);
      assert('status is not 2xx', !r.ok, `got ${r.status}`);
      assert('status is 502', r.status === 502, `got ${r.status}`);
      assert('response is not {success:true}', r.json?.success !== true, JSON.stringify(r.json));
    }

    section('E7. PATCH /api/ops/buffer/edit-lock (acquire) — successful commit -> unchanged {success:true}');
    {
      resetMock();
      setWriteResponse({ status: 200 });
      const r = await apiCall('PATCH', '/api/ops/buffer/edit-lock', {
        country: 'fr', user: 'ol-a@ibm.com', index: 0, action: 'acquire'
      }, ADMIN_TOKEN);
      assert('status is 200', r.status === 200, `got ${r.status}`);
      assert('response is {success:true}', r.json?.success === true, JSON.stringify(r.json));
    }

    section('E8. PATCH /api/ops/process/edit-lock (acquire) — failed commit -> 502, never {success:true}');
    {
      resetMock();
      setWriteResponse({ status: 403, message: 'Forbidden' });
      const r = await apiCall('PATCH', '/api/ops/process/edit-lock', {
        country: 'fr', processId: 'fr_test_process', action: 'acquire'
      }, ADMIN_TOKEN);
      assert('status is not 2xx', !r.ok, `got ${r.status}`);
      assert('status is 502', r.status === 502, `got ${r.status}`);
      assert('response is not {success:true}', r.json?.success !== true, JSON.stringify(r.json));
    }

    section('E9. PATCH /api/ops/process/edit-lock (release) — failed commit -> 502, never {success:true}');
    {
      resetMock();
      setWriteResponse({ status: 200 });
      // Acquire first so a release has something to release.
      await apiCall('PATCH', '/api/ops/process/edit-lock', { country: 'fr', processId: 'fr_test_process', action: 'acquire' }, ADMIN_TOKEN);
      setWriteResponse({ status: 403, message: 'Forbidden' });
      const r = await apiCall('PATCH', '/api/ops/process/edit-lock', {
        country: 'fr', processId: 'fr_test_process', action: 'release'
      }, ADMIN_TOKEN);
      assert('status is not 2xx', !r.ok, `got ${r.status}`);
      assert('status is 502', r.status === 502, `got ${r.status}`);
      assert('response is not {success:true}', r.json?.success !== true, JSON.stringify(r.json));
    }

    section('E10. PATCH /api/ops/process/edit-lock (acquire) — successful commit -> unchanged {success:true}');
    {
      resetMock();
      setWriteResponse({ status: 200 });
      const r = await apiCall('PATCH', '/api/ops/process/edit-lock', {
        country: 'fr', processId: 'fr_test_process_2', action: 'acquire'
      }, ADMIN_TOKEN);
      assert('status is 200', r.status === 200, `got ${r.status}`);
      assert('response is {success:true}', r.json?.success === true, JSON.stringify(r.json));
    }

    section('E11. POST /api/ops/cancel — failed commit -> 502, never {success:true}, no downstream audit');
    {
      resetMock();
      setWriteResponse({ status: 403, message: 'Forbidden' });
      const r = await apiCall('POST', '/api/ops/cancel', {
        country: 'fr', user: 'ol-a@ibm.com', index: 0
      }, ADMIN_TOKEN);
      assert('status is not 2xx', !r.ok, `got ${r.status}`);
      assert('status is 502', r.status === 502, `got ${r.status}`);
      assert('response is not {success:true}', r.json?.success !== true, JSON.stringify(r.json));
      assert('no activity-log write occurred for the failed cancel', _activityLogWrites.length === 0, JSON.stringify(_activityLogWrites));
    }

    section('E12. POST /api/ops/cancel — successful commit -> unchanged {success:true, entry}');
    {
      resetMock();
      setWriteResponse({ status: 200 });
      const r = await apiCall('POST', '/api/ops/cancel', {
        country: 'fr', user: 'ol-a@ibm.com', index: 0
      }, ADMIN_TOKEN);
      assert('status is 200', r.status === 200, `got ${r.status}`);
      assert('response is {success:true}', r.json?.success === true, JSON.stringify(r.json));
      assert('entry is present', !!r.json?.entry, JSON.stringify(r.json));
    }

    // ── Summary ────────────────────────────────────────────────────────────────
    console.log(`\n${'='.repeat(70)}`);
    console.log(`RESULTS: ${_pass} passed, ${_fail} failed`);
    if (_failures.length) {
      console.log('\nFailures:');
      _failures.forEach(f => console.log(`  - ${f}`));
    }
    console.log('='.repeat(70));

  } finally {
    serverProc.kill();
    mockServer.close();
  }

  process.exit(_fail > 0 ? 1 : 0);
})().catch(err => {
  console.error('FATAL:', err);
  process.exit(1);
});
