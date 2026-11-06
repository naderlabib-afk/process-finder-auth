#!/usr/bin/env node
/**
 * test-approval-media-history-e2e.js
 *
 * End-to-end regression for the post-merge media lifecycle of
 * POST /api/admin/pr/approve.
 *
 * Defect covered: after media promotion the route re-reads History and located
 * each approved record with `findIndex(h => h.id === updated.id)` (process ID
 * alone). History legitimately repeats process IDs across separate Publish
 * Requests, so the lookup overwrote OLDER merged records of other PRs instead of
 * the current PR's records.
 *
 * Strategy (same harness pattern as test-admin-approve-reject.js):
 *   - Mock GitHub API (contents GET/PUT/DELETE, git blobs, pulls) on MOCK_PORT.
 *   - server.js forked on SERVER_PORT against the mock.
 *   - The real approve route is exercised; all state is verified in mockState.
 *   - PF_SERVER_PATH may point at another copy of server.js (used to prove these
 *     tests FAIL against the pre-fix implementation). NODE_PATH must then point
 *     at this repo's node_modules.
 *
 * Exit 0 = all passed. Exit 1 = at least one failure.
 */
'use strict';

const http     = require('http');
const net      = require('net');
const path     = require('path');
const crypto   = require('crypto');
const { fork } = require('child_process');

let _pass = 0, _fail = 0;
const _failures = [];
function assert(label, cond, extra = '') {
  if (cond) { console.log(`  ✅ ${label}`); _pass++; }
  else { const m = `${label}${extra ? ' — ' + extra : ''}`; console.error(`  ❌ ${m}`); _failures.push(m); _fail++; }
}
const section = t => console.log(`\n── ${t} ${'─'.repeat(Math.max(0, 70 - t.length))}`);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const clone = o => JSON.parse(JSON.stringify(o));

// ── JWT ────────────────────────────────────────────────────────────────────────
const SECRET = 'approval-media-history-e2e-secret-do-not-use-in-prod';
const b64u = b => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
function jwt(payload) {
  const h = b64u(JSON.stringify({ alg: 'HS256', typ: 'JWT' })), p = b64u(JSON.stringify(payload));
  return `${h}.${p}.${b64u(crypto.createHmac('sha256', SECRET).update(`${h}.${p}`).digest())}`;
}
const nowS = Math.floor(Date.now() / 1000);
const ADMIN = jwt({ email: 'admin@ibm.com', role: 'Admin', iat: nowS, exp: nowS + 28800 });

const MOCK_PORT = 3110, SERVER_PORT = 3111;
const SERVER_PATH = process.env.PF_SERVER_PATH || path.join(__dirname, 'server.js');

// ── Synthetic fixture (no production content) ──────────────────────────────────
const ID_A = 'mea_tgt_a', ID_B = 'mea_tgt_b';
const UUID_A = '11111111-2222-4333-8444-555555555555.webp';
const STAGED_A = `assets/process-media/_staged/mea/${ID_A}/${UUID_A}`;
const FINAL_A  = `assets/process-media/mea/${ID_A}/${UUID_A}`;
const imgHtml = src => `<p>text</p><img src="${src}" alt="x" data-width="600">`;
const PR = 900, OLD_PR_A = 897, OLD_PR_B = 863;
const rec = (id, pr, st, extra = {}) => ({
  id, type: 'update', user: 'ol@ibm.com', status: 'validated', pr_status: st, prNumber: pr,
  prUrl: `https://example.invalid/pull/${pr}`, branchName: `ops/mea/${pr}`,
  process: { id, category: 'C', machineType: 'All', issue: `issue-${id}-pr${pr}`, process: `<p>content ${id} pr${pr}</p>` },
  ...extra
});
function baseHistory() {
  return {
    mea: [
      rec(ID_A, OLD_PR_A, 'merged', { mergeCommitSha: 'aaaa1111', mergedAt: '2026-01-01T00:00:00.000Z' }),   // [0] older PR, same ID as current
      rec(ID_B, OLD_PR_B, 'merged', { mergeCommitSha: 'bbbb2222', mergedAt: '2025-12-01T00:00:00.000Z' }),   // [1] older PR, same ID as current
      rec('mea_tgt_other', 500, 'merged', { mergeCommitSha: 'cccc3333', mergedAt: '2025-11-01T00:00:00.000Z' }), // [2] unrelated
      Object.assign(rec(ID_A, PR, 'pending_merge'), { process: { id: ID_A, category: 'C', machineType: 'All', issue: 'Current A', process: imgHtml(STAGED_A) } }), // [3] current
      rec(ID_B, PR, 'pending_merge')                                                                          // [4] current, no media
    ],
    fr: [rec('fr_x', 40, 'merged', { mergeCommitSha: 'dddd4444' })],
    es: []
  };
}
function bigFiller() { // push serialized History beyond 1 MiB (GitHub Contents inline limit)
  const blob = 'x'.repeat(8000);
  return Array.from({ length: 160 }, (_, i) => rec('es_fill_' + i, 1, 'merged', { filler: blob }));
}

// ── Mock GitHub ────────────────────────────────────────────────────────────────
let S = {}, CALLS = [];
function reset({ history, largeHistory = false, extraPending = null }) {
  CALLS = [];
  S = {
    'data/ops/history.json': history,
    'data/ops/pr_schedule.json': {},
    'data/ops/buffer.json': { mea: {}, fr: {} },
    'data/logs/activity_logs.json': [],
    'data/processes/mea.json': { lastUpdated: 'x', processes: [{ id: ID_A, category: 'C', machineType: 'All', issue: 'Current A', process: imgHtml(STAGED_A) }, { id: ID_B, category: 'C', machineType: 'All', issue: 'issue-B', process: '<p>b</p>' }] },
    [STAGED_A]: { __binary: Buffer.from('FAKE-WEBP-BYTES').toString('base64') },
    _large: largeHistory,
    _commits: [],
    _prs: [{ number: PR, state: 'open', html_url: `https://example.invalid/pull/${PR}`, head: { ref: `ops/mea/${PR}` }, merged_at: null }]
  };
}
const enc = o => Buffer.from(JSON.stringify(o, null, 2) + '\n').toString('base64');

const mock = http.createServer((req, res) => {
  let body = '';
  req.on('data', c => { body += c; });
  req.on('end', () => {
    const send = (st, o) => { const d = JSON.stringify(o); res.writeHead(st, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(d) }); res.end(d); };
    const p = (req.url || '').split('?')[0], m = req.method;
    CALLS.push({ m, p });
    const cm = p.match(/\/repos\/[^/]+\/[^/]+\/contents\/(.+)/);
    if (cm) {
      const fp = decodeURIComponent(cm[1]);
      if (m === 'GET') {
        if (S[fp] === undefined) return send(404, { message: 'Not Found' });
        if (S[fp] && S[fp].__binary) return send(200, { path: fp, sha: 'sha-bin-' + crypto.createHash('md5').update(S[fp].__binary).digest('hex'), content: S[fp].__binary, encoding: 'base64' });
        if (fp === 'data/ops/history.json' && S._large) return send(200, { path: fp, sha: 'sha-hist-large', content: '', encoding: 'none', size: 1100000 });
        return send(200, { path: fp, sha: 'sha-' + fp.replace(/\//g, '-') + '-' + S._commits.length, content: enc(S[fp]), encoding: 'base64' });
      }
      if (m === 'PUT') {
        let j = {}; try { j = JSON.parse(body); } catch {}
        if (fp.endsWith('.webp')) { S[fp] = { __binary: j.content }; S._commits.push({ path: fp, message: j.message }); return send(200, { content: { path: fp, sha: 'sha-new' }, commit: { sha: 'c1' } }); }
        try { S[fp] = JSON.parse(Buffer.from(j.content, 'base64').toString('utf8')); S._commits.push({ path: fp, message: j.message }); } catch {}
        return send(200, { content: { path: fp, sha: 'sha-new' }, commit: { sha: 'c1' } });
      }
      if (m === 'DELETE') { delete S[fp]; S._commits.push({ path: fp, message: 'DELETE' }); return send(200, { commit: { sha: 'c2' } }); }
    }
    const bm = p.match(/\/git\/blobs\/(.+)$/);
    if (m === 'GET' && bm) {
      if (bm[1] === 'sha-hist-large') return send(200, { sha: bm[1], encoding: 'base64', content: enc(S['data/ops/history.json']) });
      return send(404, { message: 'no blob' });
    }
    const pg = m === 'GET' && p.match(/\/pulls\/(\d+)$/);
    if (pg) { const x = S._prs.find(q => q.number === +pg[1]); return x ? send(200, x) : send(404, {}); }
    const pm = m === 'PUT' && p.match(/\/pulls\/(\d+)\/merge$/);
    if (pm) { const x = S._prs.find(q => q.number === +pm[1]); if (!x || x.state !== 'open') return send(405, {}); x.state = 'closed'; x.merged_at = new Date().toISOString(); return send(200, { sha: 'merge-sha-' + pm[1], merged: true }); }
    send(404, { message: `Mock: no handler for ${m} ${p}` });
  });
});

function api(method, urlPath, bodyObj) {
  return new Promise((resolve, reject) => {
    const b = bodyObj ? JSON.stringify(bodyObj) : '';
    const r = http.request({ hostname: 'localhost', port: SERVER_PORT, path: urlPath, method, headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(b), Authorization: `Bearer ${ADMIN}` } }, rs => {
      let d = ''; rs.on('data', c => { d += c; }); rs.on('end', () => { let j = null; try { j = JSON.parse(d); } catch {} resolve({ status: rs.statusCode, json: j }); });
    });
    r.on('error', reject); r.end(b);
  });
}
function waitForPort(port, n = 30) {
  return new Promise((ok, bad) => { (function t(i) { const s = net.connect(port, 'localhost'); s.on('connect', () => { s.destroy(); ok(); }); s.on('error', () => (i <= 0 ? bad(new Error('port')) : setTimeout(() => t(i - 1), 300))); })(n); });
}
const historyCommits = () => S._commits.filter(c => c.path === 'data/ops/history.json');
const rewriteCommits = () => historyCommits().filter(c => /rewrite staged/.test(c.message));
const logs = () => S['data/logs/activity_logs.json'] || [];

(async () => {
  await new Promise(r => mock.listen(MOCK_PORT, r));
  const proc = fork(SERVER_PATH, [], {
    env: { ...process.env, PORT: String(SERVER_PORT), JWT_SECRET: SECRET, GITHUB_TOKEN: 'mock-token', GITHUB_OWNER: 'nlabib', GITHUB_REPO: 'process-finder', GITHUB_BRANCH: 'main', GITHUB_API_BASE: `http://localhost:${MOCK_PORT}`, DISABLE_PR_CREATION: 'false', EMAIL_SEND_MODE: 'mock' },
    silent: true
  });
  proc.stdout?.on('data', () => {}); proc.stderr?.on('data', () => {});
  const t0 = Date.now();
  try {
    await waitForPort(SERVER_PORT);

    // ── E1: PR #218-shaped scenario, repeated IDs across PRs, LARGE History path ──
    section('E1: repeated IDs across PRs (PR #218 shape) via large-History reader');
    const h1 = baseHistory(); h1.es = bigFiller();
    const bytes = Buffer.byteLength(JSON.stringify(h1, null, 2));
    assert('E1-0 fixture History exceeds 1 MiB (large-file path exercised)', bytes > 1048576, `bytes=${bytes}`);
    reset({ history: clone(h1), largeHistory: true });
    const before = clone(S['data/ops/history.json']);
    const r1 = await api('POST', '/api/admin/pr/approve', { country: 'mea', prNumber: PR });
    assert('E1-1 approve returns 200 success, mergedCount 2', r1.status === 200 && r1.json?.success === true && r1.json?.mergedCount === 2, JSON.stringify(r1.json));
    await sleep(1800);
    const H = S['data/ops/history.json']; const m = H.mea;
    assert('E1-2 History country buckets preserved', Object.keys(H).join() === Object.keys(before).join());
    assert('E1-3 History record count unchanged', Object.values(H).flat().length === Object.values(before).flat().length, `${Object.values(H).flat().length} vs ${Object.values(before).flat().length}`);
    assert('E1-4 older PR record for ID A (mea[0]) unchanged', JSON.stringify(m[0]) === JSON.stringify(before.mea[0]), JSON.stringify(m[0]).slice(0, 160));
    assert('E1-5 older PR record for ID B (mea[1]) unchanged', JSON.stringify(m[1]) === JSON.stringify(before.mea[1]), JSON.stringify(m[1]).slice(0, 160));
    assert('E1-6 unrelated record (mea[2]) unchanged', JSON.stringify(m[2]) === JSON.stringify(before.mea[2]));
    assert('E1-7 exactly two records carry the approved PR number', m.filter(x => x.prNumber === PR).length === 2, `count=${m.filter(x => x.prNumber === PR).length}`);
    assert('E1-8 the two PR records stayed at their own slots (mea[3], mea[4])', m[3].prNumber === PR && m[4].prNumber === PR && m[3].id === ID_A && m[4].id === ID_B);
    assert('E1-9 both current records are merged', m[3].pr_status === 'merged' && m[4].pr_status === 'merged');
    assert('E1-10 current Oman-style record references FINAL path, not staged', m[3].process.process.includes(`src="${FINAL_A}"`) && !m[3].process.process.includes('_staged'), m[3].process.process);
    assert('E1-11 older records never acquired approval fields', !m[0].approvedBy && !m[1].approvedBy && m[0].mergeCommitSha === 'aaaa1111' && m[1].mergeCommitSha === 'bbbb2222');
    assert('E1-12 other country buckets unchanged', JSON.stringify(H.fr) === JSON.stringify(before.fr) && JSON.stringify(H.es) === JSON.stringify(before.es));
    assert('E1-13 media: final file written, staged file removed', !!S[FINAL_A] && S[STAGED_A] === undefined);
    assert('E1-14 production process data rewritten to final path', S['data/processes/mea.json'].processes[0].process.includes(`src="${FINAL_A}"`));
    assert('E1-15 second (media-rewrite) History commit made exactly once', rewriteCommits().length === 1, `n=${rewriteCommits().length}`);
    assert('E1-16 media-promoted log written; no targeting-failure log', logs().some(l => l.event === 'media-promoted') && !logs().some(l => l.event === 'media-history-target-failed'));
    assert('E1-17 Buffer and schedule untouched', JSON.stringify(S['data/ops/buffer.json']) === JSON.stringify({ mea: {}, fr: {} }) && JSON.stringify(S['data/ops/pr_schedule.json']) === '{}');

    // ── E2: ambiguous composite match -> fail closed, no second History write ──
    section('E2: ambiguous composite match fails closed');
    const h2 = baseHistory();
    h2.mea.push(Object.assign(rec(ID_A, PR, 'pending_merge'), { process: { id: ID_A, category: 'C', machineType: 'All', issue: 'Current A dup', process: imgHtml(STAGED_A) } })); // [5] second record with same id+PR
    reset({ history: clone(h2) });
    const r2 = await api('POST', '/api/admin/pr/approve', { country: 'mea', prNumber: PR });
    assert('E2-1 approve itself still succeeds (merge + first History write are unchanged behaviour)', r2.status === 200 && r2.json?.success === true, JSON.stringify(r2.json));
    await sleep(1800);
    const m2 = S['data/ops/history.json'].mea;
    assert('E2-2 no second (media-rewrite) History commit made', rewriteCommits().length === 0, `n=${rewriteCommits().length}`);
    assert('E2-3 older same-ID records unchanged', JSON.stringify(m2[0]) === JSON.stringify(h2.mea[0]) && JSON.stringify(m2[1]) === JSON.stringify(h2.mea[1]));
    assert('E2-4 History count unchanged', m2.length === h2.mea.length);
    assert('E2-5 structured failure event logged with safe metadata', logs().some(l => l.event === 'media-history-target-failed' && l.prNumber === PR && l.country === 'mea' && typeof l.code === 'string' && !JSON.stringify(l).includes('FAKE-WEBP')), JSON.stringify(logs()));

    // ── E3: media-free approval unchanged ──────────────────────────────────────
    section('E3: media-free approval has no second History mutation');
    const h3 = baseHistory(); h3.mea.splice(3, 1); // only the media-free current record for ID B remains
    reset({ history: clone(h3) });
    S['data/processes/mea.json'] = { lastUpdated: 'x', processes: [{ id: ID_B, category: 'C', machineType: 'All', issue: 'issue-B', process: '<p>b</p>' }] };
    const r3 = await api('POST', '/api/admin/pr/approve', { country: 'mea', prNumber: PR });
    await sleep(1200);
    const m3 = S['data/ops/history.json'].mea; const cur3 = m3.filter(x => x.prNumber === PR);
    assert('E3-1 approve 200 / mergedCount 1', r3.status === 200 && r3.json?.mergedCount === 1, JSON.stringify(r3.json));
    assert('E3-2 exactly one History write (status flip), no media rewrite write', historyCommits().length === 1 && rewriteCommits().length === 0, `n=${historyCommits().length}`);
    assert('E3-3 current record merged; older same-ID record (PR 863) untouched', cur3.length === 1 && cur3[0].pr_status === 'merged' && JSON.stringify(m3.find(x => x.prNumber === OLD_PR_B)) === JSON.stringify(h3.mea.find(x => x.prNumber === OLD_PR_B)));
    assert('E3-4 no promote/rewrite media calls were made', !S._commits.some(c => c.path.endsWith('.webp')));

    // ── E4: unique ID with media (ordinary case) ───────────────────────────────
    section('E4: unique-ID approval with media behaves as before');
    const h4 = baseHistory(); h4.mea = [h4.mea[2], h4.mea[3]]; // unrelated + current A only (A has no older sibling)
    reset({ history: clone(h4) });
    S['data/processes/mea.json'] = { lastUpdated: 'x', processes: [{ id: ID_A, category: 'C', machineType: 'All', issue: 'Current A', process: imgHtml(STAGED_A) }] };
    const r4 = await api('POST', '/api/admin/pr/approve', { country: 'mea', prNumber: PR });
    await sleep(1800);
    const m4 = S['data/ops/history.json'].mea;
    assert('E4-1 approve 200', r4.status === 200 && r4.json?.mergedCount === 1, JSON.stringify(r4.json));
    assert('E4-2 current record updated with FINAL path, merged', m4[1].pr_status === 'merged' && m4[1].process.process.includes(`src="${FINAL_A}"`));
    assert('E4-3 unrelated record unchanged, count unchanged', JSON.stringify(m4[0]) === JSON.stringify(h4.mea[0]) && m4.length === 2);
    assert('E4-4 exactly one media rewrite commit', rewriteCommits().length === 1);
  } catch (e) {
    console.error('Harness error:', e);
    _fail++; _failures.push('harness: ' + e.message);
  } finally {
    proc.kill(); mock.close();
  }
  console.log(`\n${'═'.repeat(70)}\nResults: ${_pass} passed, ${_fail} failed  (${((Date.now() - t0) / 1000).toFixed(1)}s)  [server=${path.basename(SERVER_PATH)}]`);
  if (_failures.length) { console.error('Failures:'); _failures.forEach(f => console.error('  - ' + f)); }
  process.exit(_fail === 0 ? 0 : 1);
})();
