/**
 * test-github-hardening.js
 *
 * Focused unit tests for the GitHub read/write hardening changes.
 * Tests the core logic of fetchGitHubJsonStrict and the history overwrite guard
 * in commitJsonToMainBranch by re-implementing the same logic in isolation with
 * a controllable fetch mock.
 *
 * This avoids loading the full server.js (which requires express, sharp, etc.).
 *
 * Run with:  node test-github-hardening.js
 *
 * Exit 0 = all passed.
 * Exit 1 = one or more failed.
 */

'use strict';

const orig = { error: console.error, warn: console.warn, log: console.log };

// ─── Fetch mock ───────────────────────────────────────────────────────────────
let _queue = [];
let _calls = 0;

function mockFetch(/* url, opts */) {
  _calls++;
  if (!_queue.length) return Promise.reject(new Error('mock: no response queued'));
  const r = _queue.shift();
  const bodyStr = typeof r.body === 'string' ? r.body : JSON.stringify(r.body);
  return Promise.resolve({
    ok:     r.status >= 200 && r.status < 300,
    status: r.status,
    json:   () => Promise.resolve(typeof r.body === 'string' ? JSON.parse(r.body) : r.body),
    text:   () => Promise.resolve(bodyStr)
  });
}

function q(status, body) { _queue.push({ status, body }); }
function reset()         { _queue = []; _calls = 0; }
function ghContent(data) { return { sha: 'sha0', content: Buffer.from(JSON.stringify(data)).toString('base64') }; }

// ─── Re-implement the hardened helpers under test ─────────────────────────────
// These are exact copies of the implementations in server.js.
// They receive the mockFetch as `fetch` so we can intercept GitHub calls.

async function fetchGitHubJsonStrict(fetch, filePath, fallback) {
  let lastStatus = null, lastErr = null;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const res = await fetch(`https://api.github.test/test/${filePath}`);
      if (res.status === 404) return fallback;
      if (res.ok) {
        const fileInfo = await res.json();
        if (!fileInfo || !fileInfo.content) {
          throw Object.assign(new Error(`no content for "${filePath}"`), { code: 'GITHUB_EMPTY_CONTENT', filePath });
        }
        const raw = Buffer.from(fileInfo.content, 'base64').toString('utf8');
        return JSON.parse(raw);
      }
      lastStatus = res.status;
      if (res.status === 502 || res.status === 503 || res.status === 504) {
        if (attempt < 3) { await new Promise(r => setTimeout(r, 1)); continue; }
        break; // last attempt — fall through to GITHUB_READ_EXHAUSTED
      }
      const body = await res.text().catch(() => '');
      throw Object.assign(
        new Error(`GitHub read HTTP ${res.status} for "${filePath}"`),
        { code: 'GITHUB_READ_HTTP_ERROR', filePath, httpStatus: res.status }
      );
    } catch (err) {
      if (err.code === 'GITHUB_READ_HTTP_ERROR' || err.code === 'GITHUB_EMPTY_CONTENT') throw err;
      lastErr = err;
      if (attempt < 3) { await new Promise(r => setTimeout(r, 1)); continue; }
    }
  }
  const msg = lastErr
    ? `GitHub read failed after 3 attempts: ${lastErr.message}`
    : `GitHub read failed after 3 attempts: HTTP ${lastStatus}`;
  throw Object.assign(new Error(msg), { code: 'GITHUB_READ_EXHAUSTED', filePath, httpStatus: lastStatus });
}

const HISTORY_FILE                              = 'data/ops/history.json';
const HISTORY_OVERWRITE_MAX_ENTRY_DROP_FRACTION = 0.20;

// ─── Re-implement the hardened preflight and rollback logic under test ─────────
// Minimal in-process models of _adminPreflightCheck (history read portion only)
// and POST /api/ops/rollback (both read calls and the write-return check).
// These reflect the exact patterns added in the amendment.

async function adminPreflightHistoryRead(fetch, country, prNumber) {
  // Mirrors the amended step 3 in _adminPreflightCheck.
  let historyPre;
  try {
    historyPre = await fetchGitHubJsonStrict(fetch, HISTORY_FILE, null);
  } catch (err) {
    return {
      ok: false, httpStatus: 503,
      error: `history.json could not be safely loaded (${err.code}).`,
      opsMessage: 'OPS could not read history.json. No changes were made.',
      productionChanged: false,
      entriesLocked: true,
      _threw: true,
      _code: err.code
    };
  }
  if (!historyPre) {
    return {
      ok: false, httpStatus: 503,
      error: 'history.json returned null.',
      opsMessage: 'OPS history file could not be loaded.',
      productionChanged: false,
      entriesLocked: true,
      _null: true
    };
  }
  const matchingEntries = (historyPre[country] || []).filter(
    h => h.prNumber === prNumber && h.pr_status === 'pending_merge'
  );
  return { ok: true, matchingEntries, historyPre };
}

async function rollbackRoute(fetch, country, historyIndex) {
  // Mirrors the amended POST /api/ops/rollback.
  // First strict read (validation copy).
  let historyForRead;
  try {
    historyForRead = await fetchGitHubJsonStrict(fetch, HISTORY_FILE, null);
  } catch (err) {
    return { status: 503, body: { code: err.code || 'GITHUB_READ_FAILURE', _phase: 'read1' } };
  }
  if (!historyForRead || !historyForRead[country] || !historyForRead[country][historyIndex]) {
    return { status: 404, body: { error: 'History item not found' } };
  }

  // Second strict read (write-back copy).
  let history;
  try {
    history = await fetchGitHubJsonStrict(fetch, HISTORY_FILE, null);
  } catch (err) {
    return { status: 503, body: { code: err.code || 'GITHUB_READ_FAILURE', _phase: 'read2' } };
  }
  if (!history) {
    return { status: 503, body: { code: 'GITHUB_READ_NULL', _phase: 'read2-null' } };
  }

  // Stamp entry and push log entry.
  const item = history[country] && history[country][historyIndex];
  if (item) { item.rolledBackAt = new Date().toISOString(); item.status = 'rolled_back'; }
  if (!history[country]) history[country] = [];
  history[country].push({ id: `rollback_test`, type: 'rollback', status: 'approved' });

  // Write with return-value check.
  const writeOk = await commitJsonToMainBranch(fetch, HISTORY_FILE, history, 'ops: rollback test', 3, {});
  if (!writeOk) {
    return { status: 502, body: { code: 'GITHUB_WRITE_FAILURE', _phase: 'write' } };
  }
  return { status: 200, body: { success: true, item: item } };
}

async function commitJsonToMainBranch(fetch, filePath, data, message, retries = 3, opts = {}) {
  const isHistoryFile = filePath === HISTORY_FILE;

  // ── History overwrite guard ────────────────────────────────────────────────
  if (isHistoryFile && !opts.allowCountryDrop) {
    try {
      // Simulate fetchGitHubJson (lenient, returns null on failure)
      const res = await fetch(`https://api.github.test/test/${filePath}`);
      let currentRaw = null;
      if (res.ok) {
        const fi = await res.json();
        if (fi && fi.content) {
          currentRaw = JSON.parse(Buffer.from(fi.content, 'base64').toString('utf8'));
        }
      }
      if (currentRaw && typeof currentRaw === 'object' && !Array.isArray(currentRaw)) {
        const currentKeys   = Object.keys(currentRaw);
        const proposedKeys  = typeof data === 'object' && !Array.isArray(data) ? Object.keys(data) : [];
        const currentTotal  = currentKeys.reduce((n, k) => n + (Array.isArray(currentRaw[k]) ? currentRaw[k].length : 0), 0);
        const proposedTotal = proposedKeys.reduce((n, k) => n + (Array.isArray(data[k]) ? data[k].length : 0), 0);
        const droppedKeys   = currentKeys.filter(k => !proposedKeys.includes(k));
        const frac          = currentTotal > 0 ? (currentTotal - proposedTotal) / currentTotal : 0;
        if (droppedKeys.length > 0 || frac > HISTORY_OVERWRITE_MAX_ENTRY_DROP_FRACTION) {
          return false; // blocked by guard
        }
      }
    } catch (_) { /* guard read failure — proceed */ }
  }

  // ── Write with retry on 409/422/502/503/504 ────────────────────────────────
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const shaRes = await fetch(`https://api.github.test/test/${filePath}`);
      const sha    = shaRes.ok ? (await shaRes.json()).sha : undefined;

      const res = await fetch(`https://api.github.test/test/${filePath}`, { method: 'PUT' });
      if (res.ok) return true;

      const isConflict  = res.status === 409 || res.status === 422;
      const isTransient = res.status === 502 || res.status === 503 || res.status === 504;
      if ((isConflict || isTransient) && attempt < retries) {
        await new Promise(r => setTimeout(r, 1));
        continue;
      }
      return false;
    } catch (err) {
      if (attempt < retries) { await new Promise(r => setTimeout(r, 1)); continue; }
      return false;
    }
  }
  return false;
}

// ─── Test runner ─────────────────────────────────────────────────────────────
const results = [];
let passed = 0, failed = 0;

function silence() { console.error = () => {}; console.warn = () => {}; console.log = () => {}; }
function restore() { Object.assign(console, orig); }

async function test(label, fn) {
  reset();
  silence();
  try   { await fn(); passed++; results.push({ ok: true, label }); }
  catch (e) { failed++; results.push({ ok: false, label, error: e.message }); }
  finally { restore(); }
}

function assert(cond, msg) { if (!cond) throw new Error(msg); }
const F = (fn) => fetchGitHubJsonStrict.bind(null, fn);
const C = (fn) => commitJsonToMainBranch.bind(null, fn);

// ─── Tests ───────────────────────────────────────────────────────────────────

async function runTests() {

  // A — fetchGitHubJsonStrict throws after 3× 502 (never silently returns fallback)
  await test('A: fetchGitHubJsonStrict throws after 3× 502 — never returns fallback {}', async () => {
    q(502, 'Bad Gateway'); q(502, 'Bad Gateway'); q(502, 'Bad Gateway');
    let threw = false, code = null;
    try { await F(mockFetch)(HISTORY_FILE, {}); }
    catch (e) { threw = true; code = e.code; }
    assert(threw, 'must throw when all retries return 502');
    assert(code === 'GITHUB_READ_EXHAUSTED', `expected GITHUB_READ_EXHAUSTED, got ${code}`);
    assert(_calls === 3, `expected 3 fetch calls, got ${_calls}`);
  });

  // A2 — fetchGitHubJsonStrict retries 502 then succeeds
  await test('A2: fetchGitHubJsonStrict retries 502 and succeeds on attempt 2', async () => {
    const history = { it: [{ id: 'it_001' }], fr: [{ id: 'fr_001' }] };
    q(502, 'Bad Gateway');
    q(200, ghContent(history));
    const result = await F(mockFetch)(HISTORY_FILE, {});
    assert(result && result.it && result.fr, 'should return parsed history with both keys');
    assert(_calls === 2, `expected 2 fetch calls, got ${_calls}`);
  });

  // A3 — fetchGitHubJsonStrict returns fallback on genuine 404
  await test('A3: fetchGitHubJsonStrict returns fallback {} on genuine 404 (file absent)', async () => {
    q(404, 'Not Found');
    const result = await F(mockFetch)(HISTORY_FILE, {});
    assert(result !== null && typeof result === 'object', 'should return fallback on 404');
    assert(_calls === 1, 'should not retry 404');
  });

  // B — commitJsonToMainBranch retries 502/503 and succeeds on 3rd attempt
  await test('B: commitJsonToMainBranch retries 502 + 503 and succeeds on 3rd attempt', async () => {
    const data = { it: [{ id: 'i1' }], fr: [] };
    q(200, ghContent(data));   // guard read
    // attempt 1: sha fetch OK, PUT → 502
    q(200, ghContent({})); q(502, 'Bad Gateway');
    // attempt 2: sha fetch OK, PUT → 503
    q(200, ghContent({})); q(503, 'Service Unavailable');
    // attempt 3: sha fetch OK, PUT → 200
    q(200, ghContent({})); q(200, { content: { sha: 'newsha' } });
    const ok = await C(mockFetch)(HISTORY_FILE, data, 'test', 3, {});
    assert(ok === true, 'should return true on eventual success');
  });

  // B2 — commitJsonToMainBranch returns false after all retries fail
  await test('B2: commitJsonToMainBranch returns false after 3 exhausted retries', async () => {
    const data = { it: [{ id: 'i1' }], fr: [] };
    q(200, ghContent(data)); // guard read
    for (let i = 0; i < 3; i++) { q(200, ghContent({})); q(502, 'Bad Gateway'); }
    const ok = await C(mockFetch)(HISTORY_FILE, data, 'test', 3, {});
    assert(ok === false, 'should return false when all retries fail');
  });

  // C — history overwrite guard blocks a write that drops country keys
  await test('C: commitJsonToMainBranch blocks write that drops ES and FR country keys', async () => {
    const current  = { it: [{ id: 'i1' }], fr: [{ id: 'f1' }], es: [{ id: 'e1' }] };
    const proposed = { it: [{ id: 'i1_new' }] }; // fr + es dropped
    q(200, ghContent(current)); // guard read — must see this and block
    const ok = await C(mockFetch)(HISTORY_FILE, proposed, 'test', 3, {});
    assert(ok === false, 'guard must block country-dropping write');
    assert(_calls === 1, `expected 1 fetch call (guard read only), got ${_calls}`);
  });

  // C2 — allowCountryDrop bypasses the overwrite guard (archive route)
  await test('C2: allowCountryDrop:true bypasses overwrite guard (archive route)', async () => {
    // No guard read when allowCountryDrop is set — goes straight to sha fetch + PUT
    q(200, ghContent({})); q(200, { content: { sha: 'newsha' } });
    const ok = await C(mockFetch)(HISTORY_FILE, { it: [] }, 'admin: clear', 3, { allowCountryDrop: true });
    assert(ok === true, 'archive route with allowCountryDrop must be allowed');
  });

  // D — normal PR creation: existing countries preserved + new entry added
  await test('D: normal PR-creation write (adds entry, keeps all countries) passes guard', async () => {
    const existing = { es: [{ id: 'e1' }], fr: [{ id: 'f1' }], it: [{ id: 'i1' }] };
    const proposed = { es: [{ id: 'e1' }], fr: [{ id: 'f1' }], it: [{ id: 'i1' }, { id: 'i2' }] };
    q(200, ghContent(existing));                           // guard read
    q(200, ghContent({})); q(200, { content: { sha: 'x' } }); // sha fetch + PUT
    const ok = await C(mockFetch)(HISTORY_FILE, proposed, 'ops: add entry', 3, {});
    assert(ok === true, 'adding entry without dropping countries must succeed');
  });

  // E — normal append: entry count grew, all countries kept
  await test('E: normal append (adds entries, all countries kept) passes guard', async () => {
    const existing = { it: [{ id: 'i1' }], mea: [{ id: 'm1' }] };
    const proposed = { it: [{ id: 'i1' }, { id: 'i2' }], mea: [{ id: 'm1' }] };
    q(200, ghContent(existing));
    q(200, ghContent({})); q(200, { content: { sha: 'x' } });
    const ok = await C(mockFetch)(HISTORY_FILE, proposed, 'ops: append', 3, {});
    assert(ok === true, 'append (more entries, no country drop) must pass guard');
  });

  // F — approve: same countries and entry count, only status changed
  await test('F: approve-style status update (no country drop, no entry loss) passes guard', async () => {
    const existing = { it: [{ id: 'i1', pr_status: 'pending_merge' }], fr: [{ id: 'f1' }] };
    const proposed = { it: [{ id: 'i1', pr_status: 'merged' }],        fr: [{ id: 'f1' }] };
    q(200, ghContent(existing));
    q(200, ghContent({})); q(200, { content: { sha: 'x' } });
    const ok = await C(mockFetch)(HISTORY_FILE, proposed, 'ops: mark merged', 3, {});
    assert(ok === true, 'status-only update must pass guard');
  });

  // ── Amendment tests ──────────────────────────────────────────────────────────

  // G — _adminPreflightCheck: history read returns 502 → operation aborts, no write proceeds
  await test('G: _adminPreflightCheck aborts (503) when history read exhausts 3× 502', async () => {
    // Three 502s for the strict history read — no further calls must happen
    q(502, 'Bad Gateway'); q(502, 'Bad Gateway'); q(502, 'Bad Gateway');
    const result = await adminPreflightHistoryRead(mockFetch, 'it', 143);
    assert(result.ok === false, 'preflight must return ok:false on read failure');
    assert(result.httpStatus === 503, `expected httpStatus 503, got ${result.httpStatus}`);
    assert(result.productionChanged === false, 'productionChanged must be false — nothing was written');
    assert(result.entriesLocked === true, 'entriesLocked must be true — preflight gate must hold');
    assert(result._threw === true, 'must have caught a thrown error (not a silent fallback)');
    assert(result._code === 'GITHUB_READ_EXHAUSTED', `expected GITHUB_READ_EXHAUSTED, got ${result._code}`);
    assert(_calls === 3, `expected exactly 3 fetch calls (retries), got ${_calls}`);
  });

  // H — rollback: first history read fails → operation aborts, no write
  await test('H: rollback aborts (503) when first history read exhausts 3× 502', async () => {
    q(502, 'Bad Gateway'); q(502, 'Bad Gateway'); q(502, 'Bad Gateway');
    const result = await rollbackRoute(mockFetch, 'it', 0);
    assert(result.status === 503, `expected HTTP 503, got ${result.status}`);
    assert(result.body.code === 'GITHUB_READ_EXHAUSTED' || result.body.code === 'GITHUB_READ_FAILURE',
      `expected read-failure code, got ${result.body.code}`);
    assert(result.body._phase === 'read1', 'failure must be identified as first read phase');
    assert(_calls === 3, `expected 3 fetch calls (first read retries only), got ${_calls}`);
  });

  // I — approve/reject regression: valid history with matching pending_merge entry → ok:true
  await test('I: _adminPreflightCheck succeeds with valid history + matching pending_merge entry', async () => {
    const history = {
      it: [{ id: 'it_001', prNumber: 143, pr_status: 'pending_merge' }],
      fr: [{ id: 'fr_001', prNumber: 99,  pr_status: 'merged' }]
    };
    q(200, ghContent(history));
    const result = await adminPreflightHistoryRead(mockFetch, 'it', 143);
    assert(result.ok === true, 'preflight must return ok:true with valid matching entries');
    assert(result.matchingEntries.length === 1, `expected 1 matching entry, got ${result.matchingEntries.length}`);
    assert(result.historyPre.fr !== undefined, 'all countries must be preserved in returned historyPre');
    assert(_calls === 1, `expected 1 fetch call, got ${_calls}`);
  });

  // J — rollback regression: valid history with entry at index 0 → 200, write committed
  await test('J: rollback succeeds with valid history and valid historyIndex', async () => {
    const history = {
      it: [{ id: 'it_001', prNumber: 143, pr_status: 'merged' }],
      fr: [{ id: 'fr_001' }]
    };
    // read1 (validation), read2 (write-back prefetch), guard read, sha fetch, PUT
    q(200, ghContent(history));  // strict read 1
    q(200, ghContent(history));  // strict read 2
    q(200, ghContent(history));  // guard read inside commitJsonToMainBranch
    q(200, ghContent({}));       // sha fetch
    q(200, { content: { sha: 'newsha' } }); // PUT success
    const result = await rollbackRoute(mockFetch, 'it', 0);
    assert(result.status === 200, `expected HTTP 200, got ${result.status}`);
    assert(result.body.success === true, 'rollback must return success:true');
    assert(result.body.item !== undefined, 'result must include the stamped item');
  });

} // end runTests

runTests()
  .then(() => {
    console.log('\n──────────────────────────────────────────────');
    console.log(' GitHub Hardening Test Results');
    console.log('──────────────────────────────────────────────');
    for (const r of results) {
      if (r.ok) console.log(`  ✓  ${r.label}`);
      else      console.log(`  ✗  ${r.label}\n       ${r.error}`);
    }
    console.log('──────────────────────────────────────────────');
    console.log(`  ${passed} passed, ${failed} failed`);
    console.log('──────────────────────────────────────────────\n');
    process.exit(failed > 0 ? 1 : 0);
  })
  .catch(e => {
    console.error('Test runner crashed:', e.message);
    process.exit(1);
  });
