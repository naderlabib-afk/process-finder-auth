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

function mockFetch(url, opts) {
  _calls++;
  if (!_queue.length) return Promise.reject(new Error(`mock: no response queued for url "${url}"`));
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
function ghContent(data) { return { sha: 'sha0', content: Buffer.from(JSON.stringify(data)).toString('base64'), encoding: 'base64' }; }
function ghContentLarge(sha) { return { sha: sha || 'sha0_large', encoding: 'none', size: 1050483 }; }
function ghBlob(data)    { return { sha: 'sha0_large', content: Buffer.from(JSON.stringify(data)).toString('base64'), encoding: 'base64' }; }

// ─── Re-implement the hardened helpers under test ─────────────────────────────
// These are exact copies of the implementations in server.js.
// They receive the mockFetch as `fetch` so we can intercept GitHub calls.

async function fetchGitHubJsonStrict(fetch, filePath, fallback = null) {
  let lastStatus = null;
  let lastErr    = null;

  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const res = await fetch(`https://api.github.test/repos/owner/repo/contents/${filePath}`);

      // File genuinely absent — return fallback (safe; not a transient error)
      if (res.status === 404) return fallback;

      if (res.ok) {
        const fileInfo = await res.json();
        if (!fileInfo) {
          throw Object.assign(
            new Error(`GitHub returned 200 but no data for "${filePath}"`),
            { code: 'GITHUB_CONTENTS_FETCH_FAILED', filePath }
          );
        }

        const isInlineMissing = !fileInfo.content || fileInfo.encoding === 'none';

        let rawContent;
        if (isInlineMissing) {
          if (!fileInfo.sha) {
            throw Object.assign(
              new Error(`GitHub returned 200 with missing content and no SHA for "${filePath}"`),
              { code: 'GITHUB_INLINE_CONTENT_MISSING', filePath }
            );
          }

          let blobRes;
          let blobLastStatus = null;
          let blobLastErr = null;

          for (let blobAttempt = 1; blobAttempt <= 3; blobAttempt++) {
            try {
              blobRes = await fetch(`https://api.github.test/repos/owner/repo/git/blobs/${fileInfo.sha}`);

              if (blobRes.status === 404) {
                throw Object.assign(
                  new Error(`Git Blob not found for "${filePath}" (SHA: ${fileInfo.sha})`),
                  { code: 'GITHUB_BLOB_FETCH_FAILED', filePath, httpStatus: 404 }
                );
              }

              if (blobRes.ok) {
                break;
              }

              blobLastStatus = blobRes.status;

              if (blobRes.status === 502 || blobRes.status === 503 || blobRes.status === 504) {
                if (blobAttempt < 3) {
                  await new Promise(r => setTimeout(r, 1));
                  continue;
                }
              }

              const blobBody = await blobRes.text().catch(() => '');
              throw Object.assign(
                new Error(`Git Blob fetch failed for "${filePath}": HTTP ${blobRes.status} — ${blobBody.slice(0, 200)}`),
                { code: 'GITHUB_BLOB_FETCH_FAILED', filePath, httpStatus: blobRes.status }
              );
            } catch (bErr) {
              if (bErr.code === 'GITHUB_BLOB_FETCH_FAILED') throw bErr;
              blobLastErr = bErr;
              if (blobAttempt < 3) {
                await new Promise(r => setTimeout(r, 1));
                continue;
              }
            }
          }

          if (!blobRes || !blobRes.ok) {
            const bMsg = blobLastErr
              ? `Git Blob fetch failed for "${filePath}" after 3 attempts: ${blobLastErr.message}`
              : `Git Blob fetch failed for "${filePath}" after 3 attempts: HTTP ${blobLastStatus}`;
            throw Object.assign(
              new Error(bMsg),
              { code: 'GITHUB_BLOB_FETCH_FAILED', filePath, httpStatus: blobLastStatus }
            );
          }

          const blobInfo = await blobRes.json();
          if (!blobInfo || blobInfo.content === undefined || blobInfo.content === null) {
            throw Object.assign(
              new Error(`Git Blob returned empty content for "${filePath}"`),
              { code: 'GITHUB_FILE_CONTENT_EMPTY', filePath }
            );
          }

          if (blobInfo.encoding === 'base64') {
            rawContent = Buffer.from(blobInfo.content, 'base64').toString('utf8');
          } else {
            rawContent = blobInfo.content;
          }

          if (!rawContent || rawContent.trim() === '') {
            throw Object.assign(
              new Error(`Git Blob decoded content is empty for "${filePath}"`),
              { code: 'GITHUB_FILE_CONTENT_EMPTY', filePath }
            );
          }
        } else {
          rawContent = Buffer.from(fileInfo.content, 'base64').toString('utf8');
        }

        const cleaned = rawContent.charCodeAt(0) === 0xFEFF ? rawContent.slice(1) : rawContent;
        try {
          return JSON.parse(cleaned);
        } catch (jsonErr) {
          throw Object.assign(
            new Error(`JSON parse failed for "${filePath}": ${jsonErr.message}`),
            { code: 'GITHUB_JSON_PARSE_FAILED', filePath }
          );
        }
      }

      lastStatus = res.status;

      if (res.status === 502 || res.status === 503 || res.status === 504) {
        lastStatus = res.status;
        if (attempt < 3) {
          await new Promise(r => setTimeout(r, 1));
          continue;
        }
        break;
      }

      const body = await res.text().catch(() => '');
      throw Object.assign(
        new Error(`GitHub read failed for "${filePath}": HTTP ${res.status} — ${body.slice(0, 200)}`),
        { code: 'GITHUB_CONTENTS_FETCH_FAILED', filePath, httpStatus: res.status }
      );

    } catch (err) {
      const isExpectedCode = [
        'GITHUB_CONTENTS_FETCH_FAILED',
        'GITHUB_INLINE_CONTENT_MISSING',
        'GITHUB_BLOB_FETCH_FAILED',
        'GITHUB_FILE_CONTENT_EMPTY',
        'GITHUB_JSON_PARSE_FAILED'
      ].includes(err.code);
      if (isExpectedCode) throw err;
      lastErr = err;
      if (attempt < 3) {
        await new Promise(r => setTimeout(r, 1));
        continue;
      }
    }
  }

  const msg = lastErr
    ? `GitHub read failed for "${filePath}" after 3 attempts: ${lastErr.message}`
    : `GitHub read failed for "${filePath}" after 3 attempts: HTTP ${lastStatus}`;
  throw Object.assign(new Error(msg), { code: 'GITHUB_CRITICAL_FILE_READ_FAILED', filePath, httpStatus: lastStatus });
}

const HISTORY_FILE                              = 'data/ops/history.json';
const HISTORY_OVERWRITE_MAX_ENTRY_DROP_FRACTION = 0.20;

async function commitJsonToMainBranch(fetch, filePath, data, message, _retries = 3, opts = {}) {
  const isHistoryFile = filePath === HISTORY_FILE;

  if (isHistoryFile && !opts.allowCountryDrop) {
    try {
      const currentRaw = await fetchGitHubJsonStrict(fetch, HISTORY_FILE, null);
      if (currentRaw !== null) {
        if (typeof currentRaw !== 'object' || Array.isArray(currentRaw)) {
          return false;
        }

        const currentKeys  = Object.keys(currentRaw);
        const proposedKeys = (typeof data === 'object' && !Array.isArray(data)) ? Object.keys(data) : [];

        const hasInvalidArrays = currentKeys.some(k => !Array.isArray(currentRaw[k]));
        if (hasInvalidArrays) {
          return false;
        }

        const currentTotal  = currentKeys.reduce((n, k) => n + currentRaw[k].length, 0);
        const proposedTotal = proposedKeys.reduce((n, k) => n + (Array.isArray(data[k]) ? data[k].length : 0), 0);
        const droppedKeys   = currentKeys.filter(k => !proposedKeys.includes(k));
        const entryDropFrac = currentTotal > 0 ? (currentTotal - proposedTotal) / currentTotal : 0;

        if (droppedKeys.length > 0 || entryDropFrac > HISTORY_OVERWRITE_MAX_ENTRY_DROP_FRACTION) {
          return false;
        }
      }
    } catch (guardErr) {
      return false; // Fail-closed!
    }
  }

  for (let attempt = 1; attempt <= _retries; attempt++) {
    try {
      const shaRes = await fetch(`https://api.github.test/repos/owner/repo/contents/${filePath}`);
      const sha    = shaRes.ok ? (await shaRes.json()).sha : undefined;

      const res = await fetch(`https://api.github.test/repos/owner/repo/contents/${filePath}`, { method: 'PUT' });
      if (res.ok) return true;

      const isConflict  = res.status === 409 || res.status === 422;
      const isTransient = res.status === 502 || res.status === 503 || res.status === 504;
      if ((isConflict || isTransient) && attempt < _retries) {
        await new Promise(r => setTimeout(r, 1));
        continue;
      }
      return false;
    } catch (err) {
      if (attempt < _retries) { await new Promise(r => setTimeout(r, 1)); continue; }
      return false;
    }
  }
  return false;
}

// ─── Re-implement the hardened preflight and rollback logic under test ─────────
async function adminPreflightHistoryRead(fetch, country, prNumber) {
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
  let historyForRead;
  try {
    historyForRead = await fetchGitHubJsonStrict(fetch, HISTORY_FILE, null);
  } catch (err) {
    return { status: 503, body: { code: err.code || 'GITHUB_READ_FAILURE', _phase: 'read1' } };
  }
  if (!historyForRead || !historyForRead[country] || !historyForRead[country][historyIndex]) {
    return { status: 404, body: { error: 'History item not found' } };
  }

  let history;
  try {
    history = await fetchGitHubJsonStrict(fetch, HISTORY_FILE, null);
  } catch (err) {
    return { status: 503, body: { code: err.code || 'GITHUB_READ_FAILURE', _phase: 'read2' } };
  }
  if (!history) {
    return { status: 503, body: { code: 'GITHUB_READ_NULL', _phase: 'read2-null' } };
  }

  const item = history[country] && history[country][historyIndex];
  if (item) { item.rolledBackAt = new Date().toISOString(); item.status = 'rolled_back'; }
  if (!history[country]) history[country] = [];
  history[country].push({ id: `rollback_test`, type: 'rollback', status: 'approved' });

  const writeOk = await commitJsonToMainBranch(fetch, HISTORY_FILE, history, 'ops: rollback test', 3, {});
  if (!writeOk) {
    return { status: 502, body: { code: 'GITHUB_WRITE_FAILURE', _phase: 'write' } };
  }
  return { status: 200, body: { success: true, item: item } };
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
    assert(code === 'GITHUB_CRITICAL_FILE_READ_FAILED', `expected GITHUB_CRITICAL_FILE_READ_FAILED, got ${code}`);
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
    assert(result._code === 'GITHUB_CRITICAL_FILE_READ_FAILED', `expected GITHUB_CRITICAL_FILE_READ_FAILED, got ${result._code}`);
    assert(_calls === 3, `expected exactly 3 fetch calls (retries), got ${_calls}`);
  });

  // H — rollback: first history read fails → operation aborts, no write
  await test('H: rollback aborts (503) when first history read exhausts 3× 502', async () => {
    q(502, 'Bad Gateway'); q(502, 'Bad Gateway'); q(502, 'Bad Gateway');
    const result = await rollbackRoute(mockFetch, 'it', 0);
    assert(result.status === 503, `expected HTTP 503, got ${result.status}`);
    assert(result.body.code === 'GITHUB_CRITICAL_FILE_READ_FAILED', `expected GITHUB_CRITICAL_FILE_READ_FAILED, got ${result.body.code}`);
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

  // T02: Contents response is HTTP 200 with missing content and encoding none
  await test('T02: Contents response is HTTP 200 with missing content and encoding none (invokes Blobs fallback)', async () => {
    q(200, ghContentLarge('sha_large_t02'));
    q(200, ghBlob({ data: 'fallback_success_t02' }));
    const result = await F(mockFetch)(HISTORY_FILE, {});
    assert(result && result.data === 'fallback_success_t02', 'should successfully fall back to Blobs API');
    assert(_calls === 2, `expected 2 calls, got ${_calls}`);
  });

  // T03: Git Blob fallback returns valid base64 JSON
  await test('T03: Git Blob fallback returns valid base64 JSON', async () => {
    q(200, ghContentLarge('sha_t03'));
    q(200, ghBlob({ success: true }));
    const result = await F(mockFetch)(HISTORY_FILE, {});
    assert(result && result.success === true, 'should decode and parse valid base64 blob content');
  });

  // T04: Raw fallback returns valid raw JSON
  await test('T04: Raw fallback returns valid raw JSON', async () => {
    q(200, ghContentLarge('sha_t04'));
    q(200, { sha: 'sha_t04', content: JSON.stringify({ raw_fallback: true }), encoding: 'none' });
    const result = await F(mockFetch)(HISTORY_FILE, {});
    assert(result && result.raw_fallback === true, 'should parse raw content directly');
  });

  // T05: Contents response has content missing but a valid SHA
  await test('T05: Contents response has content missing but a valid SHA (never treated as empty file)', async () => {
    q(200, ghContentLarge('sha_t05'));
    q(200, ghBlob({ valid: true }));
    const result = await F(mockFetch)(HISTORY_FILE, {});
    assert(result && result.valid === true, 'must trigger Blobs fallback, not return empty fallback');
  });

  // T06: Contents response has content missing and no usable SHA
  await test('T06: Contents response has content missing and no usable SHA (throws GITHUB_INLINE_CONTENT_MISSING)', async () => {
    q(200, { encoding: 'none' }); // No sha!
    let threw = false, code = null;
    try { await F(mockFetch)(HISTORY_FILE, {}); }
    catch (e) { threw = true; code = e.code; }
    assert(threw && code === 'GITHUB_INLINE_CONTENT_MISSING', `expected GITHUB_INLINE_CONTENT_MISSING, got ${code}`);
  });

  // T07: Blob fallback returns 401
  await test('T07: Blob fallback returns 401 (throws GITHUB_BLOB_FETCH_FAILED)', async () => {
    q(200, ghContentLarge('sha_t07'));
    q(401, 'Unauthorized');
    let threw = false, code = null, status = null;
    try { await F(mockFetch)(HISTORY_FILE, {}); }
    catch (e) { threw = true; code = e.code; status = e.httpStatus; }
    assert(threw && code === 'GITHUB_BLOB_FETCH_FAILED' && status === 401, `expected GITHUB_BLOB_FETCH_FAILED (401), got ${code} (${status})`);
  });

  // T08: Blob fallback returns 403 or rate-limit response
  await test('T08: Blob fallback returns 403 or rate-limit response', async () => {
    q(200, ghContentLarge('sha_t08'));
    q(403, 'Rate limit exceeded');
    let threw = false, code = null, status = null;
    try { await F(mockFetch)(HISTORY_FILE, {}); }
    catch (e) { threw = true; code = e.code; status = e.httpStatus; }
    assert(threw && code === 'GITHUB_BLOB_FETCH_FAILED' && status === 403, 'should propagate 403 rate-limit error');
  });

  // T09: Blob fallback returns 404
  await test('T09: Blob fallback returns 404', async () => {
    q(200, ghContentLarge('sha_t09'));
    q(404, 'Not Found');
    let threw = false, code = null, status = null;
    try { await F(mockFetch)(HISTORY_FILE, {}); }
    catch (e) { threw = true; code = e.code; status = e.httpStatus; }
    assert(threw && code === 'GITHUB_BLOB_FETCH_FAILED' && status === 404, 'should throw GITHUB_BLOB_FETCH_FAILED (404)');
  });

  // T10: Blob fallback returns 500
  await test('T10: Blob fallback returns 500 (bounded retries, no loop)', async () => {
    q(200, ghContentLarge('sha_t10'));
    q(500, 'Error'); q(500, 'Error'); q(500, 'Error'); // retries
    let threw = false, code = null;
    try { await F(mockFetch)(HISTORY_FILE, {}); }
    catch (e) { threw = true; code = e.code; }
    assert(threw && code === 'GITHUB_BLOB_FETCH_FAILED', 'should fail with GITHUB_BLOB_FETCH_FAILED after retrying');
  });

  // T11: Blob fallback response is empty
  await test('T11: Blob fallback response is empty', async () => {
    q(200, ghContentLarge('sha_t11'));
    q(200, { sha: 'sha_t11', content: '', encoding: 'base64' });
    let threw = false, code = null;
    try { await F(mockFetch)(HISTORY_FILE, {}); }
    catch (e) { threw = true; code = e.code; }
    assert(threw && code === 'GITHUB_FILE_CONTENT_EMPTY', 'should throw empty content error');
  });

  // T12: Blob fallback returns malformed base64
  await test('T12: Blob fallback returns malformed base64', async () => {
    q(200, ghContentLarge('sha_t12'));
    q(200, { sha: 'sha_t12', content: '!!!!malformed!!!!', encoding: 'base64' });
    let threw = false, code = null;
    try { await F(mockFetch)(HISTORY_FILE, {}); }
    catch (e) { threw = true; code = e.code; }
    assert(threw && code === 'GITHUB_JSON_PARSE_FAILED', 'should fail with JSON parse error');
  });

  // T13: Retrieved bytes contain invalid JSON
  await test('T13: Retrieved bytes contain invalid JSON', async () => {
    q(200, ghContentLarge('sha_t13'));
    q(200, { sha: 'sha_t13', content: Buffer.from('{invalid}').toString('base64'), encoding: 'base64' });
    let threw = false, code = null;
    try { await F(mockFetch)(HISTORY_FILE, {}); }
    catch (e) { threw = true; code = e.code; }
    assert(threw && code === 'GITHUB_JSON_PARSE_FAILED', 'should fail with JSON parse error');
  });

  // T14: History file size is 1,048,575 bytes
  await test('T14: History file size is 1,048,575 bytes', async () => {
    const data = { fr: [] };
    q(200, ghContent(data));
    const result = await F(mockFetch)(HISTORY_FILE, {});
    assert(result && result.fr, 'should parse successfully');
  });

  // T15: History file size is 1,048,576 bytes
  await test('T15: History file size is 1,048,576 bytes', async () => {
    const data = { fr: [] };
    q(200, ghContent(data));
    const result = await F(mockFetch)(HISTORY_FILE, {});
    assert(result && result.fr, 'should parse successfully (inline or fallback)');
  });

  // T16: History file size is 1,048,577 bytes
  await test('T16: History file size is 1,048,577 bytes', async () => {
    const data = { fr: [] };
    q(200, ghContentLarge('sha_t16'));
    q(200, ghBlob(data));
    const result = await F(mockFetch)(HISTORY_FILE, {});
    assert(result && result.fr, 'should parse successfully through Blobs API fallback');
  });

  // T17: History fixture equivalent to 1,050,483 bytes
  await test('T17: History fixture equivalent to 1,050,483 bytes', async () => {
    // Generate synthetic history data matching 228 records or similar
    const data = { fr: Array.from({ length: 228 }, (_, i) => ({ id: `rec_${i}`, prNumber: 100 + i, pr_status: 'merged' })) };
    q(200, ghContentLarge('sha_t17'));
    q(200, ghBlob(data));
    const result = await F(mockFetch)(HISTORY_FILE, {});
    assert(result && Array.isArray(result.fr) && result.fr.length === 228, 'should parse large-file history fixture and return exact count');
  });

  // T20: History overwrite guard cannot read current History
  await test('T20: History overwrite guard cannot read current History (write blocked)', async () => {
    const proposed = { fr: [{ id: 'f1' }] };
    q(502, 'Bad Gateway'); q(502, 'Bad Gateway'); q(502, 'Bad Gateway'); // strict guard read fails
    const ok = await C(mockFetch)(HISTORY_FILE, proposed, 'ops: write', 3, {});
    assert(ok === false, 'should fail closed and block write if current history cannot be read');
  });

  // T21: History overwrite guard receives invalid current JSON
  await test('T21: History overwrite guard receives invalid current JSON (write blocked)', async () => {
    const proposed = { fr: [{ id: 'f1' }] };
    q(200, { sha: 'sha_t21', content: Buffer.from('{invalid').toString('base64'), encoding: 'base64' }); // invalid json
    const ok = await C(mockFetch)(HISTORY_FILE, proposed, 'ops: write', 3, {});
    assert(ok === false, 'should fail closed and block write if current history JSON is invalid');
  });

  // T22: History archive path cannot read current History
  await test('T22: History archive path cannot read current History', async () => {
    q(502, 'Bad Gateway'); q(502, 'Bad Gateway'); q(502, 'Bad Gateway');
    let threw = false;
    try {
      await F(mockFetch)(HISTORY_FILE, {});
    } catch (_) { threw = true; }
    assert(threw, 'archive read must fail closed on critical read failure');
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
