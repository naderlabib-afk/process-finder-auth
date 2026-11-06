/**
 * test-approval-history-targeting.js
 * Unit tests for _planApprovedHistoryMediaUpdate (composite History targeting used by
 * the post-approval media-rewrite step of POST /api/admin/pr/approve).
 * Run with: node test-approval-history-targeting.js
 */
'use strict';

const { _planApprovedHistoryMediaUpdate: plan } = require('./server.js');

let _pass = 0, _fail = 0;
const _failures = [];
function assert(label, cond, extra = '') {
  if (cond) { _pass++; console.log(`  ✅ ${label}`); }
  else { _fail++; _failures.push(`${label}${extra ? ': ' + extra : ''}`); console.log(`  ❌ ${label}${extra ? ' — ' + extra : ''}`); }
}
const section = t => console.log(`\n── ${t} ─────────────────────────────────────`);
const clone = o => JSON.parse(JSON.stringify(o));

const STAGED = 'assets/process-media/_staged/mea/mea_x/aaaa.webp';
const FINAL  = 'assets/process-media/mea/mea_x/aaaa.webp';
const rec = (id, pr, st, html = '<p>old</p>') => ({
  id, type: 'update', pr_status: st, prNumber: pr, process: { id, issue: `i-${id}-${pr}`, process: html }
});
// approved (in-memory, already rewritten to final path) copy of a record
const approved = (id, pr, html = `<img src="${FINAL}">`) => rec(id, pr, 'merged', html);

section('1. Repeated ID across two PRs — only the current-PR record is targeted');
{
  const h = { mea: [rec('A', 10, 'merged'), rec('A', 20, 'merged', `<img src="${STAGED}">`)], fr: [rec('F', 1, 'merged')] };
  const before = clone(h);
  const upd = approved('A', 20);
  const r = plan(h, 'mea', [upd], 20, [STAGED]);
  assert('plan ok', r.ok === true, JSON.stringify(r));
  assert('resolved index is 1 (not 0)', r.ok && r.indexes.length === 1 && r.indexes[0] === 1);
  assert('older same-ID record deep-equal and same reference', r.ok && r.history.mea[0] === h.mea[0] && JSON.stringify(r.history.mea[0]) === JSON.stringify(before.mea[0]));
  assert('current record replaced', r.ok && r.history.mea[1] === upd);
  assert('count unchanged', r.ok && r.history.mea.length === 2);
  assert('other country bucket same reference', r.ok && r.history.fr === h.fr);
  assert('input History not mutated', JSON.stringify(h) === JSON.stringify(before));
}

section('2. PR #218-shaped fixture: two IDs, both repeated in older PRs');
{
  const h = { mea: [
    rec('S', 163, 'merged'), rec('X', 208, 'merged'), rec('S', 208, 'merged'),
    rec('O', 217, 'merged'), rec('S', 217, 'merged'),
    rec('O', 218, 'merged', `<img src="${STAGED}">`), rec('S', 218, 'merged')
  ] };
  const before = clone(h);
  const ups = [approved('O', 218), approved('S', 218, '<p>s</p>')];
  const r = plan(h, 'mea', ups, 218, [STAGED]);
  assert('plan ok', r.ok === true, JSON.stringify(r));
  assert('indexes are [5,6]', r.ok && r.indexes.join() === '5,6');
  assert('exactly two records changed', r.ok && r.history.mea.filter((x, i) => JSON.stringify(x) !== JSON.stringify(before.mea[i])).length === 2);
  assert('records for PR 163/208/217 deep-equal', r.ok && [0, 1, 2, 3, 4].every(i => JSON.stringify(r.history.mea[i]) === JSON.stringify(before.mea[i])));
  assert('exactly two records carry prNumber 218', r.ok && r.history.mea.filter(x => x.prNumber === 218).length === 2);
}

section('3. Unique ID — ordinary case');
{
  const h = { mea: [rec('U', 5, 'merged', `<img src="${STAGED}">`), rec('Z', 6, 'merged')] };
  const r = plan(h, 'mea', [approved('U', 5)], 5, [STAGED]);
  assert('ok, index 0', r.ok && r.indexes[0] === 0);
}

section('4. Zero match fails closed (no ID-only fallback)');
{
  const h = { mea: [rec('A', 10, 'merged'), rec('A', 30, 'merged')] };
  const r = plan(h, 'mea', [approved('A', 20)], 20, [STAGED]);
  assert('NO_MATCH', r.ok === false && r.code === 'NO_MATCH', JSON.stringify(r));
}

section('5. Ambiguous match fails closed (no "first match")');
{
  const h = { mea: [rec('A', 20, 'merged'), rec('A', 20, 'merged')] };
  const r = plan(h, 'mea', [approved('A', 20)], 20, [STAGED]);
  assert('AMBIGUOUS_MATCH', r.ok === false && r.code === 'AMBIGUOUS_MATCH', JSON.stringify(r));
  assert('detail has ids/indexes only', r.detail.includes('[0,1]') && !r.detail.includes('<img'));
}

section('6. Same id + PR, different status — not a target');
{
  const h = { mea: [rec('A', 20, 'pending_merge'), rec('A', 20, 'refused')] };
  const r = plan(h, 'mea', [approved('A', 20)], 20, [STAGED]);
  assert('NO_MATCH when none is merged', r.ok === false && r.code === 'NO_MATCH');
  const h2 = { mea: [rec('A', 20, 'refused'), rec('A', 20, 'merged'), rec('A', 20, 'pending_merge')] };
  const r2 = plan(h2, 'mea', [approved('A', 20)], 20, [STAGED]);
  assert('only the merged one is chosen', r2.ok && r2.indexes[0] === 1);
  assert('refused / pending siblings untouched', r2.ok && r2.history.mea[0] === h2.mea[0] && r2.history.mea[2] === h2.mea[2]);
}

section('7. Multiple records in one PR, one missing => all-or-nothing');
{
  const h = { mea: [rec('A', 20, 'merged'), rec('B', 99, 'merged')] };
  const r = plan(h, 'mea', [approved('A', 20), approved('B', 20)], 20, []);
  assert('NO_MATCH, nothing planned', r.ok === false && r.code === 'NO_MATCH');
}

section('8. Shared index — two approved entries with the same id');
{
  const h = { mea: [rec('A', 20, 'merged')] };
  const r = plan(h, 'mea', [approved('A', 20), approved('A', 20)], 20, []);
  assert('SHARED_INDEX', r.ok === false && r.code === 'SHARED_INDEX', JSON.stringify(r));
}

section('9. Verification: staged path still present / prNumber coercion / bad inputs');
{
  const h = { mea: [rec('A', 20, 'merged')] };
  const bad = rec('A', 20, 'merged', `<img src="${STAGED}">`);
  const r = plan(h, 'mea', [bad], 20, [STAGED]);
  assert('STAGED_PATH_REMAINS', r.ok === false && r.code === 'STAGED_PATH_REMAINS');
  const h2 = { mea: [rec('A', '20', 'merged')] };
  assert('string prNumber in History matched numerically', plan(h2, 'mea', [approved('A', 20)], 20, []).ok === true);
  assert('BUCKET_MISSING', plan({ fr: [] }, 'mea', [approved('A', 20)], 20, []).code === 'BUCKET_MISSING');
  assert('NO_APPROVED_ENTRIES', plan(h, 'mea', [], 20, []).code === 'NO_APPROVED_ENTRIES');
  assert('INVALID_PR_NUMBER', plan(h, 'mea', [approved('A', 20)], 'x', []).code === 'INVALID_PR_NUMBER');
  assert('INVALID_ENTRY', plan(h, 'mea', [{}], 20, []).code === 'INVALID_ENTRY');
}

section('10. Large History (>1 MiB) — invariants and performance');
{
  const filler = 'x'.repeat(8000);
  const h = { mea: [], es: Array.from({ length: 160 }, (_, i) => ({ ...rec('es' + i, 1, 'merged'), filler })) };
  for (let i = 0; i < 40; i++) h.mea.push(rec('ID' + (i % 5), 100 + i, 'merged'));
  h.mea.push(rec('ID1', 500, 'merged', `<img src="${STAGED}">`));
  const bytes = Buffer.byteLength(JSON.stringify(h));
  assert('fixture exceeds 1 MiB', bytes > 1048576, `bytes=${bytes}`);
  const t = Date.now();
  const r = plan(h, 'mea', [approved('ID1', 500)], 500, [STAGED]);
  assert('ok, resolves to last slot only', r.ok && r.indexes[0] === h.mea.length - 1);
  assert('older ID1 records (PRs 101,106,…) untouched', r.ok && h.mea.slice(0, 40).every((x, i) => r.history.mea[i] === x));
  assert('other bucket same reference', r.ok && r.history.es === h.es);
  assert('completes quickly (<500 ms)', Date.now() - t < 500);
}

console.log(`\n${'═'.repeat(60)}`);
console.log(`Results: ${_pass} passed, ${_fail} failed`);
if (_fail > 0) { console.log('Failures:'); _failures.forEach(f => console.log('  - ' + f)); process.exit(1); }
process.exit(0);
