/**
 * test-rich-content-v1.js
 * Unit tests for Rich Process Content V1.
 * Uses the real sanitize-html-powered functions imported from server.js.
 * Run with: node test-rich-content-v1.js
 */

'use strict';

// ─── Import from server.js (require.main guard prevents server start) ─────────

const {
  sanitizeProcessHtml,
  _safeMediaSrc,
  _safeLinkHref,
  _isValidMediaPath,
  _isValidStagedMediaPath,
  _isValidFinalMediaPath,
  _isStagedPath,
  _isFinalPath,
  _stagedToFinalPath,
  _extractMediaRefs,
  _isAllowedPRPath,
  validateProcessEntry,
  MEDIA_STAGED_PREFIX,
  MEDIA_FINAL_PREFIX,
  MEDIA_MAX_IMAGES_PER_PROCESS,
  MEDIA_MAX_DISPLAY_WIDTH,
  MEDIA_MIN_DISPLAY_WIDTH,
  MEDIA_DEFAULT_DISPLAY_WIDTH
} = require('./server.js');

// ─── Test harness ─────────────────────────────────────────────────────────────

let _pass = 0;
let _fail = 0;
const _failures = [];

function assert(label, condition, extra = '') {
  if (condition) {
    _pass++;
    console.log(`  ✅ ${label}`);
  } else {
    _fail++;
    _failures.push(`${label}${extra ? ': ' + extra : ''}`);
    console.log(`  ❌ ${label}${extra ? ' — ' + extra : ''}`);
  }
}

function section(title) {
  console.log(`\n── ${title} ─────────────────────────────────────`);
}

// ─── A. Sanitization (uses real sanitize-html parser) ─────────────────────────

section('A. Sanitization — script injection blocked');
{
  const r = sanitizeProcessHtml('<p>Hello<script>alert(1)</script></p>');
  assert('script tag removed', !r.includes('<script'));
  assert('alert not in output', !r.includes('alert(1)'));
  assert('paragraph preserved', r.includes('<p>'));
}

section('A. Sanitization — inline event handlers blocked');
{
  const r = sanitizeProcessHtml('<p onclick="alert(1)">Text</p>');
  assert('onclick removed', !r.includes('onclick'));
  assert('paragraph tag kept', r.includes('<p>'));
  assert('text preserved', r.includes('Text'));
}

section('A. Sanitization — onerror on img blocked');
{
  const r = sanitizeProcessHtml('<img src="assets/process-media/fr/abc/11111111-2222-3333-4444-555555555555.webp" onerror="alert(1)">');
  assert('onerror removed', !r.includes('onerror'));
  assert('img kept (valid internal src)', r.includes('<img'));
}

section('A. Sanitization — onload on img blocked');
{
  const r = sanitizeProcessHtml('<img src="assets/process-media/fr/p1/11111111-2222-3333-4444-555555555555.webp" onload="stealCookies()">');
  assert('onload removed', !r.includes('onload='));
  assert('img kept (valid internal src)', r.includes('<img'));
}

section('A. Sanitization — iframe blocked entirely (subtree stripped)');
{
  const r = sanitizeProcessHtml('<p>Text</p><iframe src="//evil.com"></iframe>');
  assert('iframe removed', !r.includes('<iframe'));
  assert('paragraph preserved', r.includes('Text'));
}

section('A. Sanitization — style tag stripped (subtree)');
{
  const r = sanitizeProcessHtml('<style>body{display:none}</style><p>Visible</p>');
  assert('style tag removed', !r.includes('<style'));
  assert('css content not in output', !r.includes('display:none'));
  assert('paragraph kept', r.includes('Visible'));
}

section('A. Sanitization — javascript: link blocked');
{
  const r = sanitizeProcessHtml('<a href="javascript:alert(1)">Click</a>');
  assert('javascript: href removed', !r.includes('javascript:'));
  assert('a tag kept but no javascript href', r.includes('<a'));
}

section('A. Sanitization — data: URI image blocked');
{
  const dataUri = 'data:image/png;base64,iVBORw0KGgo=';
  const r = sanitizeProcessHtml(`<img src="${dataUri}">`);
  assert('data: img element dropped', !r.includes('<img'));
  assert('data: URI not in output', !r.includes('data:image'));
}

section('A. Sanitization — external image URL blocked');
{
  const r = sanitizeProcessHtml('<img src="https://evil.com/bad.png">');
  assert('external img element dropped', !r.includes('<img'));
}

section('A. Sanitization — SVG content blocked (subtree stripped)');
{
  const r = sanitizeProcessHtml('<svg><script>alert(1)</script><rect fill="red"/></svg>');
  assert('svg removed', !r.includes('<svg'));
  assert('script in svg removed', !r.includes('<script'));
  assert('rect removed', !r.includes('<rect'));
}

section('A. Sanitization — uppercase SCRIPT tag blocked (parser handles case)');
{
  const r = sanitizeProcessHtml('<P>Text<SCRIPT>evil()</SCRIPT></P>');
  assert('uppercase SCRIPT removed', !r.includes('SCRIPT') && !r.includes('<script'));
  assert('evil() not in output', !r.includes('evil()'));
}

section('A. Sanitization — nested injection attempt (htmlparser2 handles malformed)');
{
  // Attempts to confuse regex-based sanitizers using attribute nesting trick
  const r = sanitizeProcessHtml('<img src=x onerror=alert(1)//>');
  assert('onerror not in output', !r.includes('onerror'));
  // External img (src=x is not a valid internal path) should be dropped
  assert('invalid-src img dropped', !r.includes('<img') || !r.includes('src="x"'));
}

section('A. Sanitization — internal media src allowed');
{
  const src = 'assets/process-media/fr/fr_20260101_0000_001/11111111-2222-3333-4444-555555555555.webp';
  const r = sanitizeProcessHtml(`<img src="${src}" data-width="600">`);
  assert('img kept', r.includes('<img'));
  assert('src preserved', r.includes(src));
  assert('data-width preserved', r.includes('data-width="600"'));
  assert('loading=lazy added', r.includes('loading="lazy"'));
}

section('A. Sanitization — staged media src allowed (Buffer preview)');
{
  const src = 'assets/process-media/_staged/fr/p1/11111111-2222-3333-4444-555555555555.webp';
  const r = sanitizeProcessHtml(`<img src="${src}" data-width="500">`);
  assert('staged img kept', r.includes('<img'));
  assert('staged src preserved', r.includes(src));
}

section('A. Sanitization — img data-width clamped to [200, 800]');
{
  const src = 'assets/process-media/fr/p1/11111111-2222-3333-4444-555555555555.webp';
  const r1 = sanitizeProcessHtml(`<img src="${src}" data-width="1000">`);
  assert('data-width 1000 stripped (over max)', !r1.includes('data-width="1000"'));
  const r2 = sanitizeProcessHtml(`<img src="${src}" data-width="100">`);
  assert('data-width 100 stripped (under min)', !r2.includes('data-width="100"'));
  const r3 = sanitizeProcessHtml(`<img src="${src}" data-width="400">`);
  assert('data-width 400 preserved', r3.includes('data-width="400"'));
  const r4 = sanitizeProcessHtml(`<img src="${src}" data-width="200">`);
  assert('data-width 200 (min) preserved', r4.includes('data-width="200"'));
  const r5 = sanitizeProcessHtml(`<img src="${src}" data-width="800">`);
  assert('data-width 800 (max) preserved', r5.includes('data-width="800"'));
}

section('A. Sanitization — allowed rich tags preserved');
{
  const input = '<p><strong>Bold</strong> and <em>italic</em></p><ul><li>item</li></ul><ol><li>ordered</li></ol>';
  const r = sanitizeProcessHtml(input);
  assert('strong preserved', r.includes('<strong>'));
  assert('em preserved', r.includes('<em>'));
  assert('ul/li preserved', r.includes('<ul>') && r.includes('<li>'));
  assert('ol preserved', r.includes('<ol>'));
}

section('A. Sanitization — https link allowed with safe attrs');
{
  const r = sanitizeProcessHtml('<a href="https://ibm.com">IBM</a>');
  assert('https link kept', r.includes('href="https://ibm.com"'));
  assert('rel=noopener added', r.includes('rel="noopener noreferrer"'));
  assert('target=_blank added', r.includes('target="_blank"'));
}

section('A. Sanitization — http link allowed');
{
  const r = sanitizeProcessHtml('<a href="http://internal.example.com/page">link</a>');
  assert('http link kept', r.includes('href="http://internal.example.com/page"'));
}

section('A. Sanitization — mailto link allowed');
{
  const r = sanitizeProcessHtml('<a href="mailto:help@example.com">contact</a>');
  assert('mailto link kept', r.includes('href="mailto:help@example.com"'));
}

section('A. Sanitization — style attributes stripped from all tags');
{
  const r = sanitizeProcessHtml('<p style="color:red;background:url(evil)">text</p>');
  assert('style attribute removed from p', !r.includes('style='));
}

section('A. Sanitization — class and id attributes stripped');
{
  const r = sanitizeProcessHtml('<p class="foo" id="bar">text</p>');
  assert('class removed', !r.includes('class='));
  assert('id removed', !r.includes('id='));
}

section('A. Sanitization — unknown tags stripped but text kept (discard mode)');
{
  const r = sanitizeProcessHtml('<p>Normal <custom-tag>kept text</custom-tag></p>');
  assert('custom tag removed', !r.includes('<custom-tag'));
  assert('inner text preserved', r.includes('kept text'));
}

section('A. Sanitization — legacy plain text passes through unchanged');
{
  const plainText = 'Check the fan speed.\nReplace if below 2000 RPM.';
  const r = sanitizeProcessHtml(plainText);
  assert('plain text returned unchanged', r === plainText);
}

section('A. Sanitization — empty/null/undefined handled');
{
  assert('empty string returns ""', sanitizeProcessHtml('') === '');
  assert('null returns ""', sanitizeProcessHtml(null) === '');
  assert('undefined returns ""', sanitizeProcessHtml(undefined) === '');
  assert('whitespace-only returns whitespace', sanitizeProcessHtml('   ').trim() === '');
}

// ─── B. _safeMediaSrc ─────────────────────────────────────────────────────────

section('B. _safeMediaSrc — valid paths');
{
  assert('final path allowed',   _safeMediaSrc('assets/process-media/fr/p1/abc.webp') !== null);
  assert('staged path allowed',  _safeMediaSrc('assets/process-media/_staged/fr/p1/abc.webp') !== null);
  assert('root-relative allowed', _safeMediaSrc('/assets/process-media/fr/p1/abc.webp') !== null);
}

section('B. _safeMediaSrc — blocked sources');
{
  assert('null rejected',        _safeMediaSrc(null) === null);
  assert('empty rejected',       _safeMediaSrc('') === null);
  assert('data: rejected',       _safeMediaSrc('data:image/png;base64,abc') === null);
  assert('javascript: rejected', _safeMediaSrc('javascript:alert(1)') === null);
  assert('https external rejected', _safeMediaSrc('https://evil.com/img.png') === null);
  assert('relative path rejected',  _safeMediaSrc('../secret/file.webp') === null);
}

// ─── C. Media path validation ─────────────────────────────────────────────────

section('C. _isValidMediaPath — accepts valid paths');
{
  assert('final webp path',   _isValidMediaPath('assets/process-media/fr/p1/img.webp'));
  assert('staged webp path',  _isValidMediaPath('assets/process-media/_staged/fr/p1/img.webp'));
}

section('C. _isValidMediaPath — rejects unsafe paths');
{
  assert('path traversal blocked',   !_isValidMediaPath('assets/process-media/fr/../secret'));
  assert('external URL blocked',     !_isValidMediaPath('https://evil.com/img.webp'));
  assert('data: blocked',            !_isValidMediaPath('data:image/png;base64,abc'));
  assert('empty blocked',            !_isValidMediaPath(''));
  assert('null blocked',             !_isValidMediaPath(null));
  assert('non-media path blocked',   !_isValidMediaPath('data/processes/fr.json'));
  assert('non-webp extension blocked', !_isValidMediaPath('assets/process-media/fr/p1/img.png'));
}

section('C. _isValidStagedMediaPath — structure validation');
{
  const valid = 'assets/process-media/_staged/fr/proc-123/11111111-2222-3333-4444-555555555555.webp';
  assert('valid staged path accepted', _isValidStagedMediaPath(valid));
  assert('final path rejected by staged validator', !_isValidStagedMediaPath('assets/process-media/fr/p1/abc123.webp'));
  assert('path traversal rejected', !_isValidStagedMediaPath('assets/process-media/_staged/fr/../secret/a.webp'));
  assert('non-uuid filename rejected', !_isValidStagedMediaPath('assets/process-media/_staged/fr/p1/evil.webp'));
}

section('C. _isValidFinalMediaPath — structure validation');
{
  const valid = 'assets/process-media/fr/proc-123/11111111-2222-3333-4444-555555555555.webp';
  assert('valid final path accepted', _isValidFinalMediaPath(valid));
  assert('staged path rejected by final validator', !_isValidFinalMediaPath('assets/process-media/_staged/fr/p1/11111111-2222-3333-4444-555555555555.webp'));
  assert('non-uuid filename rejected', !_isValidFinalMediaPath('assets/process-media/fr/p1/myimage.webp'));
}

section('C. _isStagedPath / _isFinalPath');
{
  assert('staged path is staged',   _isStagedPath('assets/process-media/_staged/fr/p1/a.webp'));
  assert('final path is not staged', !_isStagedPath('assets/process-media/fr/p1/a.webp'));
  assert('final path is final',     _isFinalPath('assets/process-media/fr/p1/a.webp'));
  assert('staged path is not final', !_isFinalPath('assets/process-media/_staged/fr/p1/a.webp'));
}

section('C. _stagedToFinalPath — path promotion');
{
  const staged = 'assets/process-media/_staged/fr/p1/11111111-2222-3333-4444-555555555555.webp';
  const final  = 'assets/process-media/fr/p1/11111111-2222-3333-4444-555555555555.webp';
  assert('staged → final conversion', _stagedToFinalPath(staged) === final);
  assert('final path unchanged by stagedToFinal', _stagedToFinalPath(final) === final);
}

section('C. _extractMediaRefs');
{
  const html = '<p>'
    + '<img src="assets/process-media/fr/p1/a.webp" loading="lazy">'
    + '<img src="assets/process-media/fr/p1/b.webp">'
    + '</p>';
  const refs = _extractMediaRefs(html);
  assert('extracts 2 refs', refs.size === 2);
  assert('first ref correct',  refs.has('assets/process-media/fr/p1/a.webp'));
  assert('second ref correct', refs.has('assets/process-media/fr/p1/b.webp'));
}

section('C. _extractMediaRefs — external/staged refs extracted correctly');
{
  const html = '<p>'
    + '<img src="assets/process-media/_staged/fr/p1/c.webp">'
    + '<img src="https://evil.com/bad.png">'
    + '<img src="assets/process-media/fr/p1/ok.webp">'
    + '</p>';
  const refs = _extractMediaRefs(html);
  assert('staged ref included', refs.has('assets/process-media/_staged/fr/p1/c.webp'));
  assert('final ref included',  refs.has('assets/process-media/fr/p1/ok.webp'));
  // Note: _extractMediaRefs captures all assets/process-media/ srcs; external https src is NOT captured
  assert('external https not captured', !refs.has('https://evil.com/bad.png'));
}

// ─── D. _isAllowedPRPath ──────────────────────────────────────────────────────

section('D. _isAllowedPRPath — process data files');
{
  assert('fr.json allowed',   _isAllowedPRPath('data/processes/fr.json'));
  assert('de.json allowed',   _isAllowedPRPath('data/processes/de.json'));
  assert('subdirectory blocked', !_isAllowedPRPath('data/processes/subdir/fr.json'));
  assert('non-json blocked',  !_isAllowedPRPath('data/processes/fr.yaml'));
  assert('server.js blocked', !_isAllowedPRPath('server.js'));
  assert('.env blocked',       !_isAllowedPRPath('.env'));
}

section('D. _isAllowedPRPath — final media files (UUID.webp)');
{
  const validFinal = 'assets/process-media/fr/proc-123/11111111-2222-3333-4444-555555555555.webp';
  assert('valid final media allowed', _isAllowedPRPath(validFinal));
  assert('non-webp blocked',  !_isAllowedPRPath('assets/process-media/fr/p1/img.png'));
  assert('path traversal blocked', !_isAllowedPRPath('assets/process-media/fr/../etc/passwd.webp'));
  assert('non-uuid filename blocked', !_isAllowedPRPath('assets/process-media/fr/p1/evil.webp'));
  assert('too-deep path blocked', !_isAllowedPRPath('assets/process-media/fr/p1/sub/11111111-2222-3333-4444-555555555555.webp'));
}

section('D. _isAllowedPRPath — staged media files');
{
  const validStaged = 'assets/process-media/_staged/fr/proc-123/11111111-2222-3333-4444-555555555555.webp';
  assert('valid staged media allowed', _isAllowedPRPath(validStaged));
  assert('staged non-webp blocked', !_isAllowedPRPath('assets/process-media/_staged/fr/p1/img.jpg'));
  assert('staged non-uuid blocked', !_isAllowedPRPath('assets/process-media/_staged/fr/p1/myfile.webp'));
}

// ─── E. validateProcessEntry (MOD-5 enforcement) ─────────────────────────────

section('E. validateProcessEntry — basic field validation');
{
  assert('null rejected', validateProcessEntry(null) !== null);
  assert('missing category rejected', validateProcessEntry({ issue: 'x', process: 'y' }) !== null);
  assert('missing issue rejected', validateProcessEntry({ category: 'c', process: 'y' }) !== null);
  assert('missing process rejected', validateProcessEntry({ category: 'c', issue: 'x' }) !== null);
  assert('valid plain text entry accepted', validateProcessEntry({ category: 'Hardware', issue: 'Fan noise', process: 'Replace fan.' }) === null);
}

section('E. validateProcessEntry — MOD-5 max 3 images enforced');
{
  const src = (n) => `assets/process-media/fr/p1/${n}1111111-2222-3333-4444-555555555555.webp`;
  const make3 = `<p><img src="${src('a')}" data-width="600"><img src="${src('b')}" data-width="600"><img src="${src('c')}" data-width="600"></p>`;
  const make4 = make3 + `<img src="${src('d')}" data-width="600">`;

  assert('3 images accepted',  validateProcessEntry({ category: 'c', issue: 'i', process: make3 }) === null);
  const err4 = validateProcessEntry({ category: 'c', issue: 'i', process: make4 });
  assert('4 images rejected',  err4 !== null);
  assert('4-image error mentions Maximum 3', err4 && err4.includes('Maximum 3'));
}

section('E. validateProcessEntry — MOD-5 external src blocked after sanitization');
{
  // After sanitizer, external img would be dropped → no img → passes count check
  // But if somehow an external src survived (belt-and-suspenders regex check):
  const withExternalSrc = '<p>text</p>';
  // validateProcessEntry sanitizes first then checks — external imgs dropped by sanitizer
  assert('plain-html-no-img passes', validateProcessEntry({ category: 'c', issue: 'i', process: withExternalSrc }) === null);
}

section('E. validateProcessEntry — sanitized content accepted');
{
  const html = '<p><strong>Step 1</strong>: Turn off the machine.</p>';
  assert('rich text entry accepted', validateProcessEntry({ category: 'Hardware', issue: 'Startup', process: html }) === null);
}

// ─── F. Constants validation ──────────────────────────────────────────────────

section('F. Constants — governance values');
{
  assert('MEDIA_MAX_IMAGES_PER_PROCESS === 3',   MEDIA_MAX_IMAGES_PER_PROCESS === 3);
  assert('MEDIA_MAX_DISPLAY_WIDTH === 800',       MEDIA_MAX_DISPLAY_WIDTH === 800);
  assert('MEDIA_MIN_DISPLAY_WIDTH === 200',       MEDIA_MIN_DISPLAY_WIDTH === 200);
  assert('MEDIA_DEFAULT_DISPLAY_WIDTH === 600',   MEDIA_DEFAULT_DISPLAY_WIDTH === 600);
  assert('MEDIA_STAGED_PREFIX correct', MEDIA_STAGED_PREFIX === 'assets/process-media/_staged/');
  assert('MEDIA_FINAL_PREFIX correct',  MEDIA_FINAL_PREFIX  === 'assets/process-media/');
}

// ─── G. Backward compatibility — legacy plain text ────────────────────────────

section('G. Backward compatibility — plain text process renders unchanged');
{
  const plain = 'Step 1: Turn off the server.\nStep 2: Replace the drive.';
  const r = sanitizeProcessHtml(plain);
  assert('plain text returned unchanged', r === plain);
}

section('G. Backward compatibility — validateProcessEntry with plain text');
{
  const err = validateProcessEntry({ category: 'IT', issue: 'Drive replacement', process: 'Shut down.\nReplace drive.\nReboot.' });
  assert('plain text entry accepted', err === null);
}

// ─── H. Copy-to-country path rewrite simulation ───────────────────────────────

section('H. Copy-to-country — path rewrite');
{
  const srcHtml = '<p><img src="assets/process-media/fr/p1/11111111-2222-3333-4444-555555555555.webp" data-width="600" loading="lazy"></p>';
  const pathMap = {
    'assets/process-media/fr/p1/11111111-2222-3333-4444-555555555555.webp':
    'assets/process-media/_staged/de/p2/22222222-3333-4444-5555-666666666666.webp'
  };
  let newHtml = srcHtml;
  Object.entries(pathMap).forEach(([sp, dp]) => {
    newHtml = newHtml.split(`src="${sp}"`).join(`src="${dp}"`);
  });
  assert('src rewritten to destination staged path', newHtml.includes('assets/process-media/_staged/de/p2/22222222'));
  assert('source path no longer present', !newHtml.includes('assets/process-media/fr/p1/11111111'));
  assert('data-width preserved', newHtml.includes('data-width="600"'));
}

// ─── I. Staged-to-final promotion path rewrite ────────────────────────────────

section('I. Staged-to-final — HTML src rewrite on approval');
{
  const stagedSrc = 'assets/process-media/_staged/fr/p1/11111111-2222-3333-4444-555555555555.webp';
  const finalSrc  = 'assets/process-media/fr/p1/11111111-2222-3333-4444-555555555555.webp';

  let html = `<p><img src="${stagedSrc}" data-width="600" loading="lazy"></p>`;
  html = html.split(`src="${stagedSrc}"`).join(`src="${finalSrc}"`);

  assert('staged src rewritten to final', html.includes(`src="${finalSrc}"`));
  assert('staged src no longer present',  !html.includes('_staged/'));
  assert('data-width preserved after rewrite', html.includes('data-width="600"'));
}

// ─── J. _safeLinkHref ─────────────────────────────────────────────────────────

section('J. _safeLinkHref — allowed protocols');
{
  assert('https allowed',  _safeLinkHref('https://ibm.com') === 'https://ibm.com');
  assert('http allowed',   _safeLinkHref('http://internal.lan') === 'http://internal.lan');
  assert('mailto allowed', _safeLinkHref('mailto:help@ibm.com') === 'mailto:help@ibm.com');
}

section('J. _safeLinkHref — blocked protocols');
{
  assert('javascript: blocked',   _safeLinkHref('javascript:alert(1)') === null);
  assert('data: blocked',         _safeLinkHref('data:text/html,<script>') === null);
  assert('vbscript: blocked',     _safeLinkHref('vbscript:MsgBox(1)') === null);
  assert('null handled',          _safeLinkHref(null) === null);
  assert('empty string blocked',  _safeLinkHref('') === null);
  assert('relative path blocked', _safeLinkHref('../evil') === null);
}

// ─── Summary ──────────────────────────────────────────────────────────────────

console.log(`\n${'─'.repeat(60)}`);
console.log(`Tests: ${_pass + _fail} total  |  ✅ ${_pass} passed  |  ${_fail > 0 ? '❌' : '✅'} ${_fail} failed`);
if (_failures.length) {
  console.log('\nFailed tests:');
  _failures.forEach(f => console.log(`  ✗ ${f}`));
  process.exit(1);
} else {
  console.log('\n✅ All tests passed.');
  process.exit(0);
}
