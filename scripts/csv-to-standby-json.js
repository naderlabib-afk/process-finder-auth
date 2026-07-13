/**
 * scripts/csv-to-standby-json.js
 *
 * Converts a standby CSV file (new template format) into the canonical
 * data/standby/{key}_{year}.json format consumed by the Standby API.
 *
 * Usage:
 *   node scripts/csv-to-standby-json.js <path-to-csv> <country-key> <year>
 *
 * Example:
 *   node scripts/csv-to-standby-json.js "../standby project/Italy_Standby_Daily_AI_Search_2026_SUPPORTED.csv" it 2026
 *
 * The CSV must have columns (in any order):
 *   Date, Day, Country, Standby_Name, Phone, Shift_Start, Shift_End, Coverage_Type
 *
 * Week structure assumption (confirmed for Italy 2026):
 *   - Period = Sun–Fri (6 consecutive days), Coverage_Type contains "standby"
 *   - Solo    = Saturday,                    Coverage_Type contains "saturday" or "solo"
 *
 * Output: data/standby/{key}_{year}.json
 */

'use strict';

const fs   = require('fs');
const path = require('path');

const [,, csvPath, countryKey, yearStr] = process.argv;

if (!csvPath || !countryKey || !yearStr) {
  console.error('Usage: node scripts/csv-to-standby-json.js <csv> <key> <year>');
  process.exit(1);
}

const year = parseInt(yearStr, 10);

// ── Parse CSV (handles quoted fields with commas) ─────────────────────────────
function parseCsvLine(line) {
  const fields = [];
  let cur = '', inQ = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"') { inQ = !inQ; }
    else if (c === ',' && !inQ) { fields.push(cur); cur = ''; }
    else { cur += c; }
  }
  fields.push(cur);
  return fields.map(f => f.trim());
}

const raw   = fs.readFileSync(path.resolve(csvPath), 'utf8');
const lines = raw.split(/\r?\n/).filter(l => l.trim());
const header = parseCsvLine(lines[0]).map(h => h.trim());

function col(row, name) {
  const idx = header.indexOf(name);
  return idx >= 0 ? (row[idx] || '').trim() : '';
}

const rows = lines.slice(1).map(l => parseCsvLine(l));

// ── Group rows into weeks ─────────────────────────────────────────────────────
// A week = all rows sharing the same Shift_Start value (the period anchor).
// Saturday rows have Shift_Start == their own Date (solo day).

const periodMap = {}; // periodStart → { period: {}, solo: {}, periodEnd: '' }

for (const row of rows) {
  const date         = col(row, 'Date');
  const coverage     = col(row, 'Coverage_Type').toLowerCase();
  const name         = col(row, 'Standby_Name');
  const phone        = col(row, 'Phone');
  const shiftStart   = col(row, 'Shift_Start').split(' ')[0]; // date part only
  const shiftEnd     = col(row, 'Shift_End').split(' ')[0];
  const day          = col(row, 'Day');

  const isSolo = coverage.includes('saturday') || coverage.includes('solo') || day.toLowerCase() === 'saturday';

  if (isSolo) {
    // solo entry — key by its own date (shiftStart == date for saturdays)
    // Store under the period that ends the day before (Friday)
    // Find matching period by locating the period that includes the Friday before this Saturday
    const satDate   = new Date(date + 'T00:00:00Z');
    const friDate   = new Date(satDate.getTime() - 86400000);
    const friStr    = friDate.toISOString().slice(0, 10);
    // find period whose end = friStr
    const entry = Object.values(periodMap).find(e => e.periodEnd === friStr);
    if (entry) {
      entry.solo = { date, name, phone, phone2: '', note: '' };
    } else {
      // Fallback: attach to nearest period
      periodMap[date] = periodMap[date] || { periodStart: date, periodEnd: date, period: null, solo: null };
      periodMap[date].solo = { date, name, phone, phone2: '', note: '' };
    }
  } else {
    // period entry
    if (!periodMap[shiftStart]) {
      periodMap[shiftStart] = { periodStart: shiftStart, periodEnd: shiftEnd, period: null, solo: null };
    }
    if (!periodMap[shiftStart].period) {
      periodMap[shiftStart].period = { name, phone, phone2: '', note: '', consecutiveWarning: false };
    }
    // refresh end date in case rows differ
    periodMap[shiftStart].periodEnd = shiftEnd;
  }
}

// ── Build weeks array sorted by periodStart ───────────────────────────────────
const weeks = Object.values(periodMap)
  .filter(e => e.period) // skip orphan solo entries
  .sort((a, b) => a.periodStart.localeCompare(b.periodStart))
  .map(e => ({
    periodStart: e.periodStart,
    periodEnd:   e.periodEnd,
    period:      e.period,
    solo:        e.solo || null
  }));

// ── Collect unique agents ──────────────────────────────────────────────────────
const agentMap = {};
for (const w of weeks) {
  if (w.period?.name) agentMap[w.period.name] = { name: w.period.name, phone: w.period.phone, phone2: '' };
  if (w.solo?.name)   agentMap[w.solo.name]   = { name: w.solo.name,   phone: w.solo.phone,   phone2: '' };
}
const agents = Object.values(agentMap).sort((a, b) => a.name.localeCompare(b.name));

// ── Assemble final JSON ────────────────────────────────────────────────────────
const countryName = col(rows[0], 'Country') || countryKey.toUpperCase();

const output = {
  country:    countryName,
  countryKey: countryKey.toLowerCase(),
  year,
  weekStart:  'sunday',
  soloDay:    'saturday',
  updatedAt:  new Date().toISOString(),
  updatedBy:  'seed-script',
  agents,
  weeks
};

const outDir  = path.join(__dirname, '..', 'data', 'standby');
const outFile = path.join(outDir, `${countryKey.toLowerCase()}_${year}.json`);
fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(outFile, JSON.stringify(output, null, 2), 'utf8');

console.log(`[OK] ${weeks.length} weeks written → ${outFile}`);
console.log(`     ${agents.length} agents: ${agents.map(a => a.name).join(', ')}`);
