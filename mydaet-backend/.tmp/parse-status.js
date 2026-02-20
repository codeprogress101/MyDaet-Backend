const fs = require('fs');
const text = fs.readFileSync('.tmp/functions-list-debug.log', 'utf8');
const marker = 'GET https://cloudfunctions.googleapis.com/v1/projects/mydaet/locations/-/functions ';
const idx = text.indexOf(marker);
if (idx < 0) throw new Error('marker not found');
const start = text.indexOf('{\"functions\":[', idx);
if (start < 0) throw new Error('json start not found');
let depth = 0;
let end = -1;
for (let i = start; i < text.length; i++) {
  const ch = text[i];
  if (ch === '{') depth++;
  if (ch === '}') {
    depth--;
    if (depth === 0) { end = i; break; }
  }
}
if (end < 0) throw new Error('json end not found');
const data = JSON.parse(text.slice(start, end + 1));
const byStatus = {};
for (const fn of data.functions || []) {
  const status = fn.status || 'UNKNOWN';
  if (!byStatus[status]) byStatus[status] = [];
  byStatus[status].push(fn.name.split('/').pop());
}
for (const status of Object.keys(byStatus).sort()) {
  console.log(\n:);
  for (const name of byStatus[status].sort()) {
    console.log(- );
  }
}
