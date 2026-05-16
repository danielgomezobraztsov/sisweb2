#!/usr/bin/env node
const { spawnSync } = require('child_process');
const path = require('path');

const scripts = [
  "syncNvd.js",
  "syncCisa.js",
  "syncMsrc.js",
  "syncOsv.js",
  "syncExploitDb.js"
];
let failed = 0;

for (const script of scripts) {
  console.log(`\nEjecutando ${script}`);
  const result = spawnSync(process.execPath, [path.join(__dirname, script)], { stdio: 'inherit' });
  if (result.status !== 0) {
    failed++;
    console.error(`${script} terminó con error`);
  }
}

if (failed) {
  console.error(`\nSync completada con ${failed} script(s) fallidos.`);
  process.exit(1);
}

console.log('\nSync completa de fuentes reales finalizada correctamente.');
