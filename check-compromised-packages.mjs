#!/usr/bin/env node
import fs from 'fs';
import path from 'path';

const FLAG_MAP = new Map();
for (let i = 2; i < process.argv.length; i += 1) {
  const flag = process.argv[i];
  const value = process.argv[i + 1];
  if (!flag?.startsWith('--')) continue;
  FLAG_MAP.set(flag.slice(2), value && !value.startsWith('--') ? value : undefined);
  if (value && !value.startsWith('--')) i += 1;
}

const DEFAULT_LOCK = path.resolve(process.cwd(), 'package-lock.json');
const DEFAULT_CSV =
  process.env.COMPROMISED_PACKAGES_CSV ||
  path.resolve(process.cwd(), 'shai-hulud-2-packages.csv');

const lockPath = path.resolve(FLAG_MAP.get('lock') || DEFAULT_LOCK);
const csvPath = path.resolve(FLAG_MAP.get('csv') || DEFAULT_CSV);

function ensureFileExists(filePath, descriptor) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`Missing ${descriptor} at ${filePath}`);
  }
}

function parseCsv(filePath) {
  const contents = fs.readFileSync(filePath, 'utf8');
  const raw = contents.replace(/^\uFEFF/, '').trim();
  if (!raw) return [];
  const lines = raw.split(/\r?\n/).filter(line => line && !line.trim().startsWith('#'));
  if (!lines.length) return [];

  const headers = lines
    .shift()
    .split(',')
    .map(h => h.trim().toLowerCase());
  return lines.map(line => {
    const cells = line.split(',').map(cell => cell.trim());
    return headers.reduce((acc, header, idx) => {
      acc[header] = cells[idx] ?? '';
      return acc;
    }, {});
  });
}

function normalizeRange(range = '*') {
  let normalized = (range || '*').trim();
  if (!normalized) return '*';
  // Remove whitespace around operators but keep the operators themselves
  normalized = normalized.replace(/(<=|>=|=|<|>|~|\^)\s+/g, '$1');
  return normalized || '*';
}

function deriveNameFromKey(pkgKey = '') {
  const normalized = pkgKey.replace(/\\/g, '/');
  const markers = ['/node_modules/', '/node_modbodules/', 'node_modules/', 'node_modbodules/'];
  for (const marker of markers) {
    const idx = normalized.lastIndexOf(marker);
    if (idx >= 0) {
      const fragment = normalized.slice(idx + marker.length);
      if (fragment) return fragment;
    }
  }
  return undefined;
}

function addToVersionIndex(versionIndex, pkgName, version) {
  const name = pkgName?.trim();
  const ver = version?.trim();
  if (!name || !ver) return;
  if (!versionIndex.has(name)) versionIndex.set(name, new Set());
  versionIndex.get(name).add(ver);
}

function collectDependencyTree(dependencies, versionIndex) {
  if (!dependencies || typeof dependencies !== 'object') return;
  for (const [depName, depMeta] of Object.entries(dependencies)) {
    addToVersionIndex(versionIndex, depName, depMeta?.version);
    collectDependencyTree(depMeta?.dependencies, versionIndex);
  }
}

function buildVersionIndex(lockJson) {
  const packagesSection = lockJson?.packages;
  const versionIndex = new Map();

  if (packagesSection && typeof packagesSection === 'object') {
    for (const [pkgPath, pkg] of Object.entries(packagesSection)) {
      const pkgName = pkg?.name || deriveNameFromKey(pkgPath);
      addToVersionIndex(versionIndex, pkgName, pkg?.version);
    }
  }

  collectDependencyTree(lockJson?.dependencies, versionIndex);

  if (!versionIndex.size) {
    throw new Error('Invalid package-lock.json: unable to index dependencies.');
  }

  return versionIndex;
}

function tokenizeVersion(version = '') {
  return String(version)
    .split(/[.\-]/)
    .map(part => (/^\d+$/.test(part) ? Number(part) : part));
}

function compareVersions(a = '', b = '') {
  const left = tokenizeVersion(a);
  const right = tokenizeVersion(b);
  const len = Math.max(left.length, right.length);
  for (let i = 0; i < len; i += 1) {
    // Treat missing parts as 0 for numbers, but handle pre-release logic if needed.
    // For simple compromised checks, 0 padding usually suffices.
    const segA = left[i] ?? (typeof right[i] === 'number' ? 0 : '');
    const segB = right[i] ?? (typeof left[i] === 'number' ? 0 : '');
    
    if (typeof segA === 'number' && typeof segB === 'number') {
      if (segA !== segB) return segA - segB;
      continue;
    }
    const strA = String(segA);
    const strB = String(segB);
    if (strA === strB) continue;
    return strA > strB ? 1 : -1;
  }
  return 0;
}

function parseConstraint(raw = '') {
  const trimmed = raw.trim();
  if (!trimmed || trimmed === '*') return { operator: '*' };
  // Capture optional operator (including =) and the version
  const match = trimmed.match(/^(>=|<=|>|<|=)?\s*v?(.+)$/);
  if (!match) return null;
  const [, operator, version] = match;
  if (!version) return null;
  return { operator: operator || '=', version };
}

function satisfiesConstraint(version, constraint) {
  if (!constraint) return false;
  if (constraint.operator === '*') return true;
  const cmp = compareVersions(version, constraint.version);
  switch (constraint.operator) {
    case '=':
    case undefined:
      return cmp === 0;
    case '>':
      return cmp > 0;
    case '>=':
      return cmp >= 0;
    case '<':
      return cmp < 0;
    case '<=':
      return cmp <= 0;
    default:
      return false;
  }
}

function findCompromised(versionIndex, compromisedList) {
  const findings = [];
  for (const entry of compromisedList) {
    const pkgName = entry.package;
    if (!pkgName) continue;
    const versions = versionIndex.get(pkgName);
    if (!versions) continue;

    const rawRange = entry.versionrange ?? entry.versionRange ?? entry.version ?? '*';
    const normalizedRange = normalizeRange(rawRange);
    const constraints =
      normalizedRange === '*'
        ? [{ operator: '*' }]
        : normalizedRange
            .split('||')
            .map(part => parseConstraint(part))
            .filter(Boolean);

    if (!constraints.length) constraints.push({ operator: '*' });

    const matches = [...versions].filter(ver =>
      constraints.some(constraint => satisfiesConstraint(ver, ver && constraint)),
    );

    if (matches.length) {
      findings.push({
        package: pkgName,
        versionRange: normalizedRange,
        versions: matches,
        notes: entry.notes || '',
      });
    }
  }
  return findings;
}

function logFindings(findings) {
  console.error('\nCompromised packages detected:\n');
  findings.forEach(finding => {
    console.error(
      `• ${finding.package} matched ${finding.versionRange} -> ${finding.versions.join(', ')}${
        finding.notes ? ` (${finding.notes})` : ''
      }`,
    );
  });
  console.error('\nFailing with exit code 1 so the pipeline can react.\n');
}

(async function main() {
  try {
    ensureFileExists(lockPath, 'package-lock.json');
    ensureFileExists(csvPath, 'compromised package CSV');

    const compromisedList = parseCsv(csvPath);
    if (!compromisedList.length) {
      console.log(`No rows found in ${csvPath}, nothing to verify.`);
      return;
    }

    const lockJson = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
    const versionIndex = buildVersionIndex(lockJson);
    const findings = findCompromised(versionIndex, compromisedList);

    if (findings.length) {
      logFindings(findings);
      process.exitCode = 1;
    } else {
      console.log('No compromised dependencies detected ✅');
    }
  } catch (err) {
    console.error(`Verification failed: ${err.message}`);
    process.exitCode = 2;
  }
})();
