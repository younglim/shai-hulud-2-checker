#!/usr/bin/env node
import fs from 'fs';
import path from 'path';
import semver from 'semver';

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
  normalized = normalized.replace(/(<=|>=|=|<|>|~|\^)\s+/g, '$1');
  if (normalized.startsWith('=')) {
    normalized = normalized.slice(1);
  }
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

function findCompromised(versionIndex, compromisedList) {
  const findings = [];
  for (const entry of compromisedList) {
    const pkgName = entry.package;
    if (!pkgName) continue;
    const versions = versionIndex.get(pkgName);
    if (!versions) continue;

    const normalizedRange = normalizeRange(entry.versionRange);
    const isWildcard = normalizedRange === '*';
    const exactVersion = semver.valid(normalizedRange);
    const validRange =
      !isWildcard && !exactVersion ? semver.validRange(normalizedRange) : null;

    const matches = [...versions].filter(ver => {
      if (!semver.valid(ver)) return false;
      if (isWildcard) return true;
      if (exactVersion) return semver.eq(ver, normalizedRange);
      if (validRange) {
        return semver.satisfies(ver, normalizedRange, { includePrerelease: true });
      }
      return false;
    });

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
