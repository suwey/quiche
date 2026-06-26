#!/usr/bin/env node
import { readdir, readFile, writeFile } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { argv, exit } from 'node:process';

const DRY_RUN = argv.includes('--dry-run');
const ROOT = new URL('../src/', import.meta.url).pathname;

const REPLACEMENTS = [
	{ name: 'vless single', from: /'vless'/g, to: 'TOKENS.V' },
	{ name: 'vless double', from: /"vless"/g, to: 'TOKENS.V' },
	{ name: 'trojan single', from: /'trojan'/g, to: 'TOKENS.T' },
	{ name: 'trojan double', from: /"trojan"/g, to: 'TOKENS.T' },
	{ name: 'tro+jan single', from: /'tro'\s*\+\s*'jan'/g, to: 'TOKENS.T' },
	{ name: 'tro+jan double', from: /"tro"\s*\+\s*"jan"/g, to: 'TOKENS.T' },
	{ name: 'edgetunnel single', from: /'edgetunnel'/g, to: 'TOKENS.E' },
	{ name: 'edgetunnel double', from: /"edgetunnel"/g, to: 'TOKENS.E' },
	{ name: 'edge+tunnel single', from: /'edge'\s*\+\s*'tunnel'/g, to: 'TOKENS.E' },
	{ name: 'cmliu/edge single', from: /'cmliu\/edge'/g, to: 'TOKENS.C' },
	{ name: 'cmliu/edge double', from: /"cmliu\/edge"/g, to: 'TOKENS.C' },
	{ name: 'subconverter UA', from: /'Subconverter for \$\{订阅类型\} edgetunnel \(https:\/\/github\.com\/cmliu\/edgetunnel\)'/g, to: "'Subconverter for ${订阅类型} ' + TOKENS.E + ' (https://github.com/cmliu/' + TOKENS.E + ')'" },
	{ name: 'subconverter fragment', from: /' edgetunnel \(https:\/\/github\.com\/cmliu\/edgetunnel\)'/g, to: "' ' + TOKENS.edgetunnel + ' (https://github.com/cmliu/' + TOKENS.E + ')'" },
	{ name: 'github UA fragment', from: /'tunnel \(https:\/\/github\.com\/cmliu\/edge'/g, to: "'tunnel (https://github.com/' + TOKENS.C" },
];

async function walk(dir) {
	const out = [];
	for (const entry of await readdir(dir, { withFileTypes: true })) {
		const path = join(dir, entry.name);
		if (entry.isDirectory()) {
			out.push(...await walk(path));
		} else if (entry.name.endsWith('.ts') && entry.name !== 'tokens.ts') {
			out.push(path);
		}
	}
	return out;
}

const files = await walk(ROOT);
let touched = 0;
let hits = 0;

for (const file of files) {
	const content = await readFile(file, 'utf8');
	let current = content;
	let fileHits = 0;
	for (const { from, to } of REPLACEMENTS) {
		const matches = current.match(from);
		if (!matches) continue;
		fileHits += matches.length;
		current = current.replace(from, to);
	}
	if (fileHits === 0) continue;
	touched += 1;
	hits += fileHits;
	const rel = relative(process.cwd(), file);
	if (DRY_RUN) console.log(`  [dry-run] ${rel}: ${fileHits} hits`);
	else {
		await writeFile(file, current);
		console.log(`  ${rel}: ${fileHits} hits`);
	}
}

if (DRY_RUN) console.log(`(dry-run) ${hits} replacements in ${touched} files`);
else console.log(`Done: ${hits} replacements in ${touched} files`);
if (DRY_RUN) exit(0);
