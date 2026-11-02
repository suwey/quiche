#!/usr/bin/env node
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { dirname, join, relative } from 'node:path';
import { argv, exit } from 'node:process';
import { SENSITIVE, STATE } from './sensitive.mjs';

const DRY_RUN = argv.includes('--dry-run');
const ROOT = new URL('../src/', import.meta.url).pathname;

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
const RULES = SENSITIVE.map(({ word, field }) => ({
	from: new RegExp(`(['"])${escapeRe(word)}\\1`, 'g'),
	to: `TOKENS.${field}`,
}));

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

const changed = new Map();
let hits = 0;

for (const file of await walk(ROOT)) {
	const original = await readFile(file, 'utf8');
	let current = original;
	let fileHits = 0;
	for (const { from, to } of RULES) {
		const matches = current.match(from);
		if (!matches) continue;
		fileHits += matches.length;
		current = current.replace(from, to);
	}
	if (fileHits === 0) continue;
	changed.set(file, { original, scrubbed: current, hits: fileHits });
	hits += fileHits;
}

const rel = (f) => relative(process.cwd(), f);
for (const [file, { hits: n }] of changed) {
	console.log(DRY_RUN ? `  [dry-run] ${rel(file)}: ${n} hits` : `  ${rel(file)}: ${n} hits`);
}

if (DRY_RUN) {
	console.log(`(dry-run) ${hits} replacements in ${changed.size} files`);
	exit(0);
}

// 快照必须先落盘，再动源码：中途被杀也还能按字节还原。
if (changed.size > 0) {
	await mkdir(dirname(STATE), { recursive: true });
	const snapshot = Object.fromEntries([...changed].map(([f, { original }]) => [f, original]));
	await writeFile(STATE, JSON.stringify(snapshot));
}
for (const [file, { scrubbed }] of changed) await writeFile(file, scrubbed);

console.log(`Done: ${hits} replacements in ${changed.size} files`);
