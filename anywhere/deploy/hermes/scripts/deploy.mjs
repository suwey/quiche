#!/usr/bin/env node
// 一站式 deploy：先 scrub，部署无论成功失败都还原源码。
// 用法：node scripts/deploy.mjs  （或 npm run deploy）
//
// 还原策略：纯替换反向 scrub，不依赖 git，避免还原整个工作区影响其他改动。

import { execSync } from 'node:child_process';
import { readFile, writeFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';

const REVERSES = [
	// 单字段引用
	{ from: /\bTOKENS\.vless\b/g, to: "'vless'" },
	{ from: /\bTOKENS\.trojan\b/g, to: "'trojan'" },
	{ from: /\bTOKENS\.edgetunnel\b/g, to: "'edgetunnel'" },
	{ from: /\bTOKENS\.cmliuEdge\b/g, to: "'cmliu/edge'" },
	// UA 字符串拼接
	{ from: /'v2rayN\/'\s*\+\s*TOKENS\.edgetunnel\s*\+\s*' \(https:\/\/github\.com\/cmliu\/'\s*\+\s*TOKENS\.edgetunnel\s*\+\s*'\)'/g, to: "'v2rayN/edgetunnel (https://github.com/cmliu/edgetunnel)'" },
	{ from: /'Subconverter for '\s*\+\s*[^']*?\s*\+\s*' '\s*\+\s*TOKENS\.edgetunnel\s*\+\s*' \(https:\/\/github\.com\/cmliu\/'\s*\+\s*TOKENS\.edgetunnel\s*\+\s*'\)'/g, to: "'Subconverter for ${订阅类型} edgetunnel (https://github.com/cmliu/edgetunnel)'" },
	{ from: /'tunnel \(https:\/\/github\.com\/'\s*\+\s*TOKENS\.cmliuEdge\b/g, to: "'tunnel (https://github.com/cmliu/edge'" },
];

const run = (cmd) => {
	console.log(`\n>> ${cmd}`);
	execSync(cmd, { stdio: 'inherit' });
};

async function walk(dir) {
	const out = [];
	for (const entry of await readdir(dir, { withFileTypes: true })) {
		const path = join(dir, entry.name);
		if (entry.isDirectory()) out.push(...await walk(path));
		else if (entry.name.endsWith('.ts')) out.push(path);
	}
	return out;
}

async function reverseScrub() {
	let hits = 0;
	for (const file of await walk(new URL('../src/', import.meta.url).pathname)) {
		let content = await readFile(file, 'utf8');
		let fileHits = 0;
		for (const { from, to } of REVERSES) {
			const m = content.match(from);
			if (!m) continue;
			fileHits += m.length;
			content = content.replace(from, to);
		}
		if (fileHits === 0) continue;
		await writeFile(file, content);
		hits += fileHits;
	}
	if (hits > 0) console.log(`(reverse-scrub) ${hits} replacements`);
}

try {
	run('node scripts/scrub-literals.mjs');
	run('npx wrangler deploy');
} catch (err) {
	console.error(`\n!! Deploy failed: ${err && err.message ? err.message : err}`);
	process.exitCode = 1;
} finally {
	// 只撤销 scrub-literals 写入的 TOKENS 引用，纯文本替换，不动其他行。
	try {
		await reverseScrub();
	} catch (err) {
		console.error(`!! Failed to restore source: ${err && err.message ? err.message : err}`);
		if (process.exitCode === undefined) process.exitCode = 1;
	}
}
