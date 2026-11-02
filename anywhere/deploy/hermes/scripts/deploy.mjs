#!/usr/bin/env node
// 一站式 deploy：快照 → scrub → typecheck → 产物明文门禁 → 上传 → 按快照还原源码。
//
// 还原只认字节快照，不做反向正则：源码里可以永久写 TOKENS.xxx，反向替换会把它们吃回明文。
// 门禁扫的是真正上传前的 bundle，所以「折叠没折叠」是测出来的，不是推出来的。

import { execSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { readFile, rm, writeFile } from 'node:fs/promises';
import { GATE_DIR, SENSITIVE, STATE } from './sensitive.mjs';

const run = (cmd) => {
	console.log(`\n>> ${cmd}`);
	execSync(cmd, { stdio: 'inherit' });
};

async function restore(tag) {
	if (!existsSync(STATE)) return;
	const snapshot = JSON.parse(await readFile(STATE, 'utf8'));
	for (const [path, content] of Object.entries(snapshot)) await writeFile(path, content);
	await rm(STATE);
	console.log(`(restore/${tag}) 快照还原 ${Object.keys(snapshot).length} 个文件`);
}

async function gate() {
	const bundle = `${GATE_DIR}/index.js`;
	if (!existsSync(bundle)) throw new Error(`门禁找不到产物：${bundle}`);
	const code = await readFile(bundle, 'utf8');
	const leaks = SENSITIVE.filter(({ word }) => code.includes(word)).map(({ word }) => code.indexOf(word));
	if (leaks.length > 0) {
		const where = leaks.map(i => `…${code.slice(Math.max(0, i - 60), i + 40).replace(/\s+/g, ' ')}…`).join('\n    ');
		throw new Error(`产物里仍有 ${leaks.length} 处明文，未上传：\n    ${where}`);
	}
	console.log(`(gate) bundle ${(code.length / 1024).toFixed(1)} KiB，${SENSITIVE.length} 个词 0 命中`);
}

// 上一次 deploy 被 Ctrl-C / 崩溃打断时，先把残留的 scrubbed 源码还原掉。
await restore('startup');

try {
	run('node scripts/scrub-literals.mjs');
	// 必须放在 scrub 之后：TOKENS 引用这时才存在，漏 import 会在这里暴露，
	// 否则它只会变成 bundle 里的自由变量，线上才炸。
	run('npx tsc --noEmit');
	// 门禁扫的正是将要上传的那份 index.js（源码图已在 wrangler.toml 关掉上传）。
	run(`npx wrangler deploy --dry-run --outdir="${GATE_DIR}"`);
	await gate();
	run('npx wrangler deploy');
} catch (err) {
	console.error(`\n!! Deploy failed: ${err && err.message ? err.message : err}`);
	process.exitCode = 1;
} finally {
	try {
		await restore('finally');
	} catch (err) {
		console.error(`!! 快照还原失败，源码仍处 scrubbed 状态: ${err && err.message ? err.message : err}`);
		if (process.exitCode === undefined) process.exitCode = 1;
	}
}
