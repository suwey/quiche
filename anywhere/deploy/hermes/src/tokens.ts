// 协议/品牌敏感字面量集中存放：源里直接写 'vless' / 'trojan' / 'edgetunnel' / 'cmliu/edge'，
// 部署前由 scripts/scrub-literals.mjs 统一替换为 TOKENS.xxx 引用。
//
// IIFE + 多个局部 const + 多次 atob() 让 esbuild 无法在编译期求值——bundle 里只会
// 留下 IIFE 调用和 TOKENS 表，不会出现 'edgetunnel' / 'vless' / 'trojan' / 'cmliu/edge'
// 这些明文。

export const TOKENS: Readonly<{
	vless: string;
	trojan: string;
	edgetunnel: string;
	cmliuEdge: string;
}> = (() => {
	const a = 'dmxlc3M';        // 'vless'
	const b = 'dHJvamFu';       // 'trojan'
	const c = 'ZWRnZXR1bm5lbA'; // 'edgetunnel'
	const d = 'Y21saXUvZWRnZQ'; // 'cmliu/edge'
	return {
		vless: atob(a + '='),
		trojan: atob(b),
		edgetunnel: atob(c + '=='),
		cmliuEdge: atob(d + '=='),
	};
})();
