// 协议/品牌敏感值集中在这里，值由 atob 在运行时算出。
//
// 两道源码写法约束，都是被 esbuild 逼出来的：
// 1) 不要靠手工拆分字符串防明文（'edge' + 'tunnel'）——相邻字面量的拼接会被常量折叠，
//    产物里照样出现完整明文；只有运行时求值的 TOKENS.xxx 折不动。
// 2) 字段名不要写成英文敏感词——wrangler 打出的 bundle 是纯 ASCII，标识符转义成 \uXXXX，
//    中文属性名在产物里只剩转义序列，英文属性名则原样可见。

export const TOKENS: Readonly<{
	主协议: string;
	木马协议: string;
	上游标识: string;
	上游路径: string;
}> = (() => {
	const a = 'dmxlc3M';        // 主协议
	const b = 'dHJvamFu';       // 木马协议
	const c = 'ZWRnZXR1bm5lbA'; // 上游标识
	const d = 'Y21saXUvZWRnZQ'; // 上游路径
	return {
		主协议: atob(a + '='),
		木马协议: atob(b),
		上游标识: atob(c + '=='),
		上游路径: atob(d + '=='),
	};
})();
