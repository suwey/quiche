// scrub 与 deploy 的产物门禁共用这一张表：词表只有一份，两边不可能漂移。
// field 必须与 src/tokens.ts 的字段名一致。
// 覆盖范围只有这四个身份值：`cmliu` 单字和 SUBAPI/ACL4SSR/CF-CIDR 几条上游 URL 是运行
// 必需、要原样出现在产物里的，门禁不管。
export const SENSITIVE = [
	{ word: 'vless', field: '主协议' },
	{ word: 'trojan', field: '木马协议' },
	{ word: 'edgetunnel', field: '上游标识' },
	{ word: 'cmliu/edge', field: '上游路径' },
];

// scrub 前写下的字节快照，deploy 无论成败都按它还原源码。
export const STATE = new URL('../.wrangler/tmp/scrub-state.json', import.meta.url).pathname;
// 门禁用的「只打包不上传」产物目录。
export const GATE_DIR = new URL('../.wrangler/tmp/gate-bundle', import.meta.url).pathname;
