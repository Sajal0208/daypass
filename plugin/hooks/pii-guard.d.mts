export type Verdict = { allow: true } | { allow: false; reason: string };
export function looksSensitive(column: string): boolean;
export function hiddenFilePath(env: Record<string, string | undefined>): string;
export function decide(sql: string, hiddenFileText: string | null, env: Record<string, string | undefined>): Verdict;
