export type Verdict = { allow: true } | { allow: false; reason: string };
export function decideTool(input: { tool_name?: string; tool_input?: unknown; cwd?: string }, env: Record<string, string | undefined>): Verdict;
