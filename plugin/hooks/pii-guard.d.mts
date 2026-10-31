export type Verdict = { allow: true } | { allow: false; reason: string };
export type Token = {
  type: 'ident' | 'string' | 'number' | 'param' | 'punct' | 'op';
  /** Decoded identifier name, number text, `$n`, or the punctuation/operator; empty for strings. */
  value: string;
  /** Identifiers only: was it written in double quotes (or `U&"..."`)? */
  quoted?: boolean;
  /** Identifiers only: the name Postgres resolves (lower-cased when unquoted, as written when quoted). */
  fold?: string;
  /** `'...'` strings only: true when the literal would end elsewhere with standard_conforming_strings off. */
  ambiguous?: boolean;
  start: number;
  end: number;
};
export type HiddenFile = string | null | { error: string };
export function looksSensitive(column: string): boolean;
export function hiddenFilePath(env: Record<string, string | undefined>): string;
export function hookDisabled(env: Record<string, string | undefined>): boolean;
export function tokenize(sql: string): Token[];
export function asciiLower(s: string): string;
export function truncateIdent(s: string): string;
export function parseHiddenFile(text: string): { hidden: string[][]; allow: string[][] };
export function decide(sql: string, hiddenFile: HiddenFile, env: Record<string, string | undefined>): Verdict;
