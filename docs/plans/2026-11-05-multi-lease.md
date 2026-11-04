# Multiple leases at once — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (or superpowers:subagent-driven-development) to implement this plan task-by-task.

**Goal:** Let a user hold one live lease per target at the same time (`daypass open ezo`, then `daypass open pineyard`), and let the MCP tools pick a lease by an optional `target` argument.

**Architecture:** `~/.daypass/lease.json` keeps its path. With **one** lease it keeps the 0.2.0 shape exactly (a bare `Lease` object), so a 0.2.0 server still running in an open Claude session, and every existing test that parses the file, keep working. With **two or more** it holds `{ "version": 2, "leases": [Lease, …] }`, at most one entry per target. The reader accepts both. A pure function `pickLease(leases, target?)` in `src/core/lease.ts` picks the lease for a tool call. Every write is a read-modify-write under the existing lease lock. The MCP server caches one pool per target instead of one pool per process.

**Tech stack:** TypeScript, vitest, commander (CLI), `@modelcontextprotocol/sdk` + zod (MCP tools), the fake EC2 in `test/helpers/fake-ec2.ts`.

**Review that shaped this version:** 2026-11-05 plan review (15 items). Each fix is tagged `[R<n>]` where it lands.

---

## Decisions (read before coding)

| # | Question | Decision |
|---|---|---|
| D1 | File shape `[R1, R2]` | 1 lease → bare 0.2.0 object. ≥2 → `{version:2, leases}`. 0 → file removed. A 0.2.0 process only breaks once a user really has two leases open. |
| D2 | Corrupt lease.json `[R3]` | `readLeases()` throws `LeaseCorruptError`. An **unconditional** `writeLease` and `clearLease(target)` rethrow it (never silently drop other targets and their `sgRuleId`). An `ifId` write returns `false` (today's behaviour). `clearLease()` with no target still removes the file. |
| D3 | Two `open`s of the same target at once `[R4]` | `open`'s first write is `writeLease(lease, { ifId: existing?.id ?? null })`. `false` → error `Another "daypass open <t>" ran at the same time. Run: daypass status`, exit 1, no AWS call. |
| D4 | Two targets on the same security group + region + port `[R5]` | `open` refuses before writing anything: AWS rejects a duplicate rule, and closing one lease would cut off the other. New optional lease field `sgPort` records the port. Older leases without `sgPort` count as a match (safe side). |
| D5 | DB pool `[R6]` | `Map<targetName, {key, pool}>` in `src/mcp/db.ts`. A config change for a target retires only that target's pool. |
| D6 | `daypass_status` text `[R8]` | 0 leases: `No lease open.` 1 lease: **exactly today's text** (`Lease … min left …` or `Expired at <ISO>`). ≥2: one line per lease plus a hint line. |
| D7 | `pickLease`, no target, ≥2 all expired `[R10]` | Error names the expired targets. |
| D8 | `daypass close` with no target `[R11]` | Closes every lease. The skill tells Claude to run `daypass close <target>` only, and never bare `daypass close` unless the user asks. |
| D9 | `readLease` | Removed. Callers move to `readLeases`. `src/mcp/index.ts` exports `readLeases` `[R9]`. |
| D10 | `sweep <target>` with a corrupt file `[R14]` | The AWS sweep runs and prints first. Then it prints `The lease file … is corrupt. Run: daypass close` and exits 1. |
| D11 | PII hook | Still one hidden-columns file for all targets (`plugin/hooks/pii-guard.mjs`). Out of scope; say so in `docs/threat-model.md`. Each target's role grants are the wall and are unchanged. |

---

### Task 1: `pickLease` (pure, in core) and `sgPort`

**Files:**
- Modify: `src/core/lease.ts` (add `sgPort` to `Lease`; append `pickLease`)
- Modify: `src/core/index.ts` (export `pickLease`, `type Pick`)
- Test: `test/lease.test.ts`

**Step 1: write the failing tests** (append to `test/lease.test.ts`)

```ts
import { pickLease } from '../src/core/index.js';
const L = (target: string, mins: number, id = target) => ({ id, target, reason: 'r', who: 'w', openedAt: '', expiresAt: new Date(Date.now() + mins * 60_000).toISOString() });

describe('pickLease', () => {
  it('no leases: asks for daypass open', () => {
    expect(pickLease([]).error).toMatch(/No active Daypass lease/);
  });
  it('one live lease, no target: uses it', () => {
    expect(pickLease([L('ezo', 10)]).lease?.target).toBe('ezo');
  });
  it('one expired lease, no target: the expired message', () => {
    expect(pickLease([L('ezo', -1)]).error).toMatch(/expired at .*daypass open ezo/);
  });
  it('two live leases, no target: refuses and lists both', () => {
    const r = pickLease([L('ezo', 10), L('pineyard', 10)]);
    expect(r.error).toMatch(/2 leases are open \(ezo, pineyard\)/);
    expect(r.error).toMatch(/Pass target/);
  });
  it('two leases, one expired, no target: uses the live one', () => {
    expect(pickLease([L('ezo', -1), L('pineyard', 10)]).lease?.target).toBe('pineyard');
  });
  it('two expired leases, no target: names both', () => {
    expect(pickLease([L('ezo', -1), L('pineyard', -2)]).error).toMatch(/expired: ezo, pineyard/);
  });
  it('named target that is live: uses it', () => {
    expect(pickLease([L('ezo', 10), L('pineyard', 10)], 'pineyard').lease?.target).toBe('pineyard');
  });
  it('named target with no lease: says which are open', () => {
    expect(pickLease([L('ezo', 10)], 'pineyard').error).toMatch(/No lease on "pineyard".*Open: ezo/);
  });
  it('named target that expired: the expired message', () => {
    expect(pickLease([L('pineyard', -1)], 'pineyard').error).toMatch(/expired at/);
  });
});
```

**Step 2: run, expect FAIL**

Run: `npx vitest run test/lease.test.ts`
Expected: FAIL, `pickLease is not a function` (or not exported).

**Step 3: implement**

In `interface Lease` in `src/core/lease.ts`, after `sgProfile?: string;`:

```ts
  /** Port the rule opens, recorded with sgGroupId, so `open` can spot a second target behind the same rule. */
  sgPort?: number;
```

Append:

```ts
export type Pick = { lease: Lease; error?: undefined } | { lease?: undefined; error: string };

const openHint = (t: string) => `Ask the user to run: daypass open ${t} --reason "..."`;
const expiredMsg = (l: Lease) => `Lease ${l.id} for "${l.target}" expired at ${l.expiresAt}. ${openHint(l.target)}`;

/** Which lease a tool call uses: the named target's, or the only live one. */
export function pickLease(leases: Lease[], target?: string, now = Date.now()): Pick {
  const live = leases.filter((l) => isLeaseLive(l, now));
  const names = (ls: Lease[]) => ls.map((x) => x.target).join(', ');
  if (target !== undefined) {
    const l = leases.find((x) => x.target === target);
    if (l && isLeaseLive(l, now)) return { lease: l };
    if (l) return { error: expiredMsg(l) };
    return { error: `No lease on "${target}". Open: ${names(live) || 'none'}. ${openHint(target)}` };
  }
  if (live.length === 1) return { lease: live[0] };
  if (live.length > 1) return { error: `${live.length} leases are open (${names(live)}). Pass target: one of them.` };
  if (leases.length === 1) return { error: expiredMsg(leases[0]) };
  if (leases.length > 1) return { error: `No live lease; expired: ${names(leases)}. ${openHint('<target>')}` };
  return { error: `No active Daypass lease. ${openHint('<target>')}` };
}
```

Add `pickLease` and `type Pick` to the lease exports in `src/core/index.ts`.

**Step 4: run, expect PASS**

Run: `npx vitest run test/lease.test.ts` → all pass.

**Step 5: commit**

```bash
git add src/core/lease.ts src/core/index.ts test/lease.test.ts
git commit -m "feat(core): pickLease chooses a lease by target"
```

---

### Task 2: lease file with one lease per target (`src/mcp/state.ts`)

**Files:**
- Modify: `src/mcp/state.ts` (replace `readLease`; rewrite `writeLease`, `clearLease`; add `readLeases`, `parseLease`, `writeLeaseFile`)
- Modify: `src/mcp/index.ts:2-18` (export `readLeases`, drop `readLease`) `[R9]`
- Test: `test/state-files.test.ts`

**Step 1: write the failing tests** (new `describe` at the end of `test/state-files.test.ts`; uses the file's own `fresh()` and `lease`)

```ts
describe('lease.json: one lease per target', () => {
  const file = (h: string) => JSON.parse(readFileSync(join(h, 'lease.json'), 'utf8'));
  it('reads a 0.2.0 single-lease file as one lease', async () => {
    const { state } = await fresh((h) => writeFileSync(join(h, 'lease.json'), JSON.stringify(lease), { mode: 0o600 }));
    expect((await state.readLeases()).map((l: any) => l.id)).toEqual(['aaaa1111']);
  });
  it('one lease is written in the 0.2.0 shape', async () => {
    const { home, state } = await fresh();
    await state.writeLease(lease);
    expect(file(home)).toMatchObject({ id: 'aaaa1111', target: 't' });
    expect(file(home).version).toBeUndefined();
  });
  it('a second target switches to v2 and keeps the first', async () => {
    const { home, state } = await fresh();
    await state.writeLease(lease);
    await state.writeLease({ ...lease, id: 'bbbb2222', target: 'u' });
    expect(file(home).version).toBe(2);
    expect((await state.readLeases()).map((l: any) => l.target).sort()).toEqual(['t', 'u']);
  });
  it('writeLease replaces the lease for the same target', async () => {
    const { state } = await fresh();
    await state.writeLease(lease);
    await state.writeLease({ ...lease, id: 'cccc3333' });
    expect((await state.readLeases()).map((l: any) => l.id)).toEqual(['cccc3333']);
  });
  it('ifId compares against the lease for that target only', async () => {
    const { state } = await fresh();
    await state.writeLease(lease);
    await state.writeLease({ ...lease, id: 'u1', target: 'u' });
    expect(await state.writeLease({ ...lease, id: 'x' }, { ifId: 'u1' })).toBe(false);
    expect(await state.writeLease({ ...lease, id: 'x' }, { ifId: 'aaaa1111' })).toBe(true);
    expect(await state.writeLease({ ...lease, id: 'v', target: 'v' }, { ifId: null })).toBe(true);
    expect(await state.writeLease({ ...lease, id: 'v2', target: 'v' }, { ifId: null })).toBe(false);
  });
  it('clearLease(target) removes one and goes back to the 0.2.0 shape; clearLease() removes all', async () => {
    const { home, state } = await fresh();
    await state.writeLease(lease);
    await state.writeLease({ ...lease, id: 'u1', target: 'u' });
    await state.clearLease('t');
    expect(file(home)).toMatchObject({ id: 'u1', target: 'u' });
    await state.writeLease(lease);
    await state.clearLease();
    expect(existsSync(join(home, 'lease.json'))).toBe(false);
  });
  it('clearLease(last target) removes the file', async () => {
    const { home, state } = await fresh();
    await state.writeLease(lease);
    await state.clearLease('t');
    expect(existsSync(join(home, 'lease.json'))).toBe(false);
  });
  it('a v2 file with a bad entry or a duplicate target is corrupt', async () => {
    for (const leases of [[{ id: 1 }], [lease, { ...lease, id: 'dup' }]]) {
      const { state } = await fresh((h) => writeFileSync(join(h, 'lease.json'), JSON.stringify({ version: 2, leases }), { mode: 0o600 }));
      await expect(state.readLeases()).rejects.toThrow(/corrupt/);
    }
  });
  it('corrupt file: an unconditional write and clearLease(target) refuse; ifId returns false; clearLease() removes it', async () => {
    const { home, state } = await fresh((h) => writeFileSync(join(h, 'lease.json'), '{nope', { mode: 0o600 }));
    await expect(state.writeLease(lease)).rejects.toThrow(/corrupt/);
    await expect(state.clearLease('t')).rejects.toThrow(/corrupt/);
    expect(await state.writeLease(lease, { ifId: null })).toBe(false);
    expect(readFileSync(join(home, 'lease.json'), 'utf8')).toBe('{nope');
    await state.clearLease();
    expect(existsSync(join(home, 'lease.json'))).toBe(false);
  });
});
```

Also replace every `state.readLease()` in the existing tests of this file (lines 38, 65, 71, 103, 146, 164) `[R9]`:
- `await expect(state.readLease()).rejects…` → `await expect(state.readLeases()).rejects…`
- `(await state.readLease())!.id` → `(await state.readLeases())[0].id`
- line 146 `const now = await state.readLease();` → `const now = (await state.readLeases())[0] ?? null;`

**Step 2: run, expect FAIL**

Run: `npm run build && npx vitest run test/state-files.test.ts`
Expected: FAIL, `state.readLeases is not a function`.

**Step 3: implement** in `src/mcp/state.ts`, replacing `readLease`, `writeLease`, `clearLease`:

```ts
/** Thrown by readLeases when lease.json exists but holds no valid leases. */
export class LeaseCorruptError extends Error {
  readonly code = 'ELEASECORRUPT';
}
const corrupt = () => new LeaseCorruptError(`The lease file ${LEASE_PATH} is corrupt. Run: daypass close`);

function parseLease(l: any): Lease {
  if (!l || typeof l !== 'object' || typeof l.id !== 'string' || typeof l.target !== 'string' || typeof l.expiresAt !== 'string') throw corrupt();
  return l as Lease;
}

/**
 * Every lease on disk, at most one per target. A file with one lease is the 0.2.0 shape (a bare
 * lease); two or more are `{ version: 2, leases }`. Missing file: [].
 */
export async function readLeases(): Promise<Lease[]> {
  const text = await readSafe(LEASE_PATH);
  if (text === null) return [];
  let v: any;
  try {
    v = JSON.parse(text);
  } catch {
    throw corrupt();
  }
  const leases = v?.version === 2 && Array.isArray(v.leases) ? v.leases.map(parseLease) : [parseLease(v)];
  if (new Set(leases.map((l: Lease) => l.target)).size !== leases.length) throw corrupt();
  return leases;
}

/**
 * Replace lease.json with `leases` atomically (temp file in the same directory, fsync, rename),
 * or remove it when empty. One lease keeps the 0.2.0 shape so an older daypass can still read it.
 * Call only while holding the lease lock.
 */
async function writeLeaseFile(leases: Lease[]): Promise<void> {
  if (leases.length === 0) {
    await fs.rm(LEASE_PATH, { force: true });
    return;
  }
  await refuseSymlink(LEASE_PATH);
  const body = leases.length === 1 ? leases[0] : { version: 2, leases };
  const tmp = join(DAYPASS_HOME, `.lease.${randomBytes(6).toString('hex')}.tmp`);
  try {
    const fh = await fs.open(tmp, fsc.O_WRONLY | fsc.O_CREAT | fsc.O_EXCL | O_NOFOLLOW, 0o600);
    try {
      await fh.writeFile(JSON.stringify(body, null, 2));
      await fh.sync();
    } finally {
      await fh.close();
    }
    await fs.rename(tmp, LEASE_PATH);
  } finally {
    await fs.rm(tmp, { force: true }).catch(() => {});
  }
}

/**
 * Put `l` in lease.json, replacing the lease for the same target and keeping the others. The
 * read, the check and the write all run under the lease lock. With `ifId`, it writes only if
 * the lease on disk for `l.target` still has that id (null: only if that target has none), so
 * cleanup of an old lease cannot overwrite one opened meanwhile; a corrupt file then returns
 * false. Without `ifId`, a corrupt file throws LeaseCorruptError: overwriting it would drop the
 * other targets' leases and the security-group rules they record. Returns whether it wrote.
 */
export async function writeLease(l: Lease, opts: { ifId?: string | null } = {}): Promise<boolean> {
  await checkHome(true);
  await refuseSymlink(LEASE_PATH);
  return withLeaseLock(async () => {
    let leases: Lease[];
    try {
      leases = await readLeases();
    } catch (e) {
      if (opts.ifId !== undefined && e instanceof LeaseCorruptError) return false;
      throw e;
    }
    const i = leases.findIndex((x) => x.target === l.target);
    if (opts.ifId !== undefined && (i < 0 ? null : leases[i].id) !== opts.ifId) return false;
    if (i < 0) leases.push(l);
    else leases[i] = l;
    await writeLeaseFile(leases);
    return true;
  });
}

/** Remove the lease for `target`, or every lease (the whole file, even a corrupt one) without one. */
export async function clearLease(target?: string): Promise<void> {
  if (!(await checkHome(false))) return;
  await withLeaseLock(async () => {
    if (target === undefined) return fs.rm(LEASE_PATH, { force: true });
    await writeLeaseFile((await readLeases()).filter((x) => x.target !== target));
  });
}
```

Update the comment above `withLeaseLock` `[R12]`: add "With several targets in one file, two waiters that break the same stale lock can also lose another target's entry, not just a whole-file write."

In `src/mcp/index.ts`, replace `readLease,` with `readLeases,`.

**Step 4: run, expect PASS**

Run: `npm run build && npx vitest run test/state-files.test.ts`
Expected: PASS. `npm run build` will fail in `server.ts`, `main.ts`, `doctor.ts` (they still import `readLease`). If so, run only the vitest step now (vitest compiles `state.ts` itself); the build goes green after Task 5.

**Step 5: commit**

```bash
git add src/mcp/state.ts src/mcp/index.ts test/state-files.test.ts
git commit -m "feat(state): lease.json holds one lease per target"
```

---

### Task 3: one pool per target (`src/mcp/db.ts`) `[R6]`

**Files:**
- Modify: `src/mcp/db.ts:67` (`cached`), `:134-165` (`getPool`), `:234-238` (`closePool`), and `shutdownPool` if it reads `cached`
- Test: `test/db-pool.test.ts`

**Step 1: failing test** (in `describe('getPool')`)

```ts
it('keeps one pool per target: switching back and forth reuses both', async () => {
  const a = await getPool('t', t);
  const b = await getPool('u', { ...t, database: 'other' });
  expect(await getPool('t', t)).toBe(a);
  expect(await getPool('u', { ...t, database: 'other' })).toBe(b);
  expect(a).not.toBe(b);
});
```

The existing tests at lines 29-45 (a config change for the same name gives a new pool and retires the old one) must still pass.

**Step 2:** `npx vitest run test/db-pool.test.ts` → FAIL (`getPool('t', t)` returns a new pool).

**Step 3: implement**

```ts
/** One pool per target name, each holding its current config key. */
const cached = new Map<string, { key: string; pool: pg.Pool }>();
```

In `getPool`:

```ts
  const have = cached.get(name);
  if (have && have.key === key) return have.pool;
  // ... new pg.Pool({...}) unchanged ...
  if (have) retire(have.pool);
  cached.set(name, { key, pool });
  return pool;
```

In `closePool`:

```ts
  const pools = [...retired, ...[...cached.values()].map((c) => c.pool)];
  retired.clear();
  cached.clear();
```

Fix any other `cached` use (`grep -n cached src/mcp/db.ts`). Update the comment above `getPool`: "One connection per target per process. Two leases on targets that share a role use two of its CONNECTION LIMIT slots."

**Step 4:** `npx vitest run test/db-pool.test.ts` → PASS.

**Step 5: commit**

```bash
git add src/mcp/db.ts test/db-pool.test.ts
git commit -m "feat(db): one pool per target"
```

---

### Task 4: MCP server

**Files:**
- Modify: `src/mcp/server.ts` (imports line 7-9, `ctx` :107-128, `daypass_status` :326-340, the four tools :342-406, `auditServer` :411-424)
- Test: `test/lease-network.test.ts` (fake EC2, no DB) `[R7]`, `test/server-tools.test.ts` (live Postgres; skipped without `DAYPASS_TEST_PG_URL`)

**Step 1: failing tests**

In `test/lease-network.test.ts`, inside `describe('expired-lease cleanup in the server never overwrites a newer lease')`:

```ts
it('two targets: an expired lease on prod gives up its rule; the live dev lease is untouched', async () => {
  config({ region: 'us-east-1', securityGroupId: 'sg-1' });
  fake.rules.push({ id: 'sgr-old', groupId: 'sg-1', description: `daypass:aaaa1111 until ${past}` });
  put({ version: 2, leases: [
    lease({ expiresAt: past, sgRuleId: 'sgr-old', sgRegion: 'us-east-1', sgGroupId: 'sg-1' }),
    lease({ id: 'bbbb2222', target: 'dev' }),
  ] });
  await call('query', { sql: 'select 1', target: 'dev' });
  expect(fake.rules).toEqual([]);
  const now = JSON.parse(readFileSync(LEASE, 'utf8'));
  expect(now.version).toBe(2);
  expect(now.leases.find((l: any) => l.target === 'prod').sgRuleId).toBeUndefined();
  expect(now.leases.find((l: any) => l.target === 'dev').id).toBe('bbbb2222');
});
```

Add a new `describe('several leases, no database')`:

```ts
describe('several leases, no database', () => {
  const two = () => put({ version: 2, leases: [lease({ target: 'prod' }), lease({ id: 'bbbb2222', target: 'dev' })] });
  it('a tool with no target refuses and names both', async () => {
    config({}); two();
    const r = await call('query', { sql: 'select 1' });
    expect(r.ok).toBe(false);
    expect(r.text).toMatch(/2 leases are open \(prod, dev\)/);
  });
  it('a target with no lease says which are open', async () => {
    config({}); two();
    const r = await call('list_tables', { target: 'nope' });
    expect(r.text).toMatch(/No lease on "nope".*Open: prod, dev/);
  });
  it('daypass_status lists every lease and ends with the target hint', async () => {
    two();
    const r = await call('daypass_status');
    expect(r.text).toMatch(/Lease aaaa1111 on "prod"/);
    expect(r.text).toMatch(/Lease bbbb2222 on "dev"/);
    expect(r.text).toMatch(/Pass target: "prod" or "dev"/);
  });
  it('daypass_status with one expired lease keeps the 0.2.0 text', async () => {
    put(lease({ expiresAt: past }));
    expect((await call('daypass_status')).text).toBe(`Expired at ${past}`);
  });
});
```

In `test/server-tools.test.ts` (read its setup first; it builds a config whose target points at the review container), add:
1. Two live leases, `t` and `t2`, where `t2` is a copy of `t`'s config entry. `query` with `target: 't2'` returns rows. The last audit `end` line has `target: 't2'` and `t2`'s `leaseId`.
2. Same, `query` with no target → error with `2 leases are open`, and no new audit line with `allowed: true`.

**Step 2:** `npm run build` (may still fail in `main.ts`/`doctor.ts`; vitest runs from source) then `npx vitest run test/lease-network.test.ts` → the new tests FAIL.

**Step 3: implement**

Imports: `readLease` → `readLeases`; add `pickLease` to the core import.

```ts
const targetArg = {
  target: z.string().optional().describe('Which leased database to use. Needed only when daypass_status lists more than one lease.'),
};

async function ctx(target?: string): Promise<Ctx | string> {
  let leases: Lease[];
  try {
    leases = await readLeases();
  } catch (e) {
    return errorMessage(e);
  }
  await Promise.all(leases.filter((l) => shouldReleaseNetwork(l)).map(releaseExpiredNetwork));
  const pick = pickLease(leases, target);
  if (pick.error !== undefined) return pick.error;
  const lease = pick.lease;
  const raw = (await readConfig()).targets[lease.target];
  if (!raw) return `Lease target "${lease.target}" is not in config.`;
  try {
    return { lease, target: resolveTarget(lease.target, raw), targetName: lease.target };
  } catch (e: any) {
    return e.message;
  }
}
```

- `list_tables`: schema `{ ...targetArg }`, handler `async ({ target }) => { const c = await ctx(target); … }`.
- `describe_table`, `query`, `explain`: add `...targetArg` to the schema, destructure `target`, call `ctx(target)`.
- `revokeExpired` is unchanged. `writeLease(rest, { ifId: lease.id })` now touches only that lease's target.
- `daypass_status` `[R8]`:

```ts
    async () => {
      let leases: Lease[];
      try {
        leases = await readLeases();
      } catch (e) {
        return fail(errorMessage(e));
      }
      const line = (l: Lease) =>
        isLeaseLive(l)
          ? `Lease ${l.id} on "${l.target}" by ${l.who}: ${Math.round((Date.parse(l.expiresAt) - Date.now()) / 60_000)} min left. Reason: ${l.reason}`
          : `Lease ${l.id} on "${l.target}" expired at ${l.expiresAt}`;
      if (leases.length === 0) return text('No lease open.');
      if (leases.length === 1) return text(isLeaseLive(leases[0]) ? line(leases[0]) : `Expired at ${leases[0].expiresAt}`);
      const live = leases.filter((l) => isLeaseLive(l)).map((l) => `"${l.target}"`);
      const hint = live.length > 1 ? `\nPass target: ${live.join(' or ')} to the other tools.` : '';
      return text(leases.map(line).join('\n') + hint);
    },
```

Update the tool description: `'Show which Daypass leases are open, for which database, and how long is left.'`

- `auditServer`: `const ls = await readLeases().catch(() => []); const lease = ls.length === 1 ? ls[0] : null;` then the fields as today.

**Step 4: run, expect PASS**

```bash
npx vitest run test/lease-network.test.ts
DAYPASS_TEST_PG_URL='postgres://postgres:postgres@localhost:5472/postgres?sslmode=disable' npx vitest run test/server-tools.test.ts
```

Expected: PASS, including the existing single-lease tests (the file stays in the 0.2.0 shape with one lease, so `now.id` at lines 101-102 still works) `[R1]`.

**Step 5: regenerate the eval tool list** `[R13]`

```bash
npm run build
node dist/cli/main.js mcp   # then send tools/list as in plugin/evals/README.md:65 and save it
```

Save the result to `plugin/evals/mocks/daypass/_tools.json`. Do not hand-edit it. (If `npm run build` still fails here, do this step at the end of Task 5.)

**Step 6: commit**

```bash
git add src/mcp/server.ts test/lease-network.test.ts test/server-tools.test.ts plugin/evals/mocks/daypass/_tools.json
git commit -m "feat(mcp): tools take an optional target when several leases are open"
```

---

### Task 5: CLI `open`, `status`, `close`, `sweep` (`src/cli/main.ts:131-252`)

**Files:**
- Modify: `src/cli/main.ts` (imports :14-29; `open` :131-185; `status` :187-199; `close` :201-235; `sweep` :237-252)
- Test: `test/lease-network.test.ts` (fake EC2 for the security-group cases), `test/setup-cli-lease.test.ts`

**Step 1: failing tests** in `test/lease-network.test.ts`, `describe('daypass open')`.

Change the existing test at :226-233 to say what it means: the regex becomes `/already open on "dev".*daypass close dev/`.

Add:

```ts
it('two targets: both open, status lists both, close <t> closes one, close closes all', async () => {
  config({});
  writeFileSync(join(home, 'config.json'), JSON.stringify({ targets: {
    a: { url: 'postgres://u:p@db.invalid/a?sslmode=disable' },
    b: { url: 'postgres://u:p@db.invalid/b?sslmode=disable' },
  } }), { mode: 0o600 });
  rmSync(LEASE, { force: true });
  expect((await cli('open', 'a', '-r', 'x', '--no-network')).code).toBe(0);
  expect((await cli('open', 'b', '-r', 'y', '--no-network')).code).toBe(0);
  const s = await cli('status');
  expect(s.stdout).toMatch(/on "a"/);
  expect(s.stdout).toMatch(/on "b"/);
  const c1 = await cli('close', 'b');
  expect(c1.stdout).toMatch(/closed/);
  expect(JSON.parse(readFileSync(LEASE, 'utf8')).target).toBe('a');   // back to the 0.2.0 shape
  expect((await cli('close', 'b')).stdout).toMatch(/No lease on "b"/);
  expect((await cli('open', 'b', '-r', 'y', '--no-network')).code).toBe(0);
  const c2 = await cli('close');
  expect(c2.stdout.match(/closed/g)).toHaveLength(2);
  expect(existsSync(LEASE)).toBe(false);
});

it('refuses a second target behind the same security group and port, before touching AWS', async () => {
  writeFileSync(join(home, 'config.json'), JSON.stringify({ targets: {
    prod: { host: 'db.invalid', database: 'd', user: 'u', region: 'us-east-1', securityGroupId: 'sg-1' },
    prod2: { host: 'db.invalid', database: 'd2', user: 'u', region: 'us-east-1', securityGroupId: 'sg-1' },
  } }), { mode: 0o600 });
  put(lease({ sgRuleId: 'sgr-a', sgRegion: 'us-east-1', sgGroupId: 'sg-1', sgPort: 5432 }));
  fake.calls.length = 0;
  const r = await cli('open', 'prod2', '-r', 'x');
  expect(r.code).toBe(1);
  expect(r.stderr).toMatch(/same security-group rule as the live lease on "prod"/);
  expect(fake.calls.filter((c) => c.Action === 'AuthorizeSecurityGroupIngress')).toEqual([]);
  expect(JSON.parse(readFileSync(LEASE, 'utf8')).target).toBe('prod');
});

it('sweep <target> with a corrupt lease file: sweeps AWS, then says the file is corrupt and exits 1', async () => {
  config({ region: 'us-east-1', securityGroupId: 'sg-1' });
  fake.rules.push({ id: 'sgr-x', groupId: 'sg-1', description: `daypass:abcd1234 until ${past}` });
  put('{nope');
  const r = await cli('sweep', 'prod');
  expect(r.code).toBe(1);
  expect(r.stdout).toMatch(/Removed 1 expired rule/);
  expect(r.stderr).toMatch(/corrupt.*daypass close/);
});
```

For the D3 race (`[R4]`), add to `test/state-files.test.ts`:

```ts
it('two opens of the same target at once: exactly one wins', async () => {
  const { state } = await fresh();
  const rs = await Promise.all([1, 2, 3].map((i) => state.writeLease({ ...lease, id: `r${i}` }, { ifId: null })));
  expect(rs.filter(Boolean)).toHaveLength(1);
});
```

**Step 2:** `npx vitest run test/lease-network.test.ts test/state-files.test.ts` → the new CLI tests FAIL (`main.ts` does not build yet, or behaves as 0.2.0).

**Step 3: implement** in `src/cli/main.ts`. Import `readLeases` instead of `readLease`.

`open <target>`, replacing the `existing` block (:142-146) and the first `writeLease(lease)`:

```ts
    let leases: Lease[];
    try {
      leases = await readLeases();
    } catch (e) {
      if (e instanceof LeaseCorruptError) throw new Error(`${e.message} (this removes every lease), then retry.`);
      throw e;
    }
    const existing = leases.find((l) => l.target === targetName);
    if (existing && isLeaseLive(existing)) {
      throw new Error(`A lease is already open on ${p(`"${targetName}"`)} (${p(existing.id)}, until ${p(existing.expiresAt)}). Run: daypass close ${p(targetName)}`);
    }
    // [R5] AWS allows one rule per group/port/CIDR, and closing either lease would revoke it for both.
    if (opts.network && t.region && t.securityGroupId) {
      const clash = leases.find(
        (o) => o.target !== targetName && isLeaseLive(o) && o.sgRuleId && o.sgGroupId === t.securityGroupId && o.sgRegion === t.region && (o.sgPort === undefined || o.sgPort === t.port),
      );
      if (clash) {
        throw new Error(
          `Target "${p(targetName)}" needs the same security-group rule as the live lease on "${p(clash.target)}" (${p(t.securityGroupId)} in ${p(t.region)}, port ${t.port}). ` +
            `Close that one first: daypass close ${p(clash.target)}`,
        );
      }
    }
    if (existing) await releaseNetwork(existing, cfg.targets[existing.target]).catch((e) => console.warn(`cleanup: ${e.message}`));
```

Then the lease object as today, and:

```ts
    // [R4] Only if nobody else opened this target since we looked.
    if (!(await writeLease(lease, { ifId: existing?.id ?? null }))) {
      throw new Error(`Another "daypass open ${p(targetName)}" ran at the same time. Run: daypass status`);
    }
```

In the network block, next to `lease.sgGroupId = t.securityGroupId;` add `lease.sgPort = t.port;`. The later `writeLease(lease)` calls stay unconditional (they replace only this target's entry). Last line: `` `Your AI session can now use the daypass MCP tools. Close early with: daypass close ${targetName}` ``.

`status`:

```ts
  .description('Show the open leases')
  .action(async () => {
    const leases = await readLeases();
    if (!leases.length) return console.log('No lease.');
    for (const l of leases) {
      const left = Math.round((Date.parse(l.expiresAt) - Date.now()) / 60_000);
      console.log(
        isLeaseLive(l)
          ? `Lease ${p(l.id)} on "${p(l.target)}" by ${p(l.who)}: ${left} min left. Reason: ${p(l.reason)}`
          : `Lease ${p(l.id)} on "${p(l.target)}" expired at ${p(l.expiresAt)}. Run: daypass close ${p(l.target)}`,
      );
    }
  });
```

`close [target]`: rename the command to `close [target]`, description `End one lease (or every lease) now and remove its network rule`. Move today's body after the corrupt check into `async function closeOne(l: Lease)`, ending with `await clearLease(l.target); console.log(`Lease ${p(l.id)} closed.`);`. Then:

```ts
  .action(async (target?: string) => {
    let leases: Lease[];
    try {
      leases = await readLeases();
    } catch (e: any) {
      if (!(e instanceof LeaseCorruptError)) throw e;
      await clearLease();
      console.warn('Removed the corrupt lease file. If it held a security-group rule, run: daypass sweep <target>');
      return;
    }
    const pick = target === undefined ? leases : leases.filter((l) => l.target === target);
    if (!pick.length) return console.log(target === undefined ? 'No lease.' : `No lease on "${p(target)}".`);
    for (const l of pick) await closeOne(l);
  });
```

`readConfig` in `closeOne` is read at most once: hoist it into a lazy `let cfg` outside the loop.

`sweep <target>` (:246-251) `[R14]`:

```ts
    let l: Lease | undefined;
    try {
      l = (await readLeases()).find((x) => x.target === targetName);
    } catch (e: any) {
      if (e instanceof LeaseCorruptError) throw new Error(e.message);
      throw e;
    }
    if (l && !isLeaseLive(l)) {
      await clearLease(targetName);
      console.log(`Cleared expired local lease ${p(l.id)}.`);
    }
```

(The AWS sweep and its `console.log` run before this, as today, so they print first.)

Fix `test/setup-cli-lease.test.ts` if any assertion matches the old `already open` or `daypass close` hint text exactly (`grep -n "close" test/setup-cli-lease.test.ts`).

**Step 4: run, expect PASS**

```bash
npm run build && npx vitest run test/lease-network.test.ts test/state-files.test.ts test/setup-cli-lease.test.ts
```

**Step 5: commit**

```bash
git add src/cli/main.ts test/lease-network.test.ts test/state-files.test.ts test/setup-cli-lease.test.ts
git commit -m "feat(cli): open one lease per target; close <target> or all"
```

---

### Task 6: doctor (`src/cli/doctor.ts:254-293`)

**Files:** `src/cli/doctor.ts`, test `test/doctor-local.test.ts`

**Step 1: failing test** (follow the file's existing setup for a fake home and URL targets):
- v2 file with leases on `a` (id `aaaa1111`) and `b` (id `bbbb2222`), both live. `doctor b` → the `lease` line is ✔ and contains `bbbb2222`.
- Same file, `doctor` with no target → checks the first config target, not a random lease.

**Step 2:** run → FAIL.

**Step 3: implement**

```ts
  let leases: Lease[] = [];
  try {
    leases = await readLeases();
  } catch (e: any) {
    push('lease', false, e?.message || String(e));
  }
  const name = targetName ?? (leases.length === 1 ? leases[0].target : undefined) ?? Object.keys(cfg.targets)[0];
  const lease = leases.find((l) => l.target === name) ?? null;
```

The rest is unchanged (`live` already checks `lease.target === name`). Import `readLeases` (from `../mcp/index.js`) and `type Lease`.

**Step 4:** `npm run build && npx vitest run test/doctor-local.test.ts` → PASS. `npm run build` must now succeed with no `readLease` left: `grep -rn 'readLease\b' src test` is empty.

If `_tools.json` was not regenerated in Task 4, do it now.

**Step 5: commit**

```bash
git add src/cli/doctor.ts test/doctor-local.test.ts
git commit -m "fix(doctor): check the lease for the named target"
```

---

### Task 7: plugin skill and eval

**Files:**
- Modify: `plugin/skills/daypass/SKILL.md` (:12-25)
- Modify: `plugin/skills/daypass-status/SKILL.md`
- Create: `plugin/evals/two-leases/prompt.md`, `plugin/evals/two-leases/mocks/daypass/daypass_status.md`, `plugin/evals/two-leases/graders/{skill-fired,query-has-target,judge}.md`

**`plugin/skills/daypass/SKILL.md`, section "1. Check the lease first"** `[R8]`:
- Keep the `No lease open.` / `Expired at …` rule for one lease.
- Replace the paragraph "`daypass_status` does not name the target …" with: with one lease, the status does not name an expired lease's target, so use the target from the conversation or leave `<target>`. Never read `~/.daypass/config.json` or `lease.json`.
- Add: **Several leases.** `daypass_status` may print one line per lease (`Lease <id> on "<t>" … min left …` or `Lease <id> on "<t>" expired at …`) and a last line `Pass target: "a" or "b" …`. Then pass `target` on **every** `list_tables`, `describe_table`, `query` and `explain` call, chosen from the question. If the question does not say which database, ask in one line and stop. Name the target in the answer and in the sign-off.
- Add `[R11]`: to end a lease, suggest `daypass close <target>`. Never run or suggest bare `daypass close` unless the user asks to close everything: it closes every lease.

**`plugin/skills/daypass-status/SKILL.md`:** "The CLI prints exactly one of these" → "The CLI prints `No lease.` or one line per lease". An expired line now ends `Run: daypass close <target>`; tell the user that exact command. With several lines, report each lease.

**Eval `two-leases`:**

`prompt.md`:

```md
---
name: two-leases
description: Leases are open on "staging" and "prod". The question names staging. The skill must call daypass_status first and pass target "staging" on every data tool call.
max_turns: 25
timeout_seconds: 400
allowed_tools: [Skill]
---

On staging, how many users signed up each day from 22 to 28 October 2026?
```

`mocks/daypass/daypass_status.md`:

```
Lease 7f3a2c1e on "staging" by arn:aws:sts::123456789012:assumed-role/dev/alex: 38 min left. Reason: why did signups drop on Monday
Lease 9b1d4e7a on "prod" by arn:aws:sts::123456789012:assumed-role/dev/alex: 12 min left. Reason: check invoice totals
Pass target: "staging" or "prod" to the other tools.
```

(The other tools fall back to the shared mocks in `plugin/evals/mocks/daypass/`. Check that a case-level `mocks/` dir with only one file still falls back; if not, copy the others from `plugin/evals/no-lease/mocks/daypass/`'s sibling shared mocks.)

`graders/skill-fired.md`: copy `plugin/evals/no-lease/graders/skill-fired.md`.

`graders/query-has-target.md`:

```md
---
type: tool_used
tool: mcp__plugin_daypass_daypass__query
input_match: '"target"\s*:\s*"staging"'
min: 1
---
```

`graders/judge.md` (type `llm`): PASS if daypass_status came first, every data tool call passed `target: "staging"`, nothing was run against prod, and the answer names staging and lease `7f3a2c1e`. FAIL otherwise.

Run: `claude plugin eval ./plugin --case two-leases --runs 1 --ablation none --scaffold --trust-plugin --no-publish`, then the `no-lease` and `lease-simple-question` cases the same way (they must still pass).

**Commit:**

```bash
git add plugin/skills plugin/evals/two-leases
git commit -m "feat(plugin): pass target when several leases are open"
```

---

### Task 8: docs `[R13]`

Edit each of these. Keep the house style: short sentences, exact commands.

| File | Change |
|---|---|
| `docs/concepts.md:7` | `daypass_status` returns `No lease open.`, `Expired at …` (one lease), or one line per lease (several). |
| `docs/concepts.md:22` | Replace "One per laptop" with: **One per target.** Not per Claude session. `daypass open a` then `daypass open b` gives two leases. Opening a target that already has a live lease is refused (exit 1): `A lease is already open on "staging" (85d19374, until …). Run: daypass close staging`. With two or more open, every tool needs a `target` argument. Two targets behind the same security group and port cannot be open at once. `daypass close` with no target closes all. |
| `docs/troubleshooting.md:120` | Drop "only one lease exists at a time". Say: `daypass status` lists every lease; open one for this target. |
| `docs/troubleshooting.md:306-308` | New heading `A lease is already open on "<t>" … Run: daypass close <t>`; refused only for the same target. Add two new entries: `N leases are open (a, b). Pass target: …` (a tool error: name the target in the question) and `needs the same security-group rule as the live lease on "<t>"` (close that one first). |
| `docs/threat-model.md:12` | "tools work only while `~/.daypass/lease.json` holds a live lease for the target the call uses". |
| `docs/threat-model.md:14` | "one connection per target per server process". |
| `docs/threat-model.md` (limits section) | PII hook uses one hidden-columns list for every target (D11). |
| `docs/launch/release-notes-next.md:72-73` | "`daypass open` exits 1 when that target already has a live lease." |
| `README.md`, `docs/faq.md` | `grep -n "one lease\|lease is already\|daypass close" README.md docs/faq.md`; fix any one-lease wording. |
| `src/cli/main.ts` help | Already done in Task 5 (`close [target]`). Check `sweep`'s description still fits. |

**Upgrade note for the PR body** (CHANGELOG is written by release-please from commits) `[R2]`:
- A file with one lease is unchanged, so upgrading changes nothing until a second lease is opened.
- With two or more leases open, a daypass 0.2.0 process reads the file as corrupt. **Restart Claude Code sessions after `npm i -g daypass`.** A downgrade with several leases open: run `daypass close` once.

**Commit:** `docs: several leases at once, one per target`.

---

### Task 9: verify

```bash
npm run build && npm test                       # all green; "113 skipped" is normal without a test DB
DAYPASS_TEST_PG_URL='postgres://postgres:postgres@localhost:5472/postgres?sslmode=disable' npm test
grep -rn 'readLease\b' src test                 # empty
bash scripts/scrub-check.sh                     # clean
SCRUB_HISTORY_RANGE=origin/main..HEAD bash scripts/scrub-check.sh
```

Manual, with two URL targets `a` and `b` on the local container:

1. `daypass open a -r x --ttl 5m` → `cat ~/.daypass/lease.json` is a bare lease (0.2.0 shape).
2. `daypass open b -r y --ttl 5m` → file has `"version": 2`; `daypass status` shows two lines.
3. In Claude Code, ask a question naming `b`. Check `daypass log` shows target `b`.
4. Ask without naming one. Claude must ask which database.
5. `daypass close b` → file back to the bare shape. `daypass close` → file gone.

Use @superpowers:verification-before-completion before saying it's done.

Open the PR as `Sajal0208`, title `feat: several leases at once, one per target`, with the upgrade note from Task 8. Do not merge before the 2026-11-10 launch.
