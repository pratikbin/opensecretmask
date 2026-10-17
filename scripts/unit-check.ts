// Unit checks for the pure logic, runnable without Claude Code:
//
//   bun run scripts/unit-check.ts
//
// The hook-level checks live in tests/register.test.ts, run by
// `claude plugin test .`. This file covers the detector, the vault, the .env
// parser, the persistence split and the budget.

const R = new URL("../hooks", import.meta.url).pathname;
const { Vault } = await import(`${R}/vault/index.ts`);
const { scan, RULES, gatesIn, SIGNATURES } = await import(`${R}/detect/index.ts`);
const { garble } = await import(`${R}/vault/garble.ts`);
const { literalPrefix } = await import(`${R}/detect/prefix.ts`);
const { parseEnv, parseValue } = await import(`${R}/env.ts`);
const { isModelFacing, RESERVED } = await import(`${R}/policy/model-facing.ts`);
const { denyRules } = await import(`${R}/detect/rules/deny.ts`);
const { isPlaceholder, denialOf } = await import(`${R}/detect/suppress.ts`);
const { inbound, outbound } = await import(`${R}/policy/boundary.ts`);
const { isOpaque } = await import(`${R}/vault/walk.ts`);
const { load, save, prune, identityKey, resetKnownStore } = await import(`${R}/vault/persist.ts`);
const { readOptions } = await import(`${R}/options.ts`);
const { guard } = await import(`${R}/policy/budget.ts`);
const { elide, secretsTable, provenance, age } = await import(`${R}/events/command.ts`);
const { maskBlocks, withhold, WITHHELD } = await import(`${R}/events/append.ts`);

let pass = 0,
  fail = 0;
const ok = (n: string, c: boolean) => {
  c ? pass++ : fail++;
  console.log(`${c ? "PASS" : "FAIL"}  ${n}`);
};

/** A string the rules must mask, and a look-alike they must leave alone. */
const hit = (label: string, text: string) => ok(label, new Vault().mask(text) !== text);
const keep = (label: string, text: string) => ok(`keeps ${label}`, new Vault().mask(text) === text);

const KEY = "sk-ant-api03-" + "A".repeat(40);
console.log(`rules: ${RULES.length}\n`);

// F1 Agent.prompt keeps its fake
{
  const v = new Vault();
  const fake = v.maskOf(KEY);
  const agent: any = inbound(v, { tool: "Agent", prompt: `use ${fake}`, description: fake } as any);
  ok("F1 Agent.prompt keeps the fake", !agent.prompt.includes(KEY) && agent.prompt.includes(fake));
  const ask: any = inbound(v, { tool: "AskUserQuestion", questions: [{ q: fake }] } as any);
  ok("F1 AskUserQuestion keeps the fake", ask.questions[0].q === fake);
  const bash: any = inbound(v, { tool: "Bash", command: `curl -H "k: ${fake}"` } as any);
  ok("F1 Bash.command still restored", bash.command.includes(KEY));
  ok("F1 agentId is reserved", RESERVED.has("agentId"));
  ok(
    "F1 keep-fakes table",
    isModelFacing("Agent", "prompt") &&
      isModelFacing("AskUserQuestion", "questions") &&
      !isModelFacing("Bash", "command"),
  );
}

// F3 tool-result context masked
{
  const v = new Vault();
  const up: any = outbound(v, { result: {}, text: "", context: [`leaked ${KEY}`], ref: 7 } as any);
  ok("F3 result.context masked", !up.context[0].includes(KEY));
  ok("F3 ref dropped on rewrite", up.ref === undefined);
}

// F6 remember-once
{
  const v = new Vault();
  const secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
  v.mask(`aws_secret_access_key = "${secret}"`);
  ok("F6 bare value masked later", !v.mask(`value is ${secret}`).includes(secret));
}

// F7 whole PEM block
{
  const pem = `-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx7Vv9mQKcE2pL0bTn5sYhQwR3kZdFgH8jN1cPqSvUwXyZaBc\n-----END RSA PRIVATE KEY-----`;
  ok(
    "F7 PEM body masked",
    !new Vault().mask(pem).includes("MIIEowIBAAKCAQEAx7Vv9mQKcE2pL0bTn5sYhQwR3kZdFgH8"),
  );
}

// F8 .env comments
{
  ok(
    "F8 unquoted comment stripped",
    parseValue("hunter2-correct-horse # prod") === "hunter2-correct-horse",
  );
  ok("F8 quoted + comment", parseValue('"abc123def456" # staging') === "abc123def456");
  ok("F8 plain value intact", parseValue("justthevalue") === "justthevalue");
  const m = parseEnv('A=1 # x\n# comment\nB="two" # y\n');
  ok("F8 parseEnv", m.get("A") === "1" && m.get("B") === "two");
}

// F9 binary payloads skipped
{
  const png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQ==";
  const v = new Vault({ entropy: true, entropyThreshold: 4.0, entropyMinLen: 24 });
  const big = png.replace(/=+$/, "").repeat(60) + "=="; // >4KiB, padding only at the end
  const out: any = v.maskDeep({ type: "image", source: { data: big } });
  ok("F9 large base64 payload preserved", out.source.data === big);
  ok("F9 isOpaque(short base64) is false", !isOpaque(png));
  // The regression: skipping by key name skipped the whole subtree.
  const nested: any = v.maskDeep({ data: { apiKey: KEY }, payload: { token: KEY } });
  ok("F9 secret under `data` IS masked", nested.data.apiKey !== KEY);
  ok("F9 secret under `payload` IS masked", nested.payload.token !== KEY);
  const back: any = v.unmaskDeep({ data: { cmd: v.maskOf(KEY) } });
  ok("F9 fake under `data` restores", back.data.cmd === KEY);
}

// suppression: no FP on git SHA / UUID / Stripe public id
{
  const cfg = { entropy: true, entropyThreshold: 3.5, entropyMinLen: 24 };
  const sha = "a".repeat(4) + "9f2c1e7b3d5a8c04e6f1b2d39c7e5a10";
  const txt = `commit ${sha} price_1MqLyJ2eZvKYlo2C price_abc uuid 550e8400-e29b-41d4-a716-446655440000`;
  const v = new Vault(cfg);
  ok("SUP git SHA not masked", v.mask(txt).includes(sha));
  ok("SUP stripe public id kept", v.mask(txt).includes("price_1MqLyJ2eZvKYlo2C"));
  ok("SUP uuid kept", v.mask(txt).includes("550e8400-e29b-41d4-a716-446655440000"));
  // but a named key still wins
  const v2 = new Vault(cfg);
  const named = `api_key = ${sha}`;
  ok("SUP named key still masked", !v2.mask(named).includes(sha));
  // The general "a credential name sits to the left" rule outranks the list.
  const v3 = new Vault(cfg);
  const prefixed = "pi_9fX2qLmZ4vT7bN1cQ8wE3rY6uI0oP5aS";
  ok("SUP bare public prefix kept", v3.mask(`id ${prefixed}`).includes(prefixed));
  ok(
    "SUP named public prefix masked",
    !new Vault(cfg).mask(`secret_key = ${prefixed}`).includes(prefixed),
  );
  ok(
    "SUP pk_ stays public even when named",
    new Vault(cfg)
      .mask("secret_key = pk_live_9fX2qLmZ4vT7bN1cQ8wE3rY6")
      .includes("pk_live_9fX2qLmZ4vT7bN1cQ8wE3rY6"),
  );
}

// walk depth bound
{
  let deep: any = KEY;
  for (let i = 0; i < 40; i++) deep = { n: deep };
  const v = new Vault();
  ok("WALK deep object does not blow the stack", typeof v.maskDeep(deep) === "object");
}

// OPT the module's fallbacks must be the manifest's declared defaults. The
// engine fills a declared option before register() sees it, so these only fire
// where the manifest does not reach — a --plugin-dir run, this harness. When
// the two disagreed, every hook test ran a configuration nobody ships.
{
  const manifest = await Bun.file(
    new URL("../.claude-plugin/plugin.json", import.meta.url).pathname,
  ).json();
  const declared: Record<string, unknown> = {};
  for (const [name, spec] of Object.entries<any>(manifest.userConfig ?? {}))
    declared[name] = spec.default;
  const fallback: any = readOptions({} as any);
  ok("OPT persist is off without a manifest", fallback.persist === false);
  ok("OPT persist matches what the manifest declares", declared.persist === fallback.persist);
  ok("OPT retentionDays matches the manifest", declared.retentionDays === fallback.retentionDays);
  ok("OPT entropy matches the manifest", declared.entropy === fallback.detect.entropy);
  ok(
    "OPT entropyThreshold matches the manifest",
    declared.entropyThreshold === fallback.detect.entropyThreshold,
  );
  ok(
    "OPT entropyMinLen matches the manifest",
    declared.entropyMinLen === fallback.detect.entropyMinLen,
  );
  ok(
    "OPT envFiles matches the manifest",
    JSON.stringify(declared.envFiles) === JSON.stringify(fallback.envFiles),
  );
  // An explicit false must still turn it off, in either spelling.
  ok("OPT persist true is honoured", readOptions({ persist: true } as any).persist === true);
  ok("OPT persist false is honoured", readOptions({ persist: false } as any).persist === false);
  ok('OPT persist "false" is honoured', readOptions({ persist: "false" } as any).persist === false);
}

// persistence round trip: env ref carries no secret
{
  const v = new Vault();
  v.register("hunter2-correct-horse-staple", { kind: "env", file: "/p/.env", key: "DB_PASSWORD" });
  const entries = v.entries();
  const json = JSON.stringify(entries);
  ok("P env entry stores no secret", !json.includes("hunter2-correct-horse-staple"));
  ok("P env entry is a pointer", entries[0].kind === "env" && entries[0].key === "DB_PASSWORD");

  let stored: any;
  const port = {
    get: async () => stored,
    set: async (_k: string, v: unknown) => {
      stored = v;
    },
    readFile: async (p: string) =>
      p === "/p/.env" ? "DB_PASSWORD=hunter2-correct-horse-staple\n" : "",
  };
  await save(port, entries, 120);
  const resolved = await load(port, 120);
  ok(
    "P env entry rebinds from .env",
    resolved.length === 1 && resolved[0].secret === "hunter2-correct-horse-staple",
  );

  // literal entry does store the value, and expires
  const v2 = new Vault();
  v2.register(KEY);
  const lit = v2.entries(Date.now() - 200 * 86400000);
  ok("P literal entry stores value", JSON.stringify(lit).includes(KEY));
  ok("P literal expires past window", prune(lit, 120, Date.now()).length === 0);
  ok(
    "P env never expires",
    prune(
      entries.map((e) => ({ ...e, at: 0 })),
      120,
      Date.now(),
    ).length === 1,
  );
}

// RC reconciling a save against the store, not overwriting it. Two sessions
// share one store file, and a session's own snapshot only grows — so a save
// that just writes "everything I hold" resurrects anything a concurrent
// session purged since this one loaded. That happened twice in one day.
{
  const literal = (secret: string, fake: string) => ({
    kind: "literal" as const,
    fake,
    secret,
    at: Date.now(),
  });
  const snap = (entries: unknown[]) => ({ version: 1, entries });
  const portOver = (initial: unknown) => {
    let stored = initial;
    return {
      get: async () => stored,
      set: async (_k: string, v: unknown) => {
        stored = v;
      },
      readFile: async () => "",
      peek: () => stored as { entries: any[] } | undefined,
    };
  };

  ok(
    "RC identityKey ignores the fake",
    (() => {
      const a = literal("hunter2-correct-horse-one", "sk-ant-api03-aaaa");
      const b = { ...a, fake: "sk-ant-api03-bbbb" };
      return identityKey(a) === identityKey(b);
    })(),
  );
  ok(
    "RC identityKey separates env by file and key, not by value",
    (() => {
      const a = { kind: "env" as const, fake: "x", file: "/p/.env", key: "A", at: 0 };
      const b = { ...a, key: "B" };
      return identityKey(a) !== identityKey(b);
    })(),
  );

  {
    // A purge on disk must survive this session's next save, even though this
    // session's own vault never learned the entry was gone.
    const gone = literal("hunter2-correct-horse-gone", "sk-ant-api03-gggg");
    const port = portOver(snap([gone]));
    resetKnownStore();
    await load(port, 120); // seeds `known` with `gone`'s identity
    port.set("", snap([])); // another session purges it, out from under this one
    await save(port, [gone], 120); // this session still holds it; save() must not restore it
    ok("RC a purge is not resurrected by a stale save", port.peek()!.entries.length === 0);
  }

  {
    // A genuinely new entry, never seen on disk or by this session before,
    // must still be added — reconciling is not a synonym for "never write".
    const known = literal("hunter2-correct-horse-known", "sk-ant-api03-kkkk");
    const fresh = literal("hunter2-correct-horse-fresh", "sk-ant-api03-ffff");
    const port = portOver(snap([known]));
    resetKnownStore();
    await load(port, 120);
    await save(port, [known, fresh], 120);
    const secrets = port.peek()!.entries.map((e: any) => e.secret);
    ok("RC a genuinely new entry is added", secrets.includes("hunter2-correct-horse-fresh"));
  }

  {
    // A concurrent session's own new entry, which this session never adopted,
    // must not be dropped just because this session's own snapshot omits it.
    const mine = literal("hunter2-correct-horse-mine", "sk-ant-api03-mmmm");
    const theirs = literal("hunter2-correct-horse-theirs", "sk-ant-api03-tttt");
    const port = portOver(snap([mine]));
    resetKnownStore();
    await load(port, 120);
    port.set("", snap([mine, theirs])); // the other session adds its own entry
    await save(port, [mine], 120); // this session never saw `theirs`
    const secrets = port.peek()!.entries.map((e: any) => e.secret);
    ok(
      "RC a concurrent addition is not clobbered",
      secrets.includes("hunter2-correct-horse-theirs"),
    );
  }

  {
    // A read failure must skip the save outright, not read as "disk was
    // empty" — that would silently erase every entry a concurrent session
    // has written.
    const theirs = literal("hunter2-correct-horse-guard", "sk-ant-api03-uuuu");
    let stored = snap([theirs]);
    const port = {
      get: async () => {
        throw new Error("store unreadable");
      },
      set: async (_k: string, v: unknown) => {
        stored = v;
      },
      readFile: async () => "",
    };
    resetKnownStore();
    await save(port, [], 120);
    ok(
      "RC a read failure skips the save rather than erasing the store",
      (stored as any).entries.length === 1,
    );
  }

  resetKnownStore();
}

// DS a degraded store. Everything below reached the vault through `load()`
// once, and the empty case made every later mask() cut between every
// character of every string. The happy-path round trip above cannot see any
// of it, which is why the bug shipped with 85 checks green.
{
  const snap = (entries: unknown[]) => ({ version: 1, entries });
  const portFor = (stored: unknown, files: Record<string, string> = {}) => ({
    get: async () => stored,
    set: async () => undefined,
    readFile: async (p: string) => {
      const text = files[p];
      if (text === undefined) throw new Error("ENOENT");
      return text;
    },
  });
  const envEntry = {
    kind: "env",
    fake: "sk-ant-api03-ffff",
    file: "/p/.env",
    key: "TOKEN",
    at: Date.now(),
  };

  const drops = async (label: string, env: string | undefined) => {
    const files = env === undefined ? {} : { "/p/.env": env };
    const got = await load(portFor(snap([envEntry]), files), 120);
    ok(`DS drops ${label}`, got.length === 0);
  };
  await drops("an emptied key", "TOKEN=");
  await drops("a key emptied with quotes", 'TOKEN=""');
  await drops("a value under the minimum", "TOKEN=abc");
  await drops("a key that is gone", "OTHER=hunter2-correct-horse");
  await drops("a file that no longer reads", undefined);

  const kept = await load(
    portFor(snap([envEntry]), { "/p/.env": "TOKEN=hunter2-correct-horse" }),
    120,
  );
  ok("DS keeps a key that still resolves", kept.length === 1);

  // A store written by an older or broken writer, straight from JSON.
  const literal = { kind: "literal", fake: "sk-ant-api03-gggg", secret: "", at: Date.now() };
  const badLiteral = await load(portFor(snap([literal])), 120);
  ok("DS an empty literal does not resolve", badLiteral.length === 0);
  ok(
    "DS an empty literal never survives adoption",
    (() => {
      const v = new Vault();
      for (const r of badLiteral) v.adopt(r.entry.fake, r.secret);
      return v.size === 0 && v.mask("hello world") === "hello world";
    })(),
  );

  for (const [label, raw] of [
    ["a missing store", undefined],
    ["a store of the wrong version", { version: 99, entries: [] }],
    ["a store whose entries are not an array", { version: 1, entries: "nope" }],
    ["a store entry of the wrong shape", snap([{ kind: "env", fake: 1 }])],
    ["a store that throws on read", "THROW"],
  ] as [string, unknown][]) {
    const port =
      raw === "THROW"
        ? {
            ...portFor(undefined),
            get: async () => {
              throw new Error("store gone");
            },
          }
        : portFor(raw);
    ok(`DS survives ${label}`, (await load(port, 120)).length === 0);
  }

  // The invariant the whole file exists to protect: whatever the store says,
  // a vault built from it leaves ordinary text alone.
  const v = new Vault();
  for (const bad of ["", " ", "\n", "a", "short"]) v.adopt(`sk-ant-api03-${bad || "x"}zz`, bad);
  ok("DS no short or blank secret enters the map", v.size === 0);
  ok(
    "DS ordinary text is untouched by a poisoned store",
    v.mask("the quick brown fox") === "the quick brown fox",
  );
}

// budget: a hook that cannot mask denies instead of being skipped
{
  ok(
    "B sync throw falls back",
    guard(
      () => {
        throw new Error("x");
      },
      () => "DENIED",
    ) === "DENIED",
  );
  ok(
    "B sync ok wins",
    guard(
      () => "OK",
      () => "DENIED",
    ) === "OK",
  );
}

// rules recovered from the Go proxy's detector, plus the PGP header it caught
// and the plugin did not
{
  hit(
    "PX PGP block",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBGXyz1kBCADP3n2VqK8\n-----END PGP PRIVATE KEY BLOCK-----",
  );
  hit("PX Terraform Cloud", "AbCdEf12345678.atlasv1." + "z".repeat(70));
  hit("PX Sentry DSN", "https://a1b2c3d4e5f60718293a4b5c6d7e8f90@o12345.ingest.sentry.io/678901");
  hit("PX Atlassian token", "ATATT3xFfGF0" + "a".repeat(185));
  hit("PX Notion legacy secret", "secret_" + "a".repeat(43));
  hit("PX Bearer header", "Authorization: Bearer abcdef1234567890ABCDEFghijkl");
  // The scan gate is case-sensitive, so a case-insensitive rule must not be
  // gated on its prefix. A lowercase header once went through unmasked.
  hit("PX Bearer header, lowercase", "authorization: bearer abcdef1234567890ABCDEFghijkl");
  hit("PX Bearer header, mixed case", "AUTHORIZATION: BEARER abcdef1234567890ABCDEFghijkl");
  hit("PX connection string, uppercase scheme", "POSTGRES://admin:hunter2horsebattery@db:5432/app");
  hit("PX access_token in URL", "https://api.example.com/v1/x?access_token=abcdef1234567890ABCDEF");
  hit("PX Twilio account SID", "ACa1b2c3d4e5f60718293a4b5c6d7e8f90");
  // The DSN keeps its shape: only the key half is masked.
  const dsn = new Vault().mask(
    "https://a1b2c3d4e5f60718293a4b5c6d7e8f90@o12345.ingest.sentry.io/678901",
  );
  ok("PX Sentry DSN keeps the host", dsn.includes("@o12345.ingest.sentry.io/678901"));
  // And the new rules do not fire on ordinary text.
  keep("a bare Authorization line", "Authorization: Bearer");
  keep("a sentry issue URL", "https://sentry.io/organizations/acme/issues/12345");
  keep("an ordinary query string", "https://example.com/docs?page=2&sort=name");
}

// FP the classes the session store showed masked and should not have been
{
  const PW = String.fromCharCode(80, 65, 83, 83, 87, 79, 82, 68);
  keep("a connection-string placeholder", `postgres://user:${PW}@db:5432/app`);
  keep("an env var reference", "DATABASE_PASSWORD=${DB_PASSWORD}");
  keep("a shell var reference", 'API_KEY="$ANTHROPIC_API_KEY"');
  keep("a windows var reference", "API_TOKEN=%API_TOKEN%");
  keep("an angle-bracket placeholder", "API_KEY=<your-api-key-here>");
  keep("a bracketed placeholder", "API_TOKEN=[MASKED-0001]");
  keep("a documentation word", "SECRET_KEY=changeme");
  keep("a uuid under a credential name", "SESSION_TOKEN=550e8400-e29b-41d4-a716-446655440000");
  keep(
    "a rule regex read out of this repo",
    String.raw`/\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s/@:]{1,80}:([^\s/@]{3,200})@/gi`,
  );
  keep("a truncated key from documentation", "sk-ant-api03-Zx8Q2mLp");
  keep("a truncated openai key", "sk-proj-Zx8Q2mLp");
  keep("an ssn inside a longer run", "build 1234-56-78901");
  // `\S{8,}` does not stop at whitespace that is not there: a second
  // NAME=value glued straight onto the first reads as one token, and the
  // session store held exactly this — a captured value that was itself
  // `ARTIFACT_TOKEN=oss://bucket/path`, which `Secret reference` alone cannot
  // deny because that rule requires the whole value to be a bare locator.
  keep(
    "a second assignment glued to the first",
    "CONFIG_API_KEY=ARTIFACT_TOKEN=oss://my-bucket/path/to/object",
  );

  // And the real things the same rules exist for still go.
  hit("FP a full anthropic key", KEY);
  hit("FP a hex value under a credential name", `SERVICE_API_KEY=${"a1b2c3d4".repeat(4)}`);
  hit("FP a password in a connection string", "postgres://user:hunter2horsebattery@db:5432/app");
  hit("FP a bare ssn", "ssn 123-45-6789");

  // The capture must stop at the value, not run into the quote that follows.
  const v = new Vault();
  const masked = v.mask(`SERVICE_API_KEY="${"a1b2c3d4".repeat(4)}",`);
  ok(
    "FP capture keeps the surrounding syntax",
    masked.endsWith('",') && !masked.includes("a1b2c3d4"),
  );
}

// EM an empty secret must never enter the map: mask() splits on it, so one
// such entry rebuilds every string around the fake, character by character.
{
  const v = new Vault();
  v.adopt("sk-ant-api03-zzzz", "");
  ok("EM empty secret is refused", v.size === 0);
  ok("EM text survives an attempted empty adopt", v.mask("hello world") === "hello world");
  v.adopt("", KEY);
  ok("EM empty fake is refused", v.size === 0);

  // maskOf is public and mints on the spot, so it is a door of its own.
  const m = new Vault();
  ok("EM maskOf returns an empty secret unchanged", m.maskOf("") === "");
  ok("EM maskOf refuses a secret under the minimum", m.maskOf("short") === "short");
  ok("EM neither entered the map", m.size === 0);
  ok("EM text survives an attempted empty maskOf", m.mask("abc") === "abc");

  // The trivial cases, so nobody has to re-derive that they are safe.
  const t = new Vault();
  t.register("");
  ok("EM register refuses an empty secret", t.size === 0);
  ok("EM masking an empty string is an empty string", t.mask("") === "");
  ok("EM unmasking an empty string is an empty string", t.unmask("") === "");
  ok(
    "EM an empty string inside a tree is untouched",
    JSON.stringify(t.maskDeep({ a: "", b: [""] })) === '{"a":"","b":[""]}',
  );
}

// DY the deny rules: declared beside the rules they answer, same as a rule.
{
  ok(
    "DY every deny rule carries a reason",
    denyRules.every((d: any) => d.why.length > 0),
  );
  // `test()` on a global regex carries lastIndex between calls and starts
  // skipping matches, which would let a placeholder through every other time.
  ok(
    "DY no deny rule is global",
    denyRules.every((d: any) => !d.re.flags.includes("g")),
  );
  ok("DY a deny rule names itself", denialOf("${DB_PASSWORD}")?.name === "Variable reference");
  ok(
    "DY a uuid is denied as an identifier",
    denialOf("550e8400-e29b-41d4-a716-446655440000")?.name === "UUID",
  );
  ok(
    "DY a secret reference is denied as a locator",
    denialOf("op://my-vault/db/password")?.name === "Secret reference",
  );
  ok(
    "DY a plain url under a credential name is denied",
    denialOf("https://example.com/a/b")?.name === "Secret reference",
  );
  // A DSN carrying its password inline is NOT a locator. `Connection String
  // Password` masks that group by itself, and denying the whole value here
  // would put the password back in the clear.
  ok(
    "DY a dsn with inline credentials is not denied",
    denialOf("postgres://user:Xk29fmQpLz@host/db") === undefined,
  );
  ok("DY a real value is denied by nothing", denialOf("hunter2-correct-horse") === undefined);
  ok("DY hex under a name is still a candidate", !isPlaceholder("a1b2c3d4".repeat(4)));
  ok(
    "DY a glued second assignment is denied as chained",
    denialOf("ARTIFACT_TOKEN=oss://my-bucket/path")?.name === "Chained assignment",
  );
  // The value must actually be credential-named, or a base64 secret that
  // happens to contain '_' or '-' before its own '=' padding would be denied.
  ok(
    'DY a value merely containing "=" is not denied as chained',
    denialOf("QWxhZGRpbi1vcGVuX3Nlc2FtZQ==") === undefined,
  );
}

// round trip still works
{
  const v = new Vault();
  const body = `export ANTHROPIC_API_KEY=${KEY}\ncurl -H "x-api-key: ${KEY}"`;
  const m = v.mask(body);
  ok("RT secret gone", !m.includes(KEY));
  ok("RT prefix kept", m.includes("sk-ant-"));
  ok("RT round trip", v.unmask(m) === body);
  ok("RT idempotent", v.mask(m) === m);
}

// LG the ledger behind /osm-secrets
{
  ok("LG elide hides the middle only", elide("0123456789") === "0123•••789");
  ok("LG elide leaves both ends", elide(KEY).startsWith("sk-ant-") && elide(KEY).endsWith("AAA"));
  ok("LG elide keeps the length", elide(KEY).length === KEY.length);

  const v = new Vault();
  v.register(KEY, { file: "/work/.env", key: "ANTHROPIC_API_KEY" });
  const fake = v.maskOf(KEY);
  v.mask(`use ${KEY} twice: ${KEY}`, "Bash");
  v.unmask(`curl ${fake}`);

  const [entry] = v.ledger();
  ok(
    "LG ledger records the env source",
    entry.file === "/work/.env" && entry.key === "ANTHROPIC_API_KEY",
  );
  ok("LG ledger counts substitutions", entry.masked === 2 && entry.restored === 1);
  ok("LG ledger pairs the fake with the secret", entry.fake === fake && entry.secret === KEY);

  const found = new Vault().mask(`token ${KEY}`, "Read");
  const noted = new Vault();
  noted.mask(`token ${KEY}`, "Read");
  const [seen] = noted.ledger();
  ok("LG ledger names the rule that fired", seen.rule !== "detected" && seen.rule.length > 0);
  ok("LG ledger names the channel", seen.where === "Read" && found !== "");

  // A capture-group rule's evidence is the context it matched, not the
  // extracted value's own shape: `DB_PASSWORD=hunter2-…` carries the rule,
  // `hunter2-…` alone carries nothing a whole-value rule would recognise.
  // Re-deriving the rule by re-scanning the bare value after the fact — what
  // mask() used to do — mislabels every context-caught secret `detected`,
  // which is indistinguishable from "no rule fired" and made an unrelated
  // debt of stale store entries look like the ruleset's fault.
  const ctxVault = new Vault();
  ctxVault.mask("DB_PASSWORD=hunter2-correct-horse-battery-staple", "Bash");
  const [ctxSeen] = ctxVault.ledger();
  ok(
    "LG a context-caught secret keeps its real rule name",
    ctxSeen.rule === "Environment Variable Secret",
  );

  // What the store carries back: the row must still name the rule, the
  // channel and the first sighting, not the moment of the reload.
  const next = new Vault();
  for (const e of v.entries())
    next.adopt(
      e.fake,
      e.kind === "env" ? KEY : e.secret,
      e.kind === "env" ? { file: e.file, key: e.key } : undefined,
      e,
    );
  const carried = next.ledger()[0];
  ok(
    "LG provenance survives the store",
    carried.rule === entry.rule && carried.where === entry.where,
  );
  ok("LG first sighting survives the store", carried.at === entry.at);
  ok("LG table row has exactly one pair", secretsTable(v.ledger())[1]!.split("→").length === 2);
  ok(
    "LG table row names the rule and the channel",
    secretsTable(v.ledger())[1]!.includes(entry.rule) &&
      secretsTable(v.ledger())[1]!.includes(entry.where),
  );

  const table = secretsTable(v.ledger());
  ok("LG table never prints the whole secret", !table.join("\n").includes(KEY));
  ok("LG table pairs each secret with its fake", table.join("\n").includes(fake.slice(0, 10)));
  ok(
    "LG table keeps every row on one line",
    table.every((l: string) => !l.includes("\n") && l.length < 140),
  );
  ok("LG table says so when empty", secretsTable([])[0].includes("no secrets"));

  ok("LG provenance names the env file", provenance({ ...entry }).includes("/work/.env"));
  ok(
    "LG provenance does not repeat where it already equals file",
    // register() always sets where to the file itself for an env secret, so
    // showing both would spend half the budget saying the same path twice.
    (provenance({ ...entry }).match(/\/work\/\.env/g) ?? []).length === 1,
  );
  ok(
    "LG provenance falls back to where when there is no file",
    provenance(seen).includes(seen.where),
  );
  ok(
    "LG provenance is bounded even for a long rule name",
    provenance({ ...entry, rule: "X".repeat(80), file: undefined, key: undefined }).length <= 29,
  );

  const now = Date.now();
  ok("LG age counts seconds", age(now - 5_000, now) === "5s");
  ok("LG age counts minutes", age(now - 5 * 60_000, now) === "5m");
  ok("LG age counts hours", age(now - 5 * 3_600_000, now) === "5h");
  ok("LG age counts days", age(now - 5 * 86_400_000, now) === "5d");
  ok("LG age never goes negative", age(now + 10_000, now) === "0s");

  ok("LG table row shows the age", secretsTable(v.ledger(), Date.now())[1]!.includes("ago)"));
}

// The seven verified review findings, each locked to the behaviour that failed.
{
  // FX retention applies to the durable state, not only to what load() returns.
  const old = { kind: "literal", fake: "f", secret: "S".repeat(20), at: 0 };
  let disk: any = { version: 1, entries: [old] };
  const port = {
    get: async () => disk,
    set: async (_k: string, v: any) => {
      disk = v;
    },
    readFile: async () => "",
  };
  resetKnownStore();
  await save(port, [], 30);
  ok("FX save drops an expired literal from the store", disk.entries.length === 0);

  resetKnownStore();
  disk = { version: 1, entries: [{ ...old, at: Date.now() }] };
  await save(port, [], 30);
  ok("FX save keeps a literal inside the window", disk.entries.length === 1);

  // FX a failed write must report it, so the caller does not mark it saved.
  const dead = {
    get: async () => ({ version: 1, entries: [] }),
    set: async () => {
      throw new Error("full");
    },
    readFile: async () => "",
  };
  resetKnownStore();
  ok("FX save reports a failed write", (await save(dead as any, [], 120)) === false);
  resetKnownStore();
  ok("FX save reports a successful write", (await save(port, [], 120)) === true);
}

{
  // FX a fake that contains another registered secret must still round-trip.
  // garble copies a rule's literal prefix, so a registered prefix is inside
  // every fake of that vendor — the deterministic form of the cascade.
  const v = new Vault();
  const prefix = "sk-proj-x";
  const key = prefix + "B".repeat(40);
  v.register(key);
  v.register(prefix);
  const text = `token=${key} and bare=${prefix}`;
  const masked = v.mask(text);
  ok(
    "FX cascading replacement does not corrupt a fake",
    !masked.includes(key) && v.unmask(masked) === text,
  );
}

{
  // FX an opaque payload no longer skips the exact-match pass.
  const v = new Vault();
  const key = "sk-ant-api03-" + "C".repeat(40);
  v.register(key);
  const blob = "Q".repeat(5000) + key + "Z".repeat(500);
  ok("FX a registered secret is masked inside an opaque string", !v.mask(blob).includes(key));
  ok("FX an opaque string is still not scanned", isOpaque("Q".repeat(5000)));
}

{
  // FX a subagent's report is read by the parent's model.
  ok("FX SubagentHandback keeps its fakes", isModelFacing("SubagentHandback", "message"));
  ok(
    "FX SendMessage keeps its fakes",
    isModelFacing("SendMessage", "message") && !isModelFacing("SendMessage", "to"),
  );
}

{
  // AP every row a conversation keeps, masked before it is stored and sent.
  const v = new Vault();
  const sameShape = (s: string) => s.startsWith("sk-ant-") && s.length === KEY.length && s !== KEY;
  const [t]: any = maskBlocks([{ type: "text", text: KEY }], v, "append:attachment");
  ok("AP text block masked to a same-shaped fake", sameShape(t.text));
  const [r]: any = maskBlocks(
    [{ type: "tool_result", tool_use_id: "x", content: `out ${KEY}` }],
    v,
    "append:tool-result",
  );
  ok("AP tool_result string masked", !r.content.includes(KEY) && r.tool_use_id === "x");
  const image = { type: "image", source: { type: "base64", media_type: "image/png", data: KEY } };
  const [ra]: any = maskBlocks(
    [{ type: "tool_result", tool_use_id: "y", content: [{ type: "text", text: KEY }, image] }],
    v,
    "w",
  );
  ok("AP tool_result array: text masked", !ra.content[0].text.includes(KEY));
  ok("AP tool_result array: media block is the same object", ra.content[1] === image);
  const use = { type: "tool_use", id: "u", name: "Bash", input: { command: KEY } };
  ok("AP tool_use left as it arrived", maskBlocks([use], v, "w")[0] === use);
  const clean = [{ type: "text", text: "nothing here" }];
  ok("AP unchanged row is the same array", maskBlocks(clean, v, "w") === clean);
  const size = v.size;
  const faked = [{ type: "text", text: `again ${t.text}` }];
  ok("AP a fake is not minted again", maskBlocks(faked, v, "w") === faked && v.size === size);
  const held: any = withhold([
    { type: "text", text: KEY },
    { type: "tool_result", tool_use_id: "z", content: KEY },
    image,
  ]);
  ok(
    "AP withhold replaces text and tool_result",
    held[0].text === WITHHELD && held[1].content === WITHHELD && held[1].tool_use_id === "z",
  );
  ok("AP withhold keeps media", held[2] === image);
  ok("AP withhold is total", withhold(undefined).length === 0 && withhold([null, 5]).length === 2);
}

{
  // GATE every rule prefix must be seen wherever it occurs. A plain alternation
  // let `https://` consume the start of every webhook URL and `xox` the start
  // of `xoxe-`, and four rules never ran.
  const gates = [
    ...new Set(
      RULES.filter((r: any) => !r.re.flags.includes("i"))
        .map((r: any) => literalPrefix(r.re.source))
        .filter(Boolean),
    ),
  ] as string[];
  const hidden = gates.filter((g) => !gatesIn(`see ${g}tail`).has(g));
  ok(`GATE every one of ${gates.length} gates is found in text`, hidden.length === 0);
  ok(
    "GATE a shorter gate is found inside a longer one",
    gatesIn("xoxe-1-").has("xox") && gatesIn("xoxe-1-").has("xoxe-"),
  );
}

{
  // RD rules ported from claude-code-redact, fixtures generated so no whole
  // credential sits in this file.
  let seed = 7;
  const rnd = (n: number, abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") =>
    Array.from(
      { length: n },
      () => abc[(seed = (seed * 1103515245 + 12345) % 2 ** 31) % abc.length],
    ).join("");
  const UP = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const hook = `hooks.slack.com/services/T${rnd(8, UP)}/B${rnd(8, UP)}/${rnd(24)}`;
  hit("RD Slack webhook URL", `SLACK_WEBHOOK_URL=https://${hook}`);
  hit("RD Slack webhook without a scheme", `post to ${hook} now`);
  hit("RD Slack workflow webhook", `https://hooks.slack.com/workflows/T${rnd(8, UP)}/${rnd(40)}`);
  const sv = new Vault();
  ok(
    "RD Slack webhook fake keeps the host",
    sv.mask(`url ${hook}`).includes("url hooks.slack.com/"),
  );
  hit("RD Slack config refresh token", `t=xoxe-1-${rnd(48)}`);
  hit("RD Slack config access token", `t=xoxe.xoxp-1-${rnd(48)}`);
  hit(
    "RD Discord webhook URL",
    `https://discord.com/api/webhooks/${rnd(18, "0123456789")}/${rnd(68)}`,
  );
  hit("RD AWS ABIA key id", `id ABIA${rnd(16, UP)}`);
  hit("RD AWS ACCA key id", `id ACCA${rnd(16, UP)}`);
  hit("RD DSN with an empty user", `cache: redis://:${rnd(14)}@cache.internal:6379/0`);
  hit("RD Authorization Basic", `curl -H "Authorization: Basic ${rnd(24, B64)}" https://api.test`);
  hit("RD Authorization Token as JSON", `{"Authorization": "Token ${rnd(32)}"}`);
  hit(
    "RD Azure AccountKey",
    `DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=${rnd(86, B64)}==;EndpointSuffix=core.windows.net`,
  );
  hit("RD Azure storage key by name", `AZURE_STORAGE_KEY="${rnd(86, B64)}=="`);
  hit("RD OpenAI legacy 48", `old key sk-${rnd(48)} revoked`);
  keep("an OpenAI-shaped filler", `sk-${"a".repeat(48)}`);
  const lines = (n: number) => Array.from({ length: n }, () => rnd(64, B64)).join("\n");
  hit(
    "RD truncated private key",
    `$ head -4 id_rsa\n-----BEGIN RSA PRIVATE KEY-----\n${lines(3)}\n$ `,
  );
  hit(
    "RD truncated private key in JSON",
    `{"private_key": "-----BEGIN PRIVATE KEY-----\\n${lines(3).split("\n").join("\\n")}`,
  );
  const once = (text: string) => {
    const v = new Vault();
    v.mask(text);
    return v.ledger().length;
  };
  ok(
    "RD a whole key block is one secret, not two",
    once(`-----BEGIN RSA PRIVATE KEY-----\n${lines(5)}\n-----END RSA PRIVATE KEY-----`) === 1,
  );
  hit(
    "RD a PGP keyring past 20 000 characters",
    `-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n${lines(400)}\n=${rnd(4, B64)}\n-----END PGP PRIVATE KEY BLOCK-----`,
  );
  ok(
    "RD a whole PGP block with its checksum line is one secret",
    once(
      `-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n${lines(5)}\n=${rnd(4, B64)}\n-----END PGP PRIVATE KEY BLOCK-----`,
    ) === 1,
  );
}

{
  // CR findings from the branch review: each fixture failed before its fix.
  let seed = 11;
  const rnd = (n: number, abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") =>
    Array.from(
      { length: n },
      () => abc[(seed = (seed * 1103515245 + 12345) % 2 ** 31) % abc.length],
    ).join("");
  const UP = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const fakeOf = (value: string) => new Vault().mask(`x ${value} y`).slice(2, -2);

  const svc = `hooks.slack.com/services/T${rnd(10, UP)}/B${rnd(10, UP)}/${rnd(24)}`;
  ok("CR Slack fake keeps services/", fakeOf(svc).startsWith("hooks.slack.com/services/"));
  const wf = `hooks.slack.com/workflows/T${rnd(10, UP)}/A${rnd(10, UP)}/${rnd(18, "0123456789")}/${rnd(24)}`;
  ok(
    "CR long Slack workflow URL masked whole",
    fakeOf(wf) !== wf && !fakeOf(wf).endsWith(wf.slice(-24)),
  );
  const trig = `hooks.slack.com/triggers/T${rnd(10, UP)}/${rnd(13, "0123456789")}/${rnd(32, "0123456789abcdef")}`;
  ok("CR Slack trigger URL masked", fakeOf(trig) !== trig);

  keep("a 48-character id after risk-", `risk-${rnd(48)}`);
  hit("CR OpenAI 48 still caught after a space", `key sk-${rnd(48)}`);

  const azdo = `${rnd(75)}AZDO${rnd(5)}`;
  const af = fakeOf(azdo);
  ok(
    "CR Azure DevOps fake keeps AZDO in place",
    af !== azdo && af.indexOf("AZDO") === 75 && af.length === azdo.length,
  );

  ok("CR Tavily fake keeps dev-", fakeOf(`tvly-dev-${rnd(32)}`).startsWith("tvly-dev-"));
  ok(
    "CR GitLab runner fake keeps t1_",
    fakeOf(`glrt-t1_${rnd(30)}.${rnd(9, "abcdefghijklmnopqrstuvwxyz0123456789")}`).startsWith(
      "glrt-t1_",
    ),
  );

  {
    const body = (n: number) =>
      rnd(n, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
    const key = (b: string) => `-----BEGIN PRIVATE KEY-----\n${b}\n-----END PRIVATE KEY-----`;
    const bodies = [body(120), body(120)];
    const two = new Vault().mask(bodies.map((b) => key(b)).join("\n"));
    ok(
      "CR two adjacent private keys are both masked",
      bodies.every((b) => !two.includes(b)),
    );
    const start = performance.now();
    scan("-----BEGIN PRIVATE KEY-----\n".repeat(100_000));
    ok("CR 100k unclosed key headers scan in under 2 s", performance.now() - start < 2000);
  }
  hit(
    "CR GitLab runner with an unlisted discriminator (t4_)",
    `glrt-t4_${rnd(30)}.${rnd(9, "abcdefghijklmnopqrstuvwxyz0123456789")}`,
  );
  ok(
    "CR garble keeps AZDO only at its offset",
    !garble("a".repeat(10) + "AZDO" + "a".repeat(70), 0, SIGNATURES).includes("AZDO"),
  );
  hit("CR GitLab PAT before .Word", `token glpat-${rnd(20)}.Done`);
  hit("CR Bearer on the next line", `Authorization:\n  Bearer ${rnd(32)}`);
}

// Expanded vendor rules share fixtures with the live runner.
const { checkPatterns } = await import("./pattern-check");
checkPatterns(ok);

console.log(`\npassed ${pass}, failed ${fail}`);
if (fail) process.exit(1);
