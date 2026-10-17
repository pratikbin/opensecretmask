// Offline checks for the expanded patterns. Never prints credential values.
import { RULES, scan } from "../hooks/detect";
import { literalPrefix } from "../hooks/detect/prefix";
import { Vault } from "../hooks/vault";
import { patternFixtures, patternDecoys } from "./pattern-fixtures";

export function checkPatterns(ok: (name: string, condition: boolean) => void) {
  const shape = (value: string) =>
    value.replace(/[a-z]/g, "a").replace(/[A-Z]/g, "A").replace(/[0-9]/g, "9");
  const cases = patternFixtures();
  for (const c of cases) {
    // Several rules can share a name, one per fixed variant (`tvly-dev-`, `t1_`).
    const rule = RULES.find(
      (r) =>
        r.name === c.rule &&
        [...c.text.matchAll(new RegExp(r.re))].some((m) => m[r.group] === c.value),
    );
    const match = !!rule;
    ok(`PAT ${c.name} extracts the whole credential`, !!match);
    ok(
      `PAT ${c.name} survives the scanner gate`,
      scan(c.text).some((f) => f.value === c.value),
    );
    ok(
      `PAT ${c.name} keeps a sentence-ending dot`,
      scan(c.value + ".").some((f) => f.value === c.value),
    );
    const vault = new Vault();
    const masked = vault.mask(`before\n${c.text}\nafter`, "pattern-check");
    const entry = vault.ledger().find((e) => e.secret === c.value);
    ok(`PAT ${c.name} masks completely`, !!entry && !masked.includes(c.value));
    ok(
      `PAT ${c.name} preserves length and classes`,
      !!entry && shape(entry.fake) === shape(c.value),
    );
    ok(
      `PAT ${c.name} preserves syntax and round-trips`,
      vault.unmask(masked) === `before\n${c.text}\nafter`,
    );
    if (c.prefix) ok(`PAT ${c.name} keeps the vendor prefix`, !!entry?.fake.startsWith(c.prefix));
    // A second occurrence and an isolated value must use the remembered pair.
    if (entry) ok(`PAT ${c.name} remembers a bare value`, vault.mask(c.value) === entry.fake);
    if (rule?.group === 0) {
      ok(
        `PAT ${c.name} works in JSON`,
        scan(JSON.stringify({ value: c.value })).some((f) => f.value === c.value),
      );
    }
  }
  for (const [i, text] of patternDecoys.entries()) {
    ok(`PAT decoy ${i + 1} stays readable`, new Vault().mask(text) === text);
  }
  for (const c of cases.filter((c) =>
    RULES.find((r) => r.name === c.rule)?.re.source.startsWith("\\b"),
  )) {
    ok(`PAT ${c.name} rejects a glued word`, scan("x" + c.value).length === 0);
  }
  for (const name of [
    "OpenRouter API Key",
    "Firecrawl API Key",
    "E2B API Key",
    "SonarQube User Token",
  ]) {
    const c = cases.find((c) => c.rule === name)!;
    const r = RULES.find((r) => r.name === name)!;
    ok(`PAT ${name} rejects short values`, !new RegExp(r.re).test(c.value.slice(0, -1)));
    ok(`PAT ${name} rejects an extra token character`, !new RegExp(r.re).test(c.value + "a"));
  }
  // A sentence-ending dot is punctuation, not a routing suffix. Preserve
  // legacy PAT/runner handling as well as the newly supported routed forms.
  for (const prefix of ["glpat-", "glrt-"]) {
    const value = prefix + "A".repeat(20);
    for (const punctuation of [".", ",", ";", ")", "]"]) {
      ok(
        `PAT ${prefix} legacy token before ${punctuation}`,
        scan(value + punctuation).some((f) => f.value === value),
      );
    }
  }
  ok(
    "PAT word boundary keeps the literal prefix",
    literalPrefix("\\btskey-api-[A-Za-z0-9]+") === "tskey-api-",
  );
  ok("PAT word boundary alone is not a literal", literalPrefix("\\b[A-Za-z]+") === "");
}
