/**
 * Constraint-layer awareness.
 *
 * SolAudit's rules historically pattern-matched handler bodies only. In
 * idiomatic Anchor programs, validation lives in `#[derive(Accounts)]`
 * structs (`Signer`, `owner =`, `has_one =`, `constraint =`, `seeds`/`bump`),
 * so handler-body scanning alone both misses real bugs and false-positives
 * on correctly-secured code. This module parses the constraint layer into a
 * lightweight model the rules can consult:
 *
 *  - which struct fields are typed `Signer<'info>` (SOL-001)
 *  - which raw `AccountInfo` fields carry owner/constraint bindings (SOL-008)
 *  - which fields referenced by manual deserialization are constrained (SOL-002)
 *  - which token-account fields are (not) bound to a mint in scope (SOL-013)
 *
 * It also maps function regions (handlers `fn ...(ctx: Context<T>)` and
 * `impl T { ... }` method blocks) so a rule can ask "which Accounts struct
 * governs the code at this offset?", and detects `#[cfg(test)]` ranges so
 * findings are never reported from test modules.
 *
 * Everything here is deliberately line/regex-based with brace matching — no
 * Rust compiler — to keep the engine fast, dependency-free, and predictable.
 * Suppression only ever happens on *positive* evidence; when the model is
 * unsure, rules keep their original conservative behavior.
 */

export interface AccountsField {
  name: string;
  /** Innermost wrapper type: Signer, Account, AccountInfo, UncheckedAccount, Program, AccountLoader, InterfaceAccount, ... */
  wrapperType: string;
  /** Generic argument after 'info, e.g. TokenAccount for Account<'info, TokenAccount>; null for bare types. */
  genericArg: string | null;
  /** Raw attribute text (comments stripped) attached to the field, e.g. `#[account(mut, has_one = owner)]`. */
  attrs: string;
  /** AccountInfo or UncheckedAccount — Anchor performs no automatic validation. */
  isRaw: boolean;
  /** Typed Signer<'info> or an explicit `#[account(signer)]` attribute. */
  isSignerTyped: boolean;
  /** Account/InterfaceAccount/Box-wrapped with generic arg TokenAccount. */
  isTokenAccount: boolean;
  /** Account/InterfaceAccount/Box-wrapped with generic arg Mint. */
  isMint: boolean;
  /**
   * Attrs contain owner= / constraint= / has_one= / address= / seeds= bindings.
   * `seeds`+`bump` pins the account to a program-derived address, which an
   * attacker cannot substitute — for validation purposes it counts.
   */
  validated: boolean;
  /** Attrs bind the token account to a mint (token::mint / associated_token::mint). */
  bindsTokenMint: boolean;
  /** Attrs contain init / init_if_needed. */
  hasInit: boolean;
  /** 1-indexed line of the field declaration. */
  line: number;
}

export interface AccountsStruct {
  name: string;
  start: number;
  end: number;
  fields: AccountsField[];
}

export interface FnRegion {
  start: number;
  end: number;
  contextType: string | null;
  implType: string | null;
}

export interface ConstraintModel {
  structs: AccountsStruct[];
  regions: FnRegion[];
  testRanges: Array<[number, number]>;
}

function stripComments(text: string): string {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .split(/\r\n|\r|\n/)
    .map((line) => line.replace(/\/\/.*$/, ""))
    .join("\n");
}

/** Replace double-quoted string literals with empty strings (format strings are not code). */
export function stripStringLiterals(line: string): string {
  return line.replace(/"(?:[^"\\]|\\.)*"/g, '""');
}

/** Brace-match from the index of an opening `{`. Returns index just past the matching `}`. */
export function matchBraces(content: string, openIdx: number): number {
  let depth = 0;
  let i = openIdx;
  let inLineComment = false;
  let inBlockComment = false;
  let inString = false;
  let inChar = false;

  while (i < content.length) {
    const c = content[i];
    const next = i + 1 < content.length ? content[i + 1] : "";

    if (inLineComment) {
      if (c === "\n") inLineComment = false;
    } else if (inBlockComment) {
      if (c === "*" && next === "/") {
        inBlockComment = false;
        i++;
      }
    } else if (inString) {
      if (c === "\\") i++;
      else if (c === '"') inString = false;
    } else if (inChar) {
      if (c === "\\") i++;
      else if (c === "'") inChar = false;
    } else if (c === "/" && next === "/") {
      inLineComment = true;
      i++;
    } else if (c === "/" && next === "*") {
      inBlockComment = true;
      i++;
    } else if (c === '"') {
      inString = true;
    } else if (c === "'" && /[a-zA-Z0-9_]/.test(next) && content[i + 2] === "'") {
      // char literal like 'a' (lifetime names like 'info have no closing quote)
      inChar = true;
    } else if (c === "{") {
      depth++;
    } else if (c === "}") {
      depth--;
      if (depth === 0) return i + 1;
    }
    i++;
  }
  return content.length;
}

const RAW_WRAPPERS = new Set(["AccountInfo", "UncheckedAccount"]);

function parseFields(structBody: string, structBodyOffset: number, content: string): AccountsField[] {
  const fields: AccountsField[] = [];
  // Capture leading attribute/doc lines, then `pub name: [Box<...>] Type<'info[, Generic]>,`
  // (struct fields are comma-terminated).
  const fieldRe =
    /((?:\s*(?:#\[[\s\S]*?\]|\/\/[^\n]*))*)\s*pub\s+(\w+)\s*:\s*((?:Box\s*<\s*)*)([\w:]+)\s*<\s*'info\s*(?:,\s*([\w:]+)\s*)?>[\s>]*/g;
  let m: RegExpExecArray | null;

  while ((m = fieldRe.exec(structBody)) !== null) {
    const attrs = stripComments(m[1] || "");
    const name = m[2];
    const wrapperType = m[4];
    const genericArg = m[5] || null;
    const offset = structBodyOffset + m.index;
    const line = content.slice(0, offset).split(/\r\n|\r|\n/).length;

    fields.push({
      name,
      wrapperType,
      genericArg,
      attrs,
      isRaw: RAW_WRAPPERS.has(wrapperType),
      isSignerTyped:
        wrapperType === "Signer" || /#\s*\[\s*account\(\s*signer\s*\)\s*\]/.test(attrs),
      isTokenAccount: genericArg === "TokenAccount",
      isMint: genericArg === "Mint",
      validated: /\b(owner|constraint|has_one|address|seeds)\s*=/.test(attrs),
      bindsTokenMint: /\b(?:token|associated_token)::mint\b/.test(attrs),
      hasInit: /\binit(_if_needed)?\b/.test(attrs),
      line,
    });
  }

  return fields;
}

function parseStructs(content: string): AccountsStruct[] {
  const structs: AccountsStruct[] = [];
  const deriveRe = /#\s*\[\s*derive\(\s*Accounts(?:\s*,\s*[\w:]+)*\s*\)\s*\]/g;
  let m: RegExpExecArray | null;

  while ((m = deriveRe.exec(content)) !== null) {
    // Find `pub struct Name ... {` shortly after the derive attribute.
    const afterIdx = m.index + m[0].length;
    const structRe = /pub\s+struct\s+(\w+)[^{]*\{/g;
    structRe.lastIndex = afterIdx;
    const sm = structRe.exec(content);
    if (!sm || sm.index - afterIdx > 400) continue;

    const openBrace = sm.index + sm[0].length - 1;
    const end = matchBraces(content, openBrace);
    const body = content.slice(openBrace + 1, end - 1);

    structs.push({
      name: sm[1],
      start: m.index,
      end,
      fields: parseFields(body, openBrace + 1, content),
    });
  }

  return structs;
}

function parseRegions(content: string): FnRegion[] {
  const regions: FnRegion[] = [];

  // impl blocks: impl<'info> Foo<'info> { ... }  (also impl Foo, impl Trait for Foo)
  const implRe = /\bimpl(?:\s*<[^>]*>)?\s+(\w+)(?:\s*<[^>]*>)?(?:\s+for\s+\w+(?:\s*<[^>]*>)?)?\s*\{/g;
  let im: RegExpExecArray | null;
  while ((im = implRe.exec(content)) !== null) {
    // `impl Trait for Foo` — methods belong to Foo; `impl Foo` — methods belong to Foo.
    const forMatch = im[0].match(/\bfor\s+(\w+)/);
    const implType = forMatch ? forMatch[1] : im[1];
    const openBrace = im.index + im[0].length - 1;
    const end = matchBraces(content, openBrace);
    regions.push({ start: im.index, end, contextType: null, implType });
  }

  // Handlers / functions taking ctx: Context<T>. Tolerates fully-qualified
  // lifetime parameters (`Context<'_, '_, '_, 'info, MultisigCreate<'info>>`)
  // and generic struct arguments (`Context<LiquidateEnd<'info>>`).
  const fnRe =
    /\bfn\s+\w+\s*(?:<[^>]*>)?\s*\(\s*(?:mut\s+)?ctx\s*:\s*Context\s*<\s*(?:(?:'\w+|'_)\s*,\s*)*(\w+)(?:\s*<[^>]*>)?\s*[,>]/g;
  let fm: RegExpExecArray | null;
  while ((fm = fnRe.exec(content)) !== null) {
    // Find the opening brace of the function body (past params and return type).
    let i = fm.index + fm[0].length;
    let parenDepth = 0;
    // consume rest of parameter list
    parenDepth = 1;
    while (i < content.length && parenDepth > 0) {
      if (content[i] === "(") parenDepth++;
      else if (content[i] === ")") parenDepth--;
      i++;
    }
    while (i < content.length && content[i] !== "{") {
      if (content[i] === ";") break; // declaration without body
      i++;
    }
    if (i >= content.length || content[i] !== "{") continue;
    const end = matchBraces(content, i);
    regions.push({ start: fm.index, end, contextType: fm[1], implType: null });
  }

  return regions;
}

function parseTestRanges(content: string): Array<[number, number]> {
  const ranges: Array<[number, number]> = [];
  const re = /#\s*\[\s*cfg\(\s*test\s*\)\s*\]/g;
  let m: RegExpExecArray | null;

  while ((m = re.exec(content)) !== null) {
    const braceIdx = content.indexOf("{", m.index + m[0].length);
    if (braceIdx === -1) continue;
    ranges.push([m.index, matchBraces(content, braceIdx)]);
  }

  return ranges;
}

function buildModel(content: string): ConstraintModel {
  return {
    structs: parseStructs(content),
    regions: parseRegions(content),
    testRanges: parseTestRanges(content),
  };
}

// Rules run sequentially over the same file content, so a single-entry memo
// avoids re-parsing the constraint model once per rule.
let cached: { content: string; model: ConstraintModel } | null = null;

export function getConstraintModel(content: string): ConstraintModel {
  if (cached && cached.content === content) return cached.model;
  const model = buildModel(content);
  cached = { content, model };
  return model;
}

/** True when `offset` falls inside any [start, end) range. */
export function inRanges(offset: number, ranges: Array<[number, number]>): boolean {
  return ranges.some(([s, e]) => offset >= s && offset < e);
}

/** The innermost function region (handler or impl method) containing `offset`, if any. */
export function innermostRegionAt(model: ConstraintModel, offset: number): FnRegion | null {
  let best: FnRegion | null = null;
  for (const r of model.regions) {
    if (offset >= r.start && offset < r.end) {
      if (!best || r.end - r.start < best.end - best.start) best = r;
    }
  }
  return best;
}

/** Look up the Accounts struct governing the code at `offset` (via handler Context or impl block). */
export function structAt(model: ConstraintModel, offset: number): AccountsStruct | null {
  const region = innermostRegionAt(model, offset);
  if (!region) return null;
  const name = region.contextType ?? region.implType;
  if (!name) return null;
  return model.structs.find((s) => s.name === name) ?? null;
}

/** Find a declared field by name across every Accounts struct in the file. */
export function findField(model: ConstraintModel, name: string): AccountsField | null {
  for (const s of model.structs) {
    const f = s.fields.find((f) => f.name === name);
    if (f) return f;
  }
  return null;
}

/** Convert a 0-indexed line number to an absolute offset. */
export function lineOffset(lines: string[], idx: number): number {
  let off = 0;
  for (let i = 0; i < idx && i < lines.length; i++) off += lines[i].length + 1;
  return off;
}

/**
 * Default directory/basename exclusions for test-like code. Used by the CLI
 * walker (overridable via --include-tests) and available to rules.
 */
export function isTestLikePath(filePath: string): boolean {
  const p = filePath.replace(/\\/g, "/");
  if (/(^|\/)(tests?|test[-_]utils?|testing|fuzz|fixtures?|benches|benchmarks|examples?)(\/|$)/i.test(p)) return true;
  const base = (p.split("/").pop() || "").toLowerCase();
  return (
    /^(tests|e2e)\.rs$/.test(base) ||
    /^test_.*\.rs$/.test(base) ||
    /(_tests?|_e2e)\.rs$/.test(base)
  );
}
