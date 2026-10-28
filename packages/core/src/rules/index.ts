import type { Finding, Rule, Severity } from "../types";
import {
  findField,
  getConstraintModel,
  inRanges,

  lineOffset,
  stripStringLiterals,
  structAt,
} from "../anchor";

function makeFinding(
  rule: { id: string; name: string; severity: Severity },
  filePath: string,
  line: number,
  snippet: string,
  description: string
): Finding {
  return {
    ruleId: rule.id,
    ruleName: rule.name,
    severity: rule.severity,
    filePath,
    line,
    snippet: snippet.trim(),
    description,
  };
}

function splitLines(fileContent: string): string[] {
  return fileContent.split(/\r\n|\r|\n/);
}

/**
 * Strips `//` line comments from each line of a text block before it's used
 * as evidence in a rule's context window. Without this, a comment merely
 * *describing* a missing check (e.g. "// BUG: no discriminator zeroing")
 * would itself satisfy a naive keyword search for "discriminator" and
 * suppress the very finding the comment is explaining.
 */
function stripLineComments(text: string): string {
  return text
    .split(/\r\n|\r|\n/)
    .map((line) => line.replace(/\/\/.*$/, ""))
    .join("\n");
}

/** SOL-001: Missing Signer Check */
const missingSignerCheck: Rule = {
  id: "SOL-001",
  name: "Missing Signer Check",
  severity: "CRITICAL",
  description:
    "A transfer or mint_to call was found with no signer evidence: no is_signer check nearby, no Signer<'info> field on the governing Accounts struct, and no PDA signing (invoke_signed / new_with_signer). Add a `Signer<'info>` account type or an explicit `require!(ctx.accounts.authority.is_signer, ...)` check before authorizing fund movement.",
  check(fileContent, filePath) {
    const findings: Finding[] = [];
    const lines = splitLines(fileContent);
    const callPattern = /\b(?:transfer|mint_to|transfer_checked|mint_to_checked)\s*\(/;
    const declPattern = /\bfn\s+(?:transfer|mint_to|transfer_checked|mint_to_checked)\s*\(/;
    const model = getConstraintModel(fileContent);

    lines.forEach((rawLine, idx) => {
      if (declPattern.test(rawLine)) return; // a function *declaration*, not a call
      const line = stripStringLiterals(rawLine); // format strings are not calls
      if (!callPattern.test(line)) return;
      if (!line.includes("ctx.accounts.") && !fileContent.includes("ctx.accounts.")) return;

      const offset = lineOffset(lines, idx);
      if (inRanges(offset, model.testRanges)) return;

      const windowStart = Math.max(0, idx - 10);
      const window = lines.slice(windowStart, idx + 1).join("\n");
      const hasSignerEvidence =
        /is_signer/.test(window) ||
        /Signer<\s*'info\s*>/.test(window) ||
        /#\[account\([^)]*signer[^)]*\)\]/i.test(window);
      if (hasSignerEvidence) return;

      // Constraint-layer model for the enclosing handler (hoisted: both the
      // PDA-signed-drain check below and the final Signer-field check use it).
      const struct = structAt(model, offset);

      // Extended window: PDA-signed CPI and instruction-construction patterns
      // resolve the signer question at the invoke site, not the call site.
      const extWindow = lines
        .slice(windowStart, Math.min(lines.length, idx + 16))
        .join("\n");
      if (/\binvoke_signed\b/.test(extWindow)) {
        // PDA-signed value movement: the program itself signs, so the runtime
        // no longer requires any caller signature. That is safe only when the
        // destination comes from validated state — if the transfer's `to` is a
        // caller-supplied unchecked account and no Signer governs the
        // instruction, anyone can call it and drain the vault to themselves.
        if (struct && !struct.fields.some((f) => f.isSignerTyped)) {
          const callBlock = lines.slice(idx, Math.min(lines.length, idx + 8)).join("\n");
          if (/system_instruction::transfer|::transfer(?:_checked)?\s*\(/.test(callBlock)) {
            const refs = [...callBlock.matchAll(/ctx\.accounts\.(\w+)/g)].map((m) => m[1]);
            // system_instruction::transfer(from, to, amount) — refs[1] is `to`.
            const toField = refs.length >= 2 ? findField(model, refs[1]) : null;
            if (toField && toField.isRaw && !toField.validated) {
              findings.push(
                makeFinding(
                  missingSignerCheck,
                  filePath,
                  idx + 1,
                  rawLine,
                  `This instruction PDA-signs a transfer whose destination (\`${refs[1]}\`) is a caller-supplied unchecked account, and its Accounts struct has no Signer — anyone can call it and drain the vault. Require an authority Signer and bind the recipient to validated state.`
                )
              );
            }
          }
        }
        return;
      }
      if (/\bnew_with_signer\b/.test(extWindow)) return;
      // Instruction construction passed to invoke()/invoke_signed: the runtime
      // enforces that the `from` account signed the transaction (or is PDA-
      // signed). Covers both `system_instruction::transfer(...)` and aliased
      // imports like `&transfer(...)` appearing as invoke() arguments.
      if (/system_instruction::transfer/.test(line) && /\binvoke(?:_signed)?\s*\(/.test(extWindow)) {
        return;
      }
      // Aliased ix construction (`&transfer(...)`) appearing as an invoke()
      // argument — same reasoning as system_instruction::transfer above.
      if (!line.includes("::")) {
        const beforeMatch = line.slice(0, line.search(callPattern));
        if (/\binvoke(?:_signed)?\s*\([^)]*$/.test(beforeMatch)) return;
        const prevLines = lines.slice(Math.max(0, idx - 3), idx);
        if (prevLines.some((l) => /\binvoke(?:_signed)?\s*\([^)]*$/.test(l))) return;
      }

      // Constraint-layer awareness: if the governing Accounts struct (from the
      // enclosing handler's Context<T> or impl block) declares a Signer field,
      // Anchor rejects unsigned transactions at deserialization time.
      if (struct && struct.fields.some((f) => f.isSignerTyped)) return;

      findings.push(
        makeFinding(
          missingSignerCheck,
          filePath,
          idx + 1,
          rawLine,
          "Verify the authority/owner account is a Signer or explicitly check `.is_signer` before transferring or minting tokens."
        )
      );
    });

    return findings;
  },
};

/** SOL-002: Unchecked Account Deserialization */
const uncheckedDeserialization: Rule = {
  id: "SOL-002",
  name: "Unchecked Account Deserialization",
  severity: "HIGH",
  description:
    "`Account::try_from` / `AccountLoader::try_from` was used to manually deserialize account data without a corresponding `#[account(...)]` constraint validating ownership or discriminator. Prefer typed `Account<'info, T>` fields validated by Anchor, or add explicit owner/discriminator checks.",
  check(fileContent, filePath) {
    const findings: Finding[] = [];
    const lines = splitLines(fileContent);
    const pattern = /(Account|AccountLoader)::try_from\s*\(/;
    const model = getConstraintModel(fileContent);

    lines.forEach((line, idx) => {
      if (!pattern.test(line)) return;
      const offset = lineOffset(lines, idx);
      if (inRanges(offset, model.testRanges)) return;

      // Constraint evidence may sit a few lines above the call.
      const windowStart = Math.max(0, idx - 3);
      const window = lines.slice(windowStart, idx + 1).join("\n");
      if (/#\[account\(/.test(window)) return;

      // If the deserialized account is a struct field carrying validation
      // constraints (owner / constraint / has_one), Anchor already enforces it.
      const argMatch = line.match(/::try_from\s*\(\s*&?\s*(?:ctx\.accounts\.|self\.)?(\w+)/);
      if (argMatch) {
        const field = findField(model, argMatch[1]);
        if (field && field.validated) return;
      }

      findings.push(
        makeFinding(
          uncheckedDeserialization,
          filePath,
          idx + 1,
          line,
          "Add a `#[account(constraint = ..., owner = ...)]` attribute, or replace with a typed `Account<'info, T>` field so Anchor validates ownership and discriminator automatically."
        )
      );
    });

    return findings;
  },
};

/** SOL-003: Arbitrary CPI */
const arbitraryCpi: Rule = {
  id: "SOL-003",
  name: "Arbitrary CPI (Cross-Program Invocation)",
  severity: "HIGH",
  description:
    "`invoke` or `invoke_signed` is called with a program id sourced from a user-supplied account rather than a hardcoded/verified program ID. This allows an attacker to substitute a malicious program. Add a `constraint = program.key() == expected_program::ID` check or use Anchor's `Program<'info, T>` type.",
  check(fileContent, filePath) {
    const findings: Finding[] = [];
    const lines = splitLines(fileContent);
    const cpiPattern = /\b(?:invoke|invoke_signed)\s*\(/;
    const model = getConstraintModel(fileContent);

    lines.forEach((line, idx) => {
      if (!cpiPattern.test(line)) return;
      const offset = lineOffset(lines, idx);
      if (inRanges(offset, model.testRanges)) return;

      const windowStart = Math.max(0, idx - 12);
      const windowEnd = Math.min(lines.length, idx + 12);
      const window = stripLineComments(lines.slice(windowStart, windowEnd).join("\n"));

      // The CPI target is substitutable only when the *program* is sourced
      // from an account. Two shapes:
      //   1. `program_id: ctx.accounts.<name>...` in an Instruction literal
      //   2. a program-named account (`token_program`, `amm_program`, ...)
      //      passed into the CPI or to an instruction builder
      // Transfer arguments like `ctx.accounts.user.key()` are NOT program ids
      // and must not flag — that was the 0.3.1 false-positive source.
      const suspectNames = new Set<string>();
      for (const m of window.matchAll(/program_id\s*:\s*[*&]?\s*(?:ctx\.accounts\.)?(\w+)/g)) {
        suspectNames.add(m[1]);
      }
      for (const m of window.matchAll(/ctx\.accounts\.(\w*(?:^|_)program\w*)/g)) {
        suspectNames.add(m[1]);
      }

      for (const name of suspectNames) {
        const field = findField(model, name);
        // Typed `Program<'info, T>` accounts are validated by Anchor — safe.
        if (field && field.wrapperType === "Program") continue;
        // A non-program raw field that merely shares a name suffix (rare) is
        // still suspicious only if it's raw; typed accounts are checked.
        if (field && !field.isRaw) continue;
        if (!field && /Program<\s*'info/.test(window)) continue; // non-Anchor fallback

        findings.push(
          makeFinding(
            arbitraryCpi,
            filePath,
            idx + 1,
            line,
            "Validate the target program ID against a known constant (e.g. `token_program.key() == spl_token::ID`) or type the account as `Program<'info, T>` before invoking it."
          )
        );
        break; // one finding per CPI site
      }
    });

    return findings;
  },
};

/** SOL-004: Missing Bump Seed Canonicalization */
const missingBumpCanonicalization: Rule = {
  id: "SOL-004",
  name: "Missing Bump Seed Canonicalization",
  severity: "HIGH",
  description:
    "PDA bump seeds must be derived via `find_program_address` (which returns the canonical bump by construction) and stored/validated on-chain. Calling `create_program_address` directly with a caller-supplied bump allows bump-seed forgery attacks.",
  check(fileContent, filePath) {
    const findings: Finding[] = [];
    const lines = splitLines(fileContent);
    const model = getConstraintModel(fileContent);

    lines.forEach((line, idx) => {
      if (!/create_program_address\s*\(/.test(line)) return;
      const offset = lineOffset(lines, idx);
      if (inRanges(offset, model.testRanges)) return;

      // `find_program_address` returns the canonical bump by construction, so
      // any usage of it — including the idiomatic `.0` accessor that discards
      // the bump — is safe. Only direct `create_program_address` calls whose
      // bump did not come from a nearby canonical derivation are suspect.
      // (Comments are stripped first: a comment *mentioning* the safe API is
      // not evidence it was used.)
      const windowStart = Math.max(0, idx - 10);
      const windowEnd = Math.min(lines.length, idx + 3);
      const window = stripLineComments(lines.slice(windowStart, windowEnd).join("\n"));
      if (/find_program_address/.test(window)) return;

      findings.push(
        makeFinding(
          missingBumpCanonicalization,
          filePath,
          idx + 1,
          line,
          "Use `Pubkey::find_program_address` to derive the canonical bump instead of calling `create_program_address` directly with a caller-supplied bump."
        )
      );
    });

    // PDA substitution: a raw, mutable, unconstrained field named like a value
    // vault (treasury/vault/pool/escrow/...) participating in lamport movement.
    // Without a `seeds`/`address` binding, the caller can substitute any
    // account — draining it, or redirecting fees to themselves.
    if (model.structs.length > 0) {
      const offsets: number[] = [];
      let acc = 0;
      for (const l of lines) {
        offsets.push(acc);
        acc += l.length + 1;
      }

      for (const s of model.structs) {
        const regions = model.regions.filter((r) => r.contextType === s.name);
        const regionText =
          regions.length > 0
            ? regions.map((r) => fileContent.slice(r.start, r.end)).join("\n")
            : fileContent;
        const movesValue =
          /system_instruction::transfer|token::transfer|try_borrow_mut_lamports|lamports\.borrow_mut/.test(
            stripLineComments(regionText)
          );
        if (!movesValue) continue;

        const inScope = (lineIdx: number) => {
          if (regions.length === 0) return true;
          const off = offsets[lineIdx];
          return regions.some((r) => off >= r.start && off < r.end);
        };

        for (const f of s.fields) {
          if (!f.isRaw || f.validated) continue;
          if (!/\bmut\b/.test(f.attrs)) continue;
          if (!/vault|treasury|pool|escrow|fund|bank|reward/i.test(f.name)) continue;

          for (let i = 0; i < lines.length; i++) {
            if (!inScope(i)) continue;
            if (!lines[i].includes(`ctx.accounts.${f.name}`)) continue;
            findings.push(
              makeFinding(
                missingBumpCanonicalization,
                filePath,
                i + 1,
                lines[i],
                `\`${f.name}\` is a mutable unchecked account used in value movement with no \`seeds\` binding. Verify it against its derived PDA (\`seeds = [...], bump\`) or pin it with \`address =\` — otherwise the caller can substitute an attacker-controlled account and redirect the funds.`
              )
            );
            break; // once per field
          }
        }
      }
    }

    return findings;
  },
};

/** SOL-005: Integer Overflow Risk */
const integerOverflowRisk: Rule = {
  id: "SOL-005",
  name: "Integer Overflow Risk",
  severity: "MEDIUM",
  description:
    "Raw arithmetic (`+`, `-`, `*`) was written into account state (a field assignment or compound assignment) on amount-like values without checked or saturating arithmetic. Unchecked overflow can wrap silently in release builds without `overflow-checks = true`, corrupting balances. Use `.checked_add`/`.checked_sub`/`.checked_mul` or `saturating_*` and handle the `None` case.",
  check(fileContent, filePath) {
    const findings: Finding[] = [];
    const lines = splitLines(fileContent);
    // NOTE: test-path filtering happens once at the scanner collection layer
    // (scanner.ts, honoring --include-tests). A second guard here silently
    // suppressed this rule even when the user opted in with --include-tests.
    const model = getConstraintModel(fileContent);
    const arithmeticPattern =
      /\b(\w*(amount|balance|supply|total|shares|stake|reserve|collateral|liquidity|principal)\w*)\s*(\+|\-|\*)\s*\w/i;
    const alreadySafe = /checked_(add|sub|mul|div)|saturating_(add|sub|mul)|wrapping_(add|sub|mul)/;
    // Persisted-state writes: `foo.bar = ...`, `foo.bar += ...`, or `x += ...`.
    // Intermediate locals (`let x = a - b`) are intentionally not flagged —
    // the exploitable class is arithmetic that lands in on-chain state, and
    // flagging every subtraction made this rule 34% of all real-world output.
    const stateWritePattern =
      /^\s*(?:[\w.\[\]]+\.)[\w.\[\]]+\s*(?:=|\+=|-=|\*=)\s*[^=>]|\b\w+\s*(?:\+=|-=|\*=)\s*[^=]/;

    lines.forEach((line, idx) => {
      if (alreadySafe.test(line)) return;
      if (line.trim().startsWith("//")) return;
      if (/\d\.\d/.test(line)) return; // f64 BPS/price math doesn't wrap
      const offset = lineOffset(lines, idx);
      if (inRanges(offset, model.testRanges)) return;
      const code = stripStringLiterals(line);
      if (arithmeticPattern.test(code) && stateWritePattern.test(code)) {
        findings.push(
          makeFinding(
            integerOverflowRisk,
            filePath,
            idx + 1,
            line,
            "Replace raw arithmetic written to state with `.checked_add()/.checked_sub()/.checked_mul()` (propagating errors via `ok_or(ErrorCode::MathOverflow)?`) or `saturating_*` equivalents."
          )
        );
      }

      // Variable-exponent exponentiation in value math: `2u64.pow(level)`
      // wraps a u64 at modest exponents — the classic fee/curve overflow.
      // (Constant exponents like `10u64.pow(9)` are deliberate and skipped.)
      if (/\.pow\s*\([^)]*[a-zA-Z_]/.test(code) && !/checked_pow|saturating|wrapping/.test(code)) {
        findings.push(
          makeFinding(
            integerOverflowRisk,
            filePath,
            idx + 1,
            line,
            "Exponentiation with a non-constant exponent overflows silently and quickly (2^64 wraps a u64 to 0). Use `checked_pow` with error propagation, or bound the exponent explicitly."
          )
        );
      }
    });

    return findings;
  },
};

/** SOL-006: Type Cosplay / Missing Discriminator Check */
const typeCosplay: Rule = {
  id: "SOL-006",
  name: "Type Cosplay / Missing Discriminator Check",
  severity: "HIGH",
  description:
    "Account data is manually deserialized with `try_from_slice` without validating an 8-byte Anchor discriminator or account type tag first. An attacker can pass an account of a different type with a compatible byte layout ('type cosplay') to bypass logic. Use Anchor's `Account<'info, T>` wrapper, which enforces discriminator checks automatically, or manually compare the first 8 bytes against `T::DISCRIMINATOR`.",
  check(fileContent, filePath) {
    const findings: Finding[] = [];
    const lines = splitLines(fileContent);

    lines.forEach((line, idx) => {
      if (!/try_from_slice\s*\(/.test(line)) return;

      const windowStart = Math.max(0, idx - 5);
      const window = lines.slice(windowStart, idx + 1).join("\n");
      const usesTypedAccountWrapper = /Account<\s*'info/.test(window);
      const checksDiscriminator = /discriminator/i.test(window);

      if (!usesTypedAccountWrapper && !checksDiscriminator) {
        findings.push(
          makeFinding(
            typeCosplay,
            filePath,
            idx + 1,
            line,
            "Verify the account's 8-byte Anchor discriminator matches the expected type before trusting deserialized fields, or switch to Anchor's `Account<'info, T>` type."
          )
        );
      }
    });

    return findings;
  },
};

/** SOL-007: Insecure Account Initialization */
const insecureInit: Rule = {
  id: "SOL-007",
  name: "Insecure Account Initialization",
  severity: "MEDIUM",
  description:
    "An `#[account(init, ...)]` constraint is missing `payer` and/or `space`. Anchor requires both to safely allocate and rent-exempt a new account; omitting them causes a compile error in modern Anchor, but in hand-rolled or macro-generated code this pattern indicates the constraint block was copy-pasted incompletely and should be reviewed.",
  check(fileContent, filePath) {
    const findings: Finding[] = [];
    // Match #[account(...)] blocks, possibly spanning multiple lines.
    const blockRegex = /#\[account\(([\s\S]*?)\)\]/g;
    let match: RegExpExecArray | null;

    while ((match = blockRegex.exec(fileContent)) !== null) {
      const block = match[1];
      if (!/\binit\b/.test(block)) continue;

      const hasPayer = /\bpayer\s*=/.test(block);
      const hasSpace = /\bspace\s*=/.test(block);

      // Associated-token and token-account inits are exempt from `space` (and
      // often `payer` looks different): Anchor derives allocation for them.
      const isTokenInit = /\b(associated_token|token)::/.test(block);

      if (!hasPayer || (!hasSpace && !isTokenInit)) {
        const upToMatch = fileContent.slice(0, match.index);
        const line = upToMatch.split(/\r\n|\r|\n/).length;
        const missing = [!hasPayer && "payer", !hasSpace && !isTokenInit && "space"]
          .filter(Boolean)
          .join(" and ");
        findings.push(
          makeFinding(
            insecureInit,
            filePath,
            line,
            `#[account(${block.trim()})]`,
            `Add the missing \`${missing}\` argument(s) to this init constraint so Anchor allocates and rent-exempts the account correctly.`
          )
        );
      }
    }

    return findings;
  },
};

/** SOL-008: Missing Owner Check */
const missingOwnerCheck: Rule = {
  id: "SOL-008",
  name: "Missing Owner Check",
  severity: "LOW",
  description:
    "A raw `AccountInfo`/`UncheckedAccount` field carries no `owner`/`constraint`/`has_one` binding in its Accounts struct and no `.owner` comparison anywhere in the file. Raw accounts bypass Anchor's automatic ownership validation, so the program must manually verify `account.owner == expected_program_id` before trusting its data.",
  check(fileContent, filePath) {
    const findings: Finding[] = [];
    const lines = splitLines(fileContent);
    const model = getConstraintModel(fileContent);

    if (model.structs.length > 0) {
      // Constraint-aware path: evaluate each raw field within the handlers its
      // owning struct governs. Validated = its own declaration carries an
      // owner/constraint/has_one/address/seeds binding, or a genuine owner
      // *comparison* on it exists in the file. (An assignment like
      // `tile.owner = ...` is NOT a check — 0.3.1's cross-struct name matching
      // both suppressed real findings and reported them at the wrong site.)
      const codeOnly = stripLineComments(fileContent);
      const offsets: number[] = [];
      {
        let off = 0;
        for (const l of lines) {
          offsets.push(off);
          off += l.length + 1;
        }
      }

      const touchPattern =
        /try_borrow_data|try_borrow_mut_data|try_borrow_mut_lamports|\.load\s*\(|data\.borrow|try_from|\.lamports\s*\(\s*\)|accessor::/;

      for (const s of model.structs) {
        const regions = model.regions.filter((r) => r.contextType === s.name);
        const inScope = (lineIdx: number) => {
          if (regions.length === 0) return true;
          const off = offsets[lineIdx];
          return regions.some((r) => off >= r.start && off < r.end);
        };

        for (const f of s.fields) {
          if (!f.isRaw || f.validated) continue;

          // Genuine manual owner check (comparison / require), not assignment.
          const ownerCheck = new RegExp(
            `\\b${f.name}\\.owner\\s*==|require!\\([^)]*\\b${f.name}\\.owner\\b|require_keys_eq!\\([^)]*\\b${f.name}\\b`
          );
          if (ownerCheck.test(codeOnly)) continue;

          // Aliases: `let x = &ctx.accounts.<field>;` — the dangerous method
          // calls often happen on the alias, not on `ctx.accounts.<field>`.
          const aliases = new Set<string>();
          const aliasRe = new RegExp(
            `let\\s+(\\w+)\\s*=\\s*&?\\s*ctx\\.accounts\\.${f.name}\\b`,
            "g"
          );
          let am: RegExpExecArray | null;
          while ((am = aliasRe.exec(codeOnly)) !== null) aliases.add(am[1]);

          let reportLine = -1;
          let snippet = "";
          for (let i = 0; i < lines.length; i++) {
            if (!inScope(i)) continue;
            const l = lines[i];
            const direct = l.includes(`ctx.accounts.${f.name}`);
            const aliasTouch = [...aliases].some(
              (a) => new RegExp(`\\b${a}\\s*\\.`).test(l) && touchPattern.test(l)
            );
            const directTouch = direct && touchPattern.test(l);
            // Assigning an unvalidated account's key into persistent state
            // asserts the identity of an account nothing has checked.
            const keyAssign =
              direct &&
              new RegExp(`=\\s*&?\\s*ctx\\.accounts\\.${f.name}\\.key\\s*\\(`).test(l) &&
              !/==|require_keys_eq/.test(l);
            if (aliasTouch || directTouch || keyAssign) {
              reportLine = i + 1;
              snippet = l;
              break;
            }
          }
          if (reportLine === -1) continue; // declared but never dangerously used

          findings.push(
            makeFinding(
              missingOwnerCheck,
              filePath,
              reportLine,
              snippet,
              `\`${f.name}\` is a raw AccountInfo with no constraint binding. Add an explicit \`require!(ctx.accounts.${f.name}.owner == &expected_program_id, ErrorCode::InvalidOwner)\` check (or an \`#[account(owner = ...)]\` constraint) before trusting its data.`
            )
          );
        }
      }

      return findings;
    }

    // Fallback for non-Anchor files (no parsable Accounts structs, e.g.
    // pinocchio/native programs): legacy heuristic over raw field declarations.
    const rawFieldPattern = /pub\s+(\w+)\s*:\s*AccountInfo<\s*'info\s*>/;
    const rawFields = new Set<string>();
    lines.forEach((line) => {
      const m = line.match(rawFieldPattern);
      if (m) rawFields.add(m[1]);
    });
    if (rawFields.size === 0) return findings;

    const flagged = new Set<string>();
    lines.forEach((line, idx) => {
      for (const field of rawFields) {
        if (flagged.has(field)) continue;
        const usagePattern = new RegExp(`ctx\\.accounts\\.${field}\\b`);
        if (!usagePattern.test(line)) continue;

        const windowStart = Math.max(0, idx - 5);
        const windowEnd = Math.min(lines.length, idx + 6);
        const window = lines.slice(windowStart, windowEnd).join("\n");
        const hasOwnerCheck = new RegExp(`${field}\\.owner`).test(window) || /\.owner\s*==/.test(window);

        if (!hasOwnerCheck) {
          flagged.add(field);
          findings.push(
            makeFinding(
              missingOwnerCheck,
              filePath,
              idx + 1,
              line,
              `Add an explicit \`require!(ctx.accounts.${field}.owner == &expected_program_id, ErrorCode::InvalidOwner)\` check before using this raw AccountInfo.`
            )
          );
        }
      }
    });

    return findings;
  },
};

/** SOL-009: Insecure Manual Account Closure */
const insecureAccountClosure: Rule = {
  id: "SOL-009",
  name: "Insecure Manual Account Closure",
  severity: "HIGH",
  description:
    "An account's lamports were manually drained to zero without zeroing its data/discriminator or reassigning ownership to the System Program, unlike Anchor's `close = destination` constraint (which does both automatically). A 'closed' account that still carries its original discriminator and data can be revived/reused within the same or a later transaction before garbage collection, letting an attacker re-claim already-withdrawn funds or reopen closed state. Use `#[account(mut, close = destination)]` instead of manual lamport-draining, or manually zero the account's discriminator/data and reassign owner to the System Program.",
  check(fileContent, filePath) {
    const findings: Finding[] = [];
    const lines = splitLines(fileContent);
    const zeroLamportsPattern =
      /(?:\.lamports\.borrow_mut\(\)|\.try_borrow_mut_lamports\(\)\??)\s*=\s*0\s*;/;

    lines.forEach((line, idx) => {
      if (!zeroLamportsPattern.test(line)) return;

      const windowStart = Math.max(0, idx - 15);
      const windowEnd = Math.min(lines.length, idx + 15);
      const window = stripLineComments(lines.slice(windowStart, windowEnd).join("\n"));

      const hasSafeClosure =
        /close\s*=/.test(window) ||
        /discriminator/i.test(window) ||
        /CLOSED_ACCOUNT_DISCRIMINATOR/.test(window) ||
        /\.data\.borrow_mut\(\)/.test(window);

      if (!hasSafeClosure) {
        findings.push(
          makeFinding(
            insecureAccountClosure,
            filePath,
            idx + 1,
            line,
            "Use Anchor's `#[account(mut, close = destination)]` constraint, or manually zero the account's 8-byte discriminator and reassign its owner to the System Program, before treating this account as closed."
          )
        );
      }
    });

    return findings;
  },
};

/** SOL-010: Reinitialization Risk via init_if_needed */
const initIfNeededReinit: Rule = {
  id: "SOL-010",
  name: "Reinitialization Risk via init_if_needed",
  severity: "MEDIUM",
  description:
    "`#[account(init_if_needed, ...)]` initializes the account only when it does not already exist, so a pre-existing account flows through the same validation path. Without canonical PDA seeds/bump and constraints binding the account to expected state, this pattern has enabled reinitialization attacks where an attacker crafts or front-runs account state. Anchor's own documentation recommends avoiding `init_if_needed` unless strictly necessary.",
  check(fileContent, filePath) {
    const findings: Finding[] = [];
    const blockRegex = /#\[account\(([\s\S]*?)\)\]/g;
    let match: RegExpExecArray | null;

    while ((match = blockRegex.exec(fileContent)) !== null) {
      const block = match[1];
      if (!/\binit_if_needed\b/.test(block)) continue;

      const line = fileContent.slice(0, match.index).split(/\r\n|\r|\n/).length;
      findings.push(
        makeFinding(
          initIfNeededReinit,
          filePath,
          line,
          `#[account(${block.trim()})]`,
          "Prefer `init` plus a separate existence check. If `init_if_needed` is unavoidable, make the account a PDA with canonical `seeds`/`bump` and add `has_one`/`constraint` bindings so a pre-existing attacker-controlled account cannot pass validation."
        )
      );
    }

    return findings;
  },
};

/**
 * SOL-012 (EXPERIMENTAL): Duplicate Mutable Accounts
 *
 * Flags `#[derive(Accounts)]` structs that declare two or more mutable fields
 * of the SAME account type without any `constraint = a.key() != b.key()`
 * forcing them to be distinct. If the caller can pass the same account twice,
 * logic that assumes the accounts are distinct (balance snapshots, dual
 * debits/credits) can be exploited.
 *
 * This heuristic is deliberately NOT in the default ruleset: it false-positives
 * on common legitimate patterns (e.g. a deposit instruction's user/vault token
 * accounts, which share a type and rarely carry an explicit != constraint).
 * It ships behind the CLI's `--experimental` flag for users who want maximum
 * signal and are willing to triage noisier results.
 */
const duplicateMutableAccounts: Rule = {
  id: "SOL-012",
  name: "Duplicate Mutable Accounts (experimental)",
  severity: "HIGH",
  description:
    "Two or more mutable accounts of the same type in one instruction with no `constraint = a.key() != b.key()` forcing distinctness. If the surrounding logic assumes the accounts are different (e.g. reading one balance and writing the other, or debiting one and crediting the other), passing the same account twice can corrupt accounting. Add an explicit inequality constraint or restructure the instruction.",
  check(fileContent, filePath) {
    const findings: Finding[] = [];
    const lines = splitLines(fileContent);

    // Locate each #[derive(Accounts)] struct and brace-match its body.
    const structStart = /#\[derive\(\s*Accounts\s*\)\][\s\S]*?pub struct\s+\w+[^\{]*\{/g;
    let sm: RegExpExecArray | null;

    while ((sm = structStart.exec(fileContent)) !== null) {
      let depth = 1;
      let i = sm.index + sm[0].length;
      while (i < fileContent.length && depth > 0) {
        if (fileContent[i] === "{") depth++;
        else if (fileContent[i] === "}") depth--;
        i++;
      }
      const body = fileContent.slice(sm.index, i);
      // A comment merely *mentioning* a distinctness constraint (e.g.
      // "// BUG: no constraint = a.key() != b.key()") must not satisfy it.
      const bodyNoComments = stripLineComments(body);

      interface FieldInfo {
        name: string;
        typeName: string;
        isMut: boolean;
        offset: number;
      }
      const fields: FieldInfo[] = [];
      const fieldRegex =
        /((?:#\[[\s\S]*?\]\s*)*)pub\s+(\w+)\s*:\s*([\w:]+)\s*<\s*'info\s*(?:,\s*([\w:]+)\s*)?>/g;
      let fm: RegExpExecArray | null;

      while ((fm = fieldRegex.exec(body)) !== null) {
        const attrs = fm[1] || "";
        const isMut = /#\[account\([\s\S]*?\bmut\b[\s\S]*?\)\]/.test(attrs);
        // Account<'info, T> -> T; bare Signer<'info>/Program<'info, T> handled too.
        const typeName = fm[4] || fm[3];
        fields.push({ name: fm[2], typeName, isMut, offset: sm.index + fm.index });
      }

      const mutByType = new Map<string, FieldInfo[]>();
      for (const f of fields) {
        if (!f.isMut) continue;
        const group = mutByType.get(f.typeName) || [];
        group.push(f);
        mutByType.set(f.typeName, group);
      }

      for (const group of mutByType.values()) {
        if (group.length < 2) continue;
        const first = group[0];
        for (let g = 1; g < group.length; g++) {
          const other = group[g];
          const distinct = new RegExp(
            `${first.name}\\.key\\(\\)\\s*!=\\s*${other.name}\\.key\\(\\)|` +
              `${other.name}\\.key\\(\\)\\s*!=\\s*${first.name}\\.key\\(\\)`
          );
          if (distinct.test(bodyNoComments)) continue;

          const line = fileContent.slice(0, other.offset).split(/\r\n|\r|\n/).length;
          findings.push(
            makeFinding(
              duplicateMutableAccounts,
              filePath,
              line,
              lines[line - 1] || other.name,
              `Fields \`${first.name}\` and \`${other.name}\` are both mutable \`${other.typeName}\` accounts with no distinctness constraint. Add \`constraint = ${other.name}.key() != ${first.name}.key()\` (if the instruction requires them to differ) or document why aliasing is safe.`
            )
          );
        }
      }
    }

    return findings;
  },
};

/** SOL-011: Missing Rent-Exemption Check on Partial Withdrawal */
const missingRentExemptCheck: Rule = {
  id: "SOL-011",
  name: "Missing Rent-Exemption Check on Partial Withdrawal",
  severity: "MEDIUM",
  description:
    "Lamports are subtracted from an account's balance (a partial withdrawal) with no nearby check against `Rent::get()?.minimum_balance(...)`. If the withdrawal can drop the account below the rent-exempt threshold, the runtime may purge the account on the next epoch boundary, destroying any remaining state and potentially enabling accounting-drift or re-initialization bugs. Compare the post-withdrawal balance against the account's rent-exempt minimum before allowing a partial (non-zeroing) withdrawal.",
  check(fileContent, filePath) {
    const findings: Finding[] = [];
    const lines = splitLines(fileContent);
    const partialWithdrawPattern = /\.lamports\.borrow_mut\(\)\s*=\s*[\w.]+\.lamports\(\)\.checked_sub\(/;

    lines.forEach((line, idx) => {
      if (!partialWithdrawPattern.test(line)) return;
      // Full drains to exactly zero are covered by SOL-009's closure check instead.
      if (/=\s*0\s*;/.test(line)) return;

      const windowStart = Math.max(0, idx - 15);
      const windowEnd = Math.min(lines.length, idx + 15);
      const window = stripLineComments(lines.slice(windowStart, windowEnd).join("\n"));
      const hasRentCheck = /Rent::get\(\)|minimum_balance/.test(window);

      if (!hasRentCheck) {
        findings.push(
          makeFinding(
            missingRentExemptCheck,
            filePath,
            idx + 1,
            line,
            "Check the resulting balance against `Rent::get()?.minimum_balance(account.data_len())` before allowing a partial lamport withdrawal, or require the withdrawal to fully close the account via `close = destination`."
          )
        );
      }
    });

    return findings;
  },
};

/**
 * SOL-013: Token Account Not Bound to Mint
 *
 * When an instruction takes both a token account and a mint account, but the
 * token account's constraints never bind it to that mint (`token::mint = ...`,
 * `associated_token::mint = ...`, or a constraint/address pin), the program
 * may accept a token account of the WRONG mint. This is the vulnerability
 * class behind the Cashio infinite-mint exploit (~$50M): the program accepted
 * arbitrary token mints as collateral because the collateral token account
 * was never validated against the expected mint.
 *
 * Scoped conservatively to keep precision high: the rule only fires when a
 * `Mint` account is in scope in the SAME struct (so there is an obvious mint
 * to bind to), and stays quiet when the token account is initialized in place
 * (Anchor requires token::mint for init) or carries any other binding.
 *
 * Ships behind `--experimental`: integration-heavy programs (marginfi's
 * drift/juplend/kamino adapters) legitimately take external programs' vaults
 * unbound, so this rule's real-world precision is below the default-set bar.
 * It catches the Cashio pattern; use it for deep manual reviews.
 */
const unboundTokenMint: Rule = {
  id: "SOL-013",
  name: "Token Account Not Bound to Mint",
  severity: "MEDIUM",
  description:
    "A token-account field and a mint field coexist in the same Accounts struct, but the token account is never bound to the mint (`token::mint = ...`, `associated_token::mint = ...`, or a constraint/address pin). The instruction may accept a token account of an unintended mint — the vulnerability class behind the Cashio infinite-mint exploit. Bind the token account to the mint in the `#[account(...)]` constraint.",
  check(fileContent, filePath) {
    const findings: Finding[] = [];
    const lines = splitLines(fileContent);
    const model = getConstraintModel(fileContent);

    for (const s of model.structs) {
      const mintFields = s.fields.filter((f) => f.isMint);
      if (mintFields.length === 0) continue;

      for (const f of s.fields) {
        if (!f.isTokenAccount) continue;
        if (f.bindsTokenMint || f.hasInit || f.validated) continue;

        findings.push(
          makeFinding(
            unboundTokenMint,
            filePath,
            f.line,
            lines[f.line - 1] || f.name,
            `\`${f.name}\` is a TokenAccount but is never bound to a mint, although this instruction also takes a mint account (${mintFields
              .map((m) => `\`${m.name}\``)
              .join(", ")}). Add \`token::mint = ${mintFields[0].name}\` (and usually \`token::authority\`) to the field's #[account(...)] constraint so a token account of an unintended mint is rejected.`
          )
        );
      }
    }

    return findings;
  },
};

export const rules: Rule[] = [
  missingSignerCheck,
  uncheckedDeserialization,
  arbitraryCpi,
  missingBumpCanonicalization,
  integerOverflowRisk,
  typeCosplay,
  insecureInit,
  missingOwnerCheck,
  insecureAccountClosure,
  initIfNeededReinit,
  missingRentExemptCheck,
];

/**
 * Opt-in rules that are too noisy for the default ruleset (see each rule's
 * comment). Included only when the CLI is run with `--experimental`.
 */
export const experimentalRules: Rule[] = [duplicateMutableAccounts, unboundTokenMint];

export default rules;
