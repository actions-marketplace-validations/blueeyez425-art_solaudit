import type { Finding, Rule, Severity } from "../types";

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
    "A transfer or mint_to call was found without an is_signer / Signer<'info> check within the preceding 10 lines. Add a `Signer<'info>` account type or an explicit `require!(ctx.accounts.authority.is_signer, ...)` check before authorizing fund movement.",
  check(fileContent, filePath) {
    const findings: Finding[] = [];
    const lines = splitLines(fileContent);
    const callPattern = /\b(transfer|mint_to)\s*\(/;

    lines.forEach((line, idx) => {
      if (!callPattern.test(line)) return;
      if (!line.includes("ctx.accounts.") && !fileContent.includes("ctx.accounts.")) return;

      const windowStart = Math.max(0, idx - 10);
      const window = lines.slice(windowStart, idx + 1).join("\n");
      const hasSignerEvidence =
        /is_signer/.test(window) ||
        /Signer<\s*'info\s*>/.test(window) ||
        /#\[account\([^)]*signer[^)]*\)\]/i.test(window);

      if (!hasSignerEvidence) {
        findings.push(
          makeFinding(
            missingSignerCheck,
            filePath,
            idx + 1,
            line,
            "Verify the authority/owner account is a Signer or explicitly check `.is_signer` before transferring or minting tokens."
          )
        );
      }
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

    lines.forEach((line, idx) => {
      if (!pattern.test(line)) return;
      const prevLine = idx > 0 ? lines[idx - 1] : "";
      const hasConstraint =
        /#\[account\(/.test(prevLine) || /#\[account\(/.test(line);

      if (!hasConstraint) {
        findings.push(
          makeFinding(
            uncheckedDeserialization,
            filePath,
            idx + 1,
            line,
            "Add a `#[account(constraint = ..., owner = ...)]` attribute, or replace with a typed `Account<'info, T>` field so Anchor validates ownership and discriminator automatically."
          )
        );
      }
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
    const cpiPattern = /\b(invoke|invoke_signed)\s*\(/;

    lines.forEach((line, idx) => {
      if (!cpiPattern.test(line)) return;

      const windowStart = Math.max(0, idx - 3);
      const windowEnd = Math.min(lines.length, idx + 4);
      const window = lines.slice(windowStart, windowEnd).join("\n");

      const usesAccountsAsProgram =
        /ctx\.accounts\.\w+\.(to_account_info\(\)|key\(\))/.test(window) &&
        !/Program<\s*'info/.test(window);

      if (usesAccountsAsProgram) {
        findings.push(
          makeFinding(
            arbitraryCpi,
            filePath,
            idx + 1,
            line,
            "Validate the target program ID against a known constant (e.g. `token_program.key() == spl_token::ID`) or type the account as `Program<'info, T>` before invoking it."
          )
        );
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
    "PDA bump seeds must be derived via `find_program_address` and the canonical bump stored/validated on-chain. Calling `create_program_address` directly, or discarding the bump returned by `find_program_address`, allows bump-seed forgery attacks.",
  check(fileContent, filePath) {
    const findings: Finding[] = [];
    const lines = splitLines(fileContent);

    lines.forEach((line, idx) => {
      if (/create_program_address\s*\(/.test(line) && !/find_program_address/.test(line)) {
        findings.push(
          makeFinding(
            missingBumpCanonicalization,
            filePath,
            idx + 1,
            line,
            "Use `Pubkey::find_program_address` to derive the canonical bump instead of calling `create_program_address` directly with a caller-supplied bump."
          )
        );
        return;
      }

      const fpaMatch = line.match(/let\s+(\([^)]*\)|\w+)\s*=\s*[\w:]*find_program_address\s*\(/);
      if (fpaMatch) {
        const binding = fpaMatch[1];
        const bindsBump = /\(\s*\w+\s*,\s*\w+\s*\)/.test(binding);
        if (!bindsBump) {
          findings.push(
            makeFinding(
              missingBumpCanonicalization,
              filePath,
              idx + 1,
              line,
              "Destructure and store the bump returned by `find_program_address` (e.g. `let (pda, bump) = ...`) and persist/validate it instead of discarding it."
            )
          );
        }
      }
    });

    return findings;
  },
};

/** SOL-005: Integer Overflow Risk */
const integerOverflowRisk: Rule = {
  id: "SOL-005",
  name: "Integer Overflow Risk",
  severity: "MEDIUM",
  description:
    "Raw arithmetic (`+`, `-`, `*`) was performed on u64/u128-typed values without using checked or saturating arithmetic. Unchecked overflow can wrap silently in release builds without `overflow-checks = true`, corrupting balances. Use `.checked_add`/`.checked_sub`/`.checked_mul` or `saturating_*` and handle the `None` case.",
  check(fileContent, filePath) {
    const findings: Finding[] = [];
    const lines = splitLines(fileContent);
    const arithmeticPattern = /\b(\w*(amount|balance|supply|total|shares|stake)\w*)\s*(\+|\-|\*)\s*\w/i;
    const alreadySafe = /checked_(add|sub|mul|div)|saturating_(add|sub|mul)|wrapping_(add|sub|mul)/;

    lines.forEach((line, idx) => {
      if (alreadySafe.test(line)) return;
      if (line.trim().startsWith("//")) return;
      if (arithmeticPattern.test(line)) {
        findings.push(
          makeFinding(
            integerOverflowRisk,
            filePath,
            idx + 1,
            line,
            "Replace raw arithmetic with `.checked_add()/.checked_sub()/.checked_mul()` (propagating errors via `ok_or(ErrorCode::MathOverflow)?`) or `saturating_*` equivalents."
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

      if (!hasPayer || !hasSpace) {
        const upToMatch = fileContent.slice(0, match.index);
        const line = upToMatch.split(/\r\n|\r|\n/).length;
        const missing = [!hasPayer && "payer", !hasSpace && "space"].filter(Boolean).join(" and ");
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
    "A raw `AccountInfo` field is accessed via `ctx.accounts.` without a nearby `.owner` comparison. Raw `AccountInfo` accounts bypass Anchor's automatic ownership validation, so the program must manually verify `account.owner == expected_program_id` before trusting its data.",
  check(fileContent, filePath) {
    const findings: Finding[] = [];
    const lines = splitLines(fileContent);

    // Find field declarations typed as raw AccountInfo inside #[derive(Accounts)] structs.
    const rawFieldPattern = /pub\s+(\w+)\s*:\s*AccountInfo<\s*'info\s*>/;
    const rawFields = new Set<string>();
    lines.forEach((line) => {
      const m = line.match(rawFieldPattern);
      if (m) rawFields.add(m[1]);
    });

    if (rawFields.size === 0) return findings;

    lines.forEach((line, idx) => {
      for (const field of rawFields) {
        const usagePattern = new RegExp(`ctx\\.accounts\\.${field}\\b`);
        if (!usagePattern.test(line)) continue;

        const windowStart = Math.max(0, idx - 5);
        const windowEnd = Math.min(lines.length, idx + 6);
        const window = lines.slice(windowStart, windowEnd).join("\n");
        const hasOwnerCheck = new RegExp(`${field}\\.owner`).test(window) || /\.owner\s*==/.test(window);

        if (!hasOwnerCheck) {
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
    const zeroLamportsPattern = /\.lamports\.borrow_mut\(\)\s*=\s*0\s*;/;

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
export const experimentalRules: Rule[] = [duplicateMutableAccounts];

export default rules;
