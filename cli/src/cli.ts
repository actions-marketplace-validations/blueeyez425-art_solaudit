#!/usr/bin/env node
import { rules, experimentalRules, scanDirectory, printReport, toSarif } from "@solaudit/core";
import type { Severity } from "@solaudit/core";

const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

function printHelp(): void {
  console.log(`SolAudit — static analysis CLI for Anchor/Solana programs

Usage:
  solaudit [path] [options]

Arguments:
  path                    File or directory to scan (default: current directory)

Options:
  --json                  Print raw scan results as JSON
  --sarif                 Print scan results as SARIF 2.1.0 JSON (for GitHub code scanning)
  --min-severity <level>  Only report findings at or above this severity
                          (CRITICAL | HIGH | MEDIUM | LOW | INFO)
  --experimental          Also run experimental rules (e.g. SOL-012 duplicate
                          mutable accounts). Higher signal, more false positives.
  --include-tests         Also scan test/fuzz/fixture/example code (skipped by
                          default; findings there are rarely actionable)
  --help                  Show this help message

Examples:
  solaudit ./program
  bun run solaudit ./programs/vault --min-severity HIGH
  solaudit . --sarif > results.sarif

Exit codes:
  0   No CRITICAL or HIGH severity findings
  1   One or more CRITICAL or HIGH severity findings were found
`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.includes("--help") || args.includes("-h")) {
    printHelp();
    process.exit(0);
  }

  const wantsJson = args.includes("--json");
  const wantsSarif = args.includes("--sarif");
  const wantsExperimental = args.includes("--experimental");
  const includeTests = args.includes("--include-tests");

  let minSeverity: Severity = "INFO";
  const minSeverityIdx = args.indexOf("--min-severity");
  if (minSeverityIdx !== -1) {
    const value = (args[minSeverityIdx + 1] || "").toUpperCase() as Severity;
    if (value in SEVERITY_RANK) {
      minSeverity = value;
    } else {
      console.error(`[solaudit] invalid --min-severity value: "${args[minSeverityIdx + 1]}"`);
      process.exit(2);
    }
  }

  const positional = args.filter((arg, idx) => {
    if (arg.startsWith("-")) return false;
    if (args[idx - 1] === "--min-severity") return false;
    return true;
  });

  const targetPath = positional[0] || ".";

  const activeRules = wantsExperimental ? [...rules, ...experimentalRules] : rules;

  const result = await scanDirectory(targetPath, activeRules, { includeTests });

  result.findings = result.findings.filter(
    (finding) => SEVERITY_RANK[finding.severity] <= SEVERITY_RANK[minSeverity]
  );

  if (wantsSarif) {
    console.log(JSON.stringify(toSarif(result), null, 2));
  } else if (wantsJson) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    printReport(result);
  }

  const hasBlockingFindings = result.findings.some(
    (f) => f.severity === "CRITICAL" || f.severity === "HIGH"
  );

  process.exit(hasBlockingFindings ? 1 : 0);
}

main().catch((err) => {
  console.error(`[solaudit] fatal error: ${(err as Error).message}`);
  process.exit(2);
});
