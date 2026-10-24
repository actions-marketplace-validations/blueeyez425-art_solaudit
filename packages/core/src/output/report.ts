import type { Finding, ScanResult, Severity } from "../types";

const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const RED = "\x1b[31m";
const ORANGE = "\x1b[38;5;208m";
const YELLOW = "\x1b[33m";
const BLUE = "\x1b[34m";
const GRAY = "\x1b[90m";
const CYAN = "\x1b[36m";
const GREEN = "\x1b[32m";

function colorFor(severity: Severity): string {
  switch (severity) {
    case "CRITICAL":
      return RED;
    case "HIGH":
      return ORANGE;
    case "MEDIUM":
      return YELLOW;
    case "LOW":
      return BLUE;
    default:
      return GRAY;
  }
}

function badge(severity: Severity): string {
  const color = colorFor(severity);
  return `${color}${BOLD} ${severity.padEnd(8)} ${RESET}`;
}

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export function printReport(result: ScanResult): void {
  const timestamp = new Date().toISOString();

  console.log(`${BOLD}${CYAN}SolAudit${RESET} ${DIM}v0.3.2 — static analysis for Anchor/Solana programs${RESET}`);
  console.log(`${DIM}Scanned ${result.scannedFiles} file(s) at ${timestamp}${RESET}`);
  console.log(`${GRAY}${"─".repeat(70)}${RESET}`);

  if (result.findings.length === 0) {
    console.log(`${GREEN}${BOLD}✔ No issues found.${RESET}`);
  } else {
    const grouped = new Map<Severity, Finding[]>();
    for (const finding of result.findings) {
      const bucket = grouped.get(finding.severity) ?? [];
      bucket.push(finding);
      grouped.set(finding.severity, bucket);
    }

    for (const severity of SEVERITY_ORDER) {
      const findings = grouped.get(severity);
      if (!findings || findings.length === 0) continue;

      console.log("");
      console.log(`${colorFor(severity)}${BOLD}${severity} (${findings.length})${RESET}`);

      for (const finding of findings) {
        console.log(`  ${badge(finding.severity)} ${BOLD}${finding.ruleId}${RESET} ${finding.ruleName}`);
        console.log(`    ${DIM}${finding.filePath}:${finding.line}${RESET}`);
        console.log(`    ${GRAY}│${RESET} ${finding.snippet}`);
        console.log(`    ${GRAY}└─${RESET} ${finding.description}`);
      }
    }
  }

  console.log("");
  console.log(`${GRAY}${"─".repeat(70)}${RESET}`);
  console.log(`${BOLD}Summary${RESET}`);
  console.log(
    `  ${RED}${BOLD}CRITICAL${RESET} ${result.summary.critical}   ` +
      `${ORANGE}${BOLD}HIGH${RESET} ${result.summary.high}   ` +
      `${YELLOW}${BOLD}MEDIUM${RESET} ${result.summary.medium}   ` +
      `${BLUE}${BOLD}LOW${RESET} ${result.summary.low}   ` +
      `${GRAY}${BOLD}INFO${RESET} ${result.summary.info}`
  );
  console.log(`  ${DIM}Total findings: ${result.findings.length} across ${result.scannedFiles} file(s)${RESET}`);
  console.log("");
}
