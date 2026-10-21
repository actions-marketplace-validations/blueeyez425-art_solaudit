import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import type { Finding, Rule, ScanResult } from "./types";
import { isTestLikePath } from "./anchor";

/**
 * Run every rule against source that is already in memory (no filesystem access).
 * This is the core primitive used by both `scanFile` (CLI, reads from disk) and the
 * web app (fetches file content from GitHub's API or a browser file upload).
 */
export function scanContent(content: string, filePath: string, rules: Rule[]): Finding[] {
  const findings: Finding[] = [];

  for (const rule of rules) {
    try {
      const ruleFindings = rule.check(content, filePath);
      findings.push(...ruleFindings);
    } catch (err) {
      // A single misbehaving rule should never crash the whole scan.
      console.error(`[solaudit] rule ${rule.id} threw on ${filePath}: ${(err as Error).message}`);
    }
  }

  return findings.sort((a, b) => a.line - b.line);
}

/** Run every rule against a single file's contents, read from disk. */
export function scanFile(filePath: string, rules: Rule[]): Finding[] {
  const content = readFileSync(filePath, "utf8");
  return scanContent(content, filePath, rules);
}

/**
 * Directories skipped by default: test suites, fuzz harnesses, fixtures and
 * example code. Findings there are almost never actionable on-chain signal
 * (in real-world scans they accounted for a meaningful share of pure noise).
 * `--include-tests` restores the old behavior.
 */
const EXCLUDED_DIR_NAMES = new Set([
  "tests",
  "test",
  "test-utils",
  "test_utils",
  "testing",
  "fuzz",
  "fixtures",
  "fixture",
  "benches",
  "benchmarks",
  "examples",
  "example",
]);

function walk(dirPath: string, files: string[] = [], includeTests = false, rootPath?: string): string[] {
  const root = rootPath ?? dirPath;
  const entries = readdirSync(dirPath);

  for (const entry of entries) {
    if (entry === "node_modules" || entry === "target" || entry === ".git") continue;
    if (!includeTests && EXCLUDED_DIR_NAMES.has(entry.toLowerCase())) continue;

    const fullPath = join(dirPath, entry);
    const stat = statSync(fullPath);

    if (stat.isDirectory()) {
      walk(fullPath, files, includeTests, root);
    } else if (stat.isFile() && fullPath.endsWith(".rs")) {
      // Test-like detection applies to the path *relative to the scan root*:
      // exclusions trim noise from a repo walk, but never override a user who
      // explicitly pointed the scanner at a directory named e.g. `examples`.
      const rel = fullPath.slice(root.length).replace(/^[\/\\]/, "");
      if (!includeTests && isTestLikePath(rel)) continue;
      files.push(fullPath);
    }
  }

  return files;
}

function emptySummary() {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

function tallySummary(findings: Finding[]): ScanResult["summary"] {
  const summary = emptySummary();

  for (const finding of findings) {
    switch (finding.severity) {
      case "CRITICAL":
        summary.critical++;
        break;
      case "HIGH":
        summary.high++;
        break;
      case "MEDIUM":
        summary.medium++;
        break;
      case "LOW":
        summary.low++;
        break;
      case "INFO":
        summary.info++;
        break;
    }
  }

  return summary;
}

function sortAndSummarize(rsFileCount: number, allFindings: Finding[]): ScanResult {
  const severityOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  allFindings.sort((a, b) => {
    const sev = severityOrder[a.severity] - severityOrder[b.severity];
    if (sev !== 0) return sev;
    if (a.filePath !== b.filePath) return a.filePath.localeCompare(b.filePath);
    return a.line - b.line;
  });

  return {
    scannedFiles: rsFileCount,
    findings: allFindings,
    summary: tallySummary(allFindings),
  };
}

/** Recursively scan a directory (or a single file) for .rs files and aggregate findings. */
export async function scanDirectory(
  targetPath: string,
  rules: Rule[],
  opts: { includeTests?: boolean } = {}
): Promise<ScanResult> {
  const stat = statSync(targetPath);
  const rsFiles = stat.isDirectory()
    ? walk(targetPath, [], opts.includeTests ?? false)
    : targetPath.endsWith(".rs")
      ? [targetPath]
      : [];

  const allFindings: Finding[] = [];

  for (const file of rsFiles) {
    allFindings.push(...scanFile(file, rules));
  }

  return sortAndSummarize(rsFiles.length, allFindings);
}

export interface InMemoryFile {
  path: string;
  content: string;
}

/**
 * Scan a set of in-memory .rs files (e.g. fetched from the GitHub API or uploaded
 * via a browser). Used by the web app, which has no local filesystem to walk.
 */
export function scanFiles(files: InMemoryFile[], rules: Rule[]): ScanResult {
  const allFindings: Finding[] = [];

  for (const file of files) {
    allFindings.push(...scanContent(file.content, file.path, rules));
  }

  return sortAndSummarize(files.length, allFindings);
}
