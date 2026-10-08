import type { ScanResult, Severity } from "../types";
import { rules } from "../rules/index";

const SARIF_VERSION = "2.1.0";
const TOOL_VERSION = "0.2.0";

function severityToSarifLevel(severity: Severity): "error" | "warning" | "note" {
  switch (severity) {
    case "CRITICAL":
    case "HIGH":
      return "error";
    case "MEDIUM":
      return "warning";
    default:
      return "note";
  }
}

function toFileUri(filePath: string): string {
  // SARIF prefers relative, forward-slash URIs.
  return filePath.replace(/\\/g, "/").replace(/^\.\//, "");
}

export function toSarif(result: ScanResult) {
  const sarifRules = rules.map((rule) => ({
    id: rule.id,
    name: rule.name.replace(/\s+/g, ""),
    shortDescription: { text: rule.name },
    fullDescription: { text: rule.description },
    defaultConfiguration: { level: severityToSarifLevel(rule.severity) },
    properties: { severity: rule.severity },
  }));

  const sarifResults = result.findings.map((finding) => ({
    ruleId: finding.ruleId,
    level: severityToSarifLevel(finding.severity),
    message: { text: `${finding.description} (${finding.snippet})` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: toFileUri(finding.filePath) },
          region: { startLine: Math.max(1, finding.line) },
        },
      },
    ],
  }));

  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: "SolAudit",
            informationUri: "https://github.com/blueeyez425-art/solaudit",
            version: TOOL_VERSION,
            rules: sarifRules,
          },
        },
        results: sarifResults,
      },
    ],
  };
}
