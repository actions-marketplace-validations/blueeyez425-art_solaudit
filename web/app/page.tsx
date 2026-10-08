"use client";

import { useRef, useState } from "react";
import type { ScanResult } from "@solaudit/core";
import { ResultsView } from "@/components/ResultsView";

type Mode = "repo" | "upload";

interface ScanResponse {
  mode: Mode;
  repoUrl?: string;
  fileName?: string;
  ref?: string;
  truncated?: boolean;
  result: ScanResult;
}

// Keep in sync with packages/core/src/rules/index.ts (10 rules).
const RULES = [
  { id: "SOL-001", severity: "CRITICAL", name: "Missing Signer Check" },
  { id: "SOL-002", severity: "HIGH", name: "Unchecked Account Deserialization" },
  { id: "SOL-003", severity: "HIGH", name: "Arbitrary CPI" },
  { id: "SOL-004", severity: "HIGH", name: "Missing Bump Seed Canonicalization" },
  { id: "SOL-005", severity: "MEDIUM", name: "Integer Overflow Risk" },
  { id: "SOL-006", severity: "HIGH", name: "Type Cosplay / Missing Discriminator Check" },
  { id: "SOL-007", severity: "MEDIUM", name: "Insecure Account Initialization" },
  { id: "SOL-008", severity: "LOW", name: "Missing Owner Check" },
  { id: "SOL-009", severity: "HIGH", name: "Insecure Manual Account Closure" },
  { id: "SOL-011", severity: "MEDIUM", name: "Missing Rent-Exemption Check" },
];

export default function Home() {
  const [mode, setMode] = useState<Mode>("repo");
  const [repoUrl, setRepoUrl] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [response, setResponse] = useState<ScanResponse | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  async function handleScan(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setResponse(null);

    if (mode === "repo" && !repoUrl.trim()) {
      setError("Enter a GitHub repository URL first.");
      return;
    }
    if (mode === "upload" && !file) {
      setError("Choose a .rs file first.");
      return;
    }

    setLoading(true);
    try {
      let res: Response;
      if (mode === "repo") {
        res = await fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ repoUrl }),
        });
      } else {
        const form = new FormData();
        form.append("file", file as File);
        res = await fetch("/api/scan", { method: "POST", body: form });
      }

      const data = await res.json();
      if (!res.ok) {
        setError(data.error ?? "Something went wrong.");
        return;
      }
      setResponse(data as ScanResponse);
    } catch {
      setError("Network error — please try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="mx-auto max-w-3xl px-4 py-16">
      <header className="mb-10 text-center">
        <div className="mb-2 inline-flex items-center gap-2 rounded-full border border-slate-800 bg-slate-900/60 px-3 py-1 text-xs text-slate-400">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
          Free · No install · No account
        </div>
        <h1 className="text-3xl font-bold tracking-tight text-slate-50 sm:text-4xl">SolAudit</h1>
        <p className="mt-3 text-slate-400">
          Static analysis for Anchor/Solana programs. Paste a public GitHub repo or upload a{" "}
          <code className="rounded bg-slate-800 px-1 py-0.5 text-sm">.rs</code> file — get a full security report in
          seconds.
        </p>
      </header>

      <form onSubmit={handleScan} className="rounded-xl border border-slate-800 bg-slate-900/40 p-6">
        <div className="mb-4 flex gap-2 rounded-lg bg-slate-950 p-1">
          <button
            type="button"
            onClick={() => setMode("repo")}
            className={`flex-1 rounded-md px-3 py-2 text-sm font-medium transition ${
              mode === "repo" ? "bg-slate-800 text-slate-50" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            GitHub Repo URL
          </button>
          <button
            type="button"
            onClick={() => setMode("upload")}
            className={`flex-1 rounded-md px-3 py-2 text-sm font-medium transition ${
              mode === "upload" ? "bg-slate-800 text-slate-50" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            Upload .rs File
          </button>
        </div>

        {mode === "repo" ? (
          <input
            type="text"
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
            placeholder="https://github.com/owner/anchor-program"
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-slate-100 placeholder-slate-500 outline-none focus:border-sky-500"
          />
        ) : (
          <div
            onClick={() => fileInputRef.current?.click()}
            className="cursor-pointer rounded-lg border border-dashed border-slate-700 bg-slate-950 px-4 py-8 text-center text-sm text-slate-400 hover:border-sky-500"
          >
            {file ? (
              <span className="text-slate-200">{file.name}</span>
            ) : (
              <span>Click to choose a .rs file (max 1 MB)</span>
            )}
            <input
              ref={fileInputRef}
              type="file"
              accept=".rs"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              className="hidden"
            />
          </div>
        )}

        <button
          type="submit"
          disabled={loading}
          className="mt-4 w-full rounded-lg bg-sky-500 px-4 py-3 text-sm font-semibold text-slate-950 transition hover:bg-sky-400 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {loading ? "Scanning…" : "Scan for vulnerabilities"}
        </button>

        {error && (
          <div className="mt-4 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
            {error}
          </div>
        )}
      </form>

      {response && (
        <ResultsView
          result={response.result}
          sourceLabel={
            response.mode === "repo"
              ? `${response.repoUrl}${response.ref ? ` @ ${response.ref}` : ""}${
                  response.truncated ? " (large repo — scan capped for speed)" : ""
                }`
              : (response.fileName ?? "Uploaded file")
          }
        />
      )}

      <section className="mt-16 border-t border-slate-800 pt-8">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-500">What it checks for</h2>
        <div className="mt-4 grid gap-2 sm:grid-cols-2">
          {RULES.map((rule) => (
            <div key={rule.id} className="rounded-lg border border-slate-800 bg-slate-900/30 px-3 py-2 text-sm">
              <span className="font-mono text-xs text-slate-500">{rule.id}</span>{" "}
              <span className="text-slate-300">{rule.name}</span>
            </div>
          ))}
        </div>
        <p className="mt-6 text-center text-xs text-slate-600">
          Also available as a CLI:{" "}
          <code className="rounded bg-slate-800 px-1 py-0.5">npx solaudit ./program</code> ·{" "}
          <a
            href="https://github.com/blueeyez425-art/solaudit"
            className="text-slate-500 underline hover:text-slate-300"
            target="_blank"
            rel="noreferrer"
          >
            View source on GitHub
          </a>
        </p>
      </section>
    </main>
  );
}
