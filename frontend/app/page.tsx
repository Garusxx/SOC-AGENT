"use client";

import { useState } from "react";

type AnalysisResult = {
  severity: string;
  mitre: string;
  classification: string;
  summary: string;
  indicators: string[];
  recommendations: string[];
  raw_log_explanation: string;
  received_chars: number;
  source?: string;
  filename?: string;
  parser?: {
    log_type: string;
    total_lines: number;
    selected_lines: number;
  };
};
export default function Home() {
  const [alertText, setAlertText] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [fileContent, setFileContent] = useState("");

  async function analyzeAlert() {
    console.log("Analyze clicked", alertText);

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch(
        "http://127.0.0.1:8000/api/analyze/manual/",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            alert: alertText,
          }),
        },
      );

      if (!response.ok) {
        throw new Error("API request failed");
      }

      const data = await response.json();
      setResult(data);
    } catch {
      setError("Could not analyze alert. Check if backend is running.");
    } finally {
      setLoading(false);
    }
  }

  async function handleFileChange(file: File | null) {
    setSelectedFile(file);
    setFileContent("");

    if (!file) return;

    const text = await file.text();
    setFileContent(text);
  }

  async function analyzeFile() {
    if (!selectedFile) return;

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const formData = new FormData();
      formData.append("file", selectedFile);

      const response = await fetch("http://127.0.0.1:8000/api/analyze/file/", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        throw new Error("API request failed");
      }

      const data = await response.json();
      setResult(data);
    } catch {
      setError("Could not analyze file. Check if backend is running.");
    } finally {
      setLoading(false);
    }
  }

  const displayedLog = fileContent || alertText;

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="w-full px-6 py-8">
        <header className="mb-8">
          <p className="text-sm text-cyan-400">SOC Agent Platform</p>
          <h1 className="mt-2 text-3xl font-bold">
            Security Operations Dashboard
          </h1>
          <p className="mt-2 text-slate-400">
            Analyze alerts, logs, and suspicious activity with AI-assisted
            triage.
          </p>
        </header>

        <section className="grid gap-6 lg:grid-cols-[380px_1fr]">
          {/* LEFT TOOLBAR */}
          <aside className="space-y-6 lg:sticky lg:top-6 self-start">
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">
              <h2 className="text-xl font-semibold">Manual Input</h2>

              <textarea
                value={alertText}
                onChange={(event) => setAlertText(event.target.value)}
                className="mt-4 h-40 w-full rounded-lg border border-slate-700 bg-slate-950 p-4 text-sm text-slate-100 outline-none focus:border-cyan-500"
                placeholder="Paste alert or log here..."
              />

              <button
                onClick={analyzeAlert}
                disabled={loading || !alertText.trim()}
                className="mt-4 w-full rounded-lg bg-cyan-500 px-5 py-2 font-medium text-slate-950 hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {loading ? "Analyzing..." : "Analyze Alert"}
              </button>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">
              <h2 className="text-xl font-semibold">File Upload</h2>

              <input
                type="file"
                accept=".txt,.log,.json,.csv"
                onChange={(event) =>
                  handleFileChange(event.target.files?.[0] ?? null)
                }
                className="mt-4 block w-full text-sm text-slate-400 file:mr-4 file:rounded-lg file:border-0 file:bg-slate-800 file:px-4 file:py-2 file:text-slate-100 hover:file:bg-slate-700"
              />

              <button
                className="mt-4 w-full rounded-lg bg-slate-100 px-5 py-2 font-medium text-slate-950 hover:bg-white disabled:cursor-not-allowed disabled:opacity-50"
                onClick={analyzeFile}
                disabled={loading || !selectedFile}
              >
                {loading ? "Analyzing..." : "Analyze File"}
              </button>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">
              <h2 className="text-xl font-semibold">File History</h2>

              <div className="mt-4 space-y-3 text-sm">
                {selectedFile ? (
                  <div className="rounded-lg border border-cyan-800 bg-slate-950 p-3">
                    <p className="font-medium text-slate-200">
                      {selectedFile.name}
                    </p>
                    <p className="text-slate-500">Selected for analysis</p>
                  </div>
                ) : (
                  <p className="text-sm text-slate-500">
                    No files uploaded yet.
                  </p>
                )}

                <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
                  <p className="font-medium text-slate-200">sysmon-alert.log</p>
                  <p className="text-slate-500">Analyzed · High severity</p>
                </div>

                <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
                  <p className="font-medium text-slate-200">
                    windows-events.csv
                  </p>
                  <p className="text-slate-500">Analyzed · Medium severity</p>
                </div>
              </div>
            </div>
          </aside>

          {/* RIGHT ANALYSIS AREA */}
          <section className="space-y-6">
            {error && (
              <div className="rounded-lg border border-red-800 bg-red-950 p-4 text-sm text-red-300">
                {error}
              </div>
            )}

            {result && (
              <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">
                <h2 className="text-xl font-semibold text-cyan-400">
                  Analysis Result
                </h2>

                <div className="mt-4 grid gap-4 md:grid-cols-3">
                  <div className="rounded-lg border border-slate-800 bg-slate-950 p-4">
                    <p className="text-sm text-slate-400">Severity</p>
                    <p className="mt-1 text-lg font-semibold text-red-400">
                      {result.severity}
                    </p>
                  </div>

                  <div className="rounded-lg border border-slate-800 bg-slate-950 p-4">
                    <p className="text-sm text-slate-400">MITRE</p>
                    <p className="mt-1 text-lg font-semibold">{result.mitre}</p>
                  </div>

                  <div className="rounded-lg border border-slate-800 bg-slate-950 p-4">
                    <p className="text-sm text-slate-400">Classification</p>
                    <p className="mt-1 text-lg font-semibold">
                      {result.classification}
                    </p>
                  </div>
                </div>

                <div className="mt-6">
                  <p className="text-slate-400">Recommendations</p>
                  <ul className="mt-3 list-inside list-disc space-y-2 text-sm">
                    {result.recommendations.map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                </div>
              </div>
            )}

            <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <h2 className="text-xl font-semibold">Full Log Preview</h2>
                  <p className="mt-1 text-sm text-slate-400">
                    Pełne logi z manual input albo z ostatnio wybranego pliku.
                  </p>
                </div>

                {selectedFile && (
                  <div className="text-right text-sm text-slate-500">
                    <p>{selectedFile.name}</p>
                    <p>{Math.round(selectedFile.size / 1024)} KB</p>
                  </div>
                )}
              </div>

              <pre className="mt-4 min-h-[600px] max-h-[calc(100vh-260px)] overflow-auto whitespace-pre-wrap break-words rounded-lg border border-slate-800 bg-slate-950 p-5 font-mono text-sm leading-6 text-slate-200">
                {displayedLog || "No log selected yet."}
              </pre>
            </div>
          </section>
        </section>
      </div>
    </main>
  );
}
