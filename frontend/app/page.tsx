export default function Home() {
  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-7xl px-6 py-8">
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

        <section className="grid gap-4 md:grid-cols-3">
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
            <p className="text-sm text-slate-400">Active Alerts</p>
            <p className="mt-2 text-3xl font-bold">12</p>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
            <p className="text-sm text-slate-400">High Severity</p>
            <p className="mt-2 text-3xl font-bold text-red-400">3</p>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
            <p className="text-sm text-slate-400">AI Analyses</p>
            <p className="mt-2 text-3xl font-bold text-cyan-400">27</p>
          </div>
        </section>

        <section className="mt-8 grid gap-6 lg:grid-cols-2">
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">
            <h2 className="text-xl font-semibold">Manual Input</h2>
            <p className="mt-1 text-sm text-slate-400">
              Paste SIEM alert, EDR event, Windows Event Log, Sysmon log, or raw
              JSON.
            </p>

            <textarea
              className="mt-4 h-64 w-full rounded-lg border border-slate-700 bg-slate-950 p-4 text-sm text-slate-100 outline-none focus:border-cyan-500"
              placeholder="Paste alert or log here..."
            />

            <button className="mt-4 rounded-lg bg-cyan-500 px-5 py-2 font-medium text-slate-950 hover:bg-cyan-400">
              Analyze Alert
            </button>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">
            <h2 className="text-xl font-semibold">File Upload</h2>
            <p className="mt-1 text-sm text-slate-400">
              Upload .txt, .log, .json or .csv file for analysis.
            </p>

            <div className="mt-4 flex h-64 items-center justify-center rounded-lg border border-dashed border-slate-700 bg-slate-950 p-6 text-center">
              <div>
                <p className="text-slate-300">Drop log file here</p>
                <p className="mt-2 text-sm text-slate-500">
                  or select file manually
                </p>

                <input
                  type="file"
                  accept=".txt,.log,.json,.csv"
                  className="mt-4 block text-sm text-slate-400 file:mr-4 file:rounded-lg file:border-0 file:bg-slate-800 file:px-4 file:py-2 file:text-slate-100 hover:file:bg-slate-700"
                />
              </div>
            </div>

            <button className="mt-4 rounded-lg bg-slate-100 px-5 py-2 font-medium text-slate-950 hover:bg-white">
              Analyze File
            </button>
          </div>
        </section>

        <section className="mt-8 rounded-xl border border-slate-800 bg-slate-900 p-6">
          <h2 className="text-xl font-semibold">Recent Analysis Results</h2>

          <div className="mt-4 overflow-hidden rounded-lg border border-slate-800">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-950 text-slate-400">
                <tr>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Alert</th>
                  <th className="px-4 py-3">Source</th>
                  <th className="px-4 py-3">Status</th>
                </tr>
              </thead>
              <tbody>
                <tr className="border-t border-slate-800">
                  <td className="px-4 py-3 text-red-400">High</td>
                  <td className="px-4 py-3">Suspicious PowerShell Execution</td>
                  <td className="px-4 py-3 text-slate-400">Sysmon</td>
                  <td className="px-4 py-3 text-yellow-400">Needs Review</td>
                </tr>
                <tr className="border-t border-slate-800">
                  <td className="px-4 py-3 text-orange-400">Medium</td>
                  <td className="px-4 py-3">Multiple Failed Logins</td>
                  <td className="px-4 py-3 text-slate-400">Windows Security</td>
                  <td className="px-4 py-3 text-cyan-400">Analyzed</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </main>
  );
}
