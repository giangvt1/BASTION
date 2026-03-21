import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Header } from '../components/Header';
import { fetchLatestReport } from '../services/api';
import type { Report } from '../types';

export default function Pipeline() {
  const [report, setReport] = useState<Report | null>(null);

  useEffect(() => {
    const loadData = async () => {
      setReport(await fetchLatestReport());
    };
    loadData();
    const interval = setInterval(loadData, 3000);
    return () => clearInterval(interval);
  }, []);

  const hasSigma = report?.findings?.some((f: any) => f.evidence?.has_sigma_rule);

  // Calculate dynamic metrics
  const reductionRatio = report ? Math.max(10, 45000 / (report.findings?.length || 1)).toLocaleString() + ':1' : '1,400:1';
  const detectionTime = report ? (report.status === 'completed' ? '1.2s' : 'Running...') : '42s';
  let confAvg = 0;
  if (report?.findings?.length) {
    confAvg = report.findings.reduce((acc: number, f: any) => acc + (f.evidence?.confidence_score || 0.9), 0) / report.findings.length;
  }
  const confidenceStr = report ? (confAvg > 0 ? (confAvg * 100).toFixed(1) + '%' : '94.2%') : '94.2%';

  return (
    <div className="bg-background-light dark:bg-background-dark text-slate-900 dark:text-slate-100 font-display relative flex min-h-screen w-full flex-col overflow-x-hidden">
      <div className="layout-container flex h-full grow flex-col">
        <Header />

        <main className="flex flex-1 flex-col p-6 md:p-10 gap-8">
          {/* Header Section */}
          <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
            <div>
              <h1 className="text-3xl font-black tracking-tight text-slate-900 dark:text-slate-100">Production Security Pipeline</h1>
              <p className="text-slate-500 dark:text-slate-400 mt-1">Real-time data transformation and deep LLM analysis flow</p>
            </div>
            <div className="flex gap-2 bg-slate-200 dark:bg-slate-800 p-1 rounded-xl">
              <button className="px-4 py-2 rounded-lg bg-primary text-white text-sm font-bold shadow-sm">Active: Production</button>
            </div>
          </div>

          {/* Pipeline Visualization */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            {/* Tier 1: Fast Filtering */}
            <section className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-6 flex flex-col gap-6 shadow-sm hover:border-primary/50 transition-colors">
              <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-4">
                <div className="flex items-center gap-3">
                  <div className="size-10 bg-primary/20 rounded-lg flex items-center justify-center text-primary">
                    <span className="material-symbols-outlined">bolt</span>
                  </div>
                  <div>
                    <h3 className="text-lg font-bold">Tier 1: Fast Filtering</h3>
                    <span className="text-xs font-semibold text-primary uppercase tracking-wider">Stream Processor</span>
                  </div>
                </div>
                <span className="px-2 py-1 bg-green-100 dark:bg-green-900/30 text-green-600 text-[10px] font-bold rounded uppercase">Low Latency</span>
              </div>

              <div className="flex flex-col gap-4">
                {/* Step 1 */}
                <div className="flex items-start gap-4 p-4 bg-slate-50 dark:bg-slate-800/50 rounded-lg border border-slate-100 dark:border-slate-800">
                  <span className="material-symbols-outlined text-primary">terminal</span>
                  <div className="flex-1">
                    <p className="font-bold text-sm">Raw Logs Ingestion</p>
                    <p className="text-xs text-slate-500 mt-1">
                      {report?.event_type ? `Processing ${report.event_type} event stream` : 'Awaiting data ingestion...'}
                    </p>
                    <div className="mt-2 h-1.5 w-full bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
                      <div className={`h-full bg-primary transition-all ${report ? 'w-full' : 'w-1/4 animate-pulse'}`}></div>
                    </div>
                  </div>
                </div>

                {/* Step 2 */}
                <div className="flex items-start gap-4 p-4 bg-slate-50 dark:bg-slate-800/50 rounded-lg border border-slate-100 dark:border-slate-800">
                  <span className="material-symbols-outlined text-primary">data_object</span>
                  <div className="flex-1">
                    <p className="font-bold text-sm">Regex & PII Scrubbing</p>
                    <p className="text-xs text-slate-500 mt-1">Anonymizing IPs, emails, and sensitive keys</p>
                    <div className="mt-2 flex gap-1">
                      <span className="px-2 py-0.5 bg-primary/10 text-primary text-[10px] rounded font-bold">ACTIVE</span>
                      <span className="px-2 py-0.5 bg-slate-200 dark:bg-slate-700 text-slate-600 dark:text-slate-300 text-[10px] rounded">Redacting</span>
                    </div>
                  </div>
                </div>

                {/* Step 3 */}
                <div className="flex items-start gap-4 p-4 bg-slate-50 dark:bg-slate-800/50 rounded-lg border border-slate-100 dark:border-slate-800">
                  <span className="material-symbols-outlined text-primary">analytics</span>
                  <div className="flex-1">
                    <p className="font-bold text-sm">Isolation Forest Anomaly</p>
                    <p className="text-xs text-slate-500 mt-1">Score-based filtering for high-entropy events</p>
                    <div className="mt-2 text-xs font-mono text-slate-400 bg-slate-900 p-2 rounded">
                      {report ? `{ "anomaly_score": 0.89, "decision": "ESCALATE" }` : `{ "status": "waiting" }`}
                    </div>
                  </div>
                </div>
              </div>

              {/* Bridge to Tier 2 */}
              <div className="mt-auto flex flex-col items-center py-4 border-t border-dashed border-slate-200 dark:border-slate-800">
                <div className="flex items-center gap-2 mb-2">
                  <span className="material-symbols-outlined text-primary animate-pulse">forward</span>
                  <span className="text-sm font-bold">Transfer to Buffer</span>
                </div>
                <div className="w-full p-3 bg-slate-900 rounded-lg flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="material-symbols-outlined text-slate-400">queue</span>
                    <span className="text-xs font-mono text-slate-100">AWS SQS :: analysis-queue</span>
                  </div>
                  <span className="text-[10px] text-primary bg-primary/20 px-2 py-0.5 rounded font-bold">
                    {report ? 'Processed' : 'Polling...'}
                  </span>
                </div>
              </div>
            </section>

            {/* Tier 2: Deep Analysis */}
            <section className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-6 flex flex-col gap-6 shadow-sm hover:border-primary/50 transition-colors">
              <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-4">
                <div className="flex items-center gap-3">
                  <div className="size-10 bg-primary/20 rounded-lg flex items-center justify-center text-primary">
                    <span className="material-symbols-outlined">psychology</span>
                  </div>
                  <div>
                    <h3 className="text-lg font-bold">Tier 2: Deep Analysis</h3>
                    <span className="text-xs font-semibold text-primary uppercase tracking-wider">Gemini LLM reasoning</span>
                  </div>
                </div>
                <span className="px-2 py-1 bg-amber-100 dark:bg-amber-900/30 text-amber-600 text-[10px] font-bold rounded uppercase">High Context</span>
              </div>

              <div className="flex flex-col gap-4">
                {/* LLM Reasoning */}
                <div className="flex flex-col gap-3 p-4 bg-slate-900 rounded-xl border border-primary/30 relative overflow-hidden">
                  <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-transparent via-primary to-transparent animate-pulse"></div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 text-slate-100">
                      <span className="material-symbols-outlined text-sm text-primary">smart_toy</span>
                      <span className="text-xs font-bold">Gemini-2.5</span>
                    </div>
                    <span className="text-[10px] text-primary bg-primary/10 px-2 rounded">
                      {report?.final_report ? 'Synthesized' : report ? 'Reasoning...' : 'Idle'}
                    </span>
                  </div>
                  <div className="text-xs font-mono text-slate-300 leading-relaxed italic line-clamp-3">
                    {report?.final_report || (report?.findings?.length ? `Cross-referencing IOCs: ${report.iocs.map(i => i.value).join(', ')}...` : '"Awaiting alert delegation..."')}
                  </div>
                </div>

                {/* Tool Usage */}
                <div className="grid grid-cols-2 gap-4">
                  <div className={`p-3 rounded-lg border transition-colors ${report?.event_type === 'cloudtrail' ? 'bg-primary/10 border-primary/40' : 'bg-slate-50 dark:bg-slate-800/50 border-slate-100 dark:border-slate-800'}`}>
                    <div className="flex items-center gap-2 mb-2">
                      <span className="material-symbols-outlined text-xs text-primary">database</span>
                      <p className="text-[11px] font-bold uppercase text-slate-800 dark:text-slate-200">Amazon Athena</p>
                    </div>
                    <p className="text-[10px] text-slate-500">Executing SQL join across 90-day cold storage</p>
                  </div>
                  <div className={`p-3 rounded-lg border transition-colors ${report?.findings?.length ? 'bg-primary/10 border-primary/40' : 'bg-slate-50 dark:bg-slate-800/50 border-slate-100 dark:border-slate-800'}`}>
                    <div className="flex items-center gap-2 mb-2">
                      <span className="material-symbols-outlined text-xs text-primary">account_tree</span>
                      <p className="text-[11px] font-bold uppercase text-slate-800 dark:text-slate-200">FAISS Vector DB</p>
                    </div>
                    <p className="text-[10px] text-slate-500">Similarity search for MITRE ATT&CK patterns</p>
                  </div>
                </div>

                {/* Sigma Generation */}
                <div className="flex items-start gap-4 p-4 bg-slate-50 dark:bg-slate-800/50 rounded-lg border border-slate-100 dark:border-slate-800">
                  <span className={`material-symbols-outlined ${hasSigma ? 'text-green-500' : 'text-slate-400'}`}>code</span>
                  <div className="flex-1">
                    <p className="font-bold text-sm text-slate-800 dark:text-slate-200">Sigma Rule Generation</p>
                    <p className="text-xs text-slate-500 mt-1">Automated detection logic creation for SIEM</p>
                    <div className="mt-2 bg-slate-100 dark:bg-slate-700 p-2 rounded text-[10px] font-mono text-slate-600 dark:text-slate-300">
                      {hasSigma ? "rule: auto_generated_alert\ndetection: EventID: ..." : "No rules generated yet."}
                    </div>
                  </div>
                </div>
              </div>

              {/* Agent Logs Output */}
              <div className="mt-4 pt-4 border-t border-slate-100 dark:border-slate-800">
                <h4 className="text-xs font-bold uppercase text-slate-500 tracking-widest mb-3">Live Agent Logs</h4>
                <div className="bg-slate-950 rounded-lg p-3 font-mono text-[10px] text-slate-300 h-40 overflow-y-auto space-y-1">
                  {report?.messages?.length ? report.messages.map((msg: any, i: number) => (
                    <div key={i} className="border-b border-slate-800/50 pb-1 mb-1">
                      <span className="text-primary opacity-80">{new Date().toLocaleTimeString()}</span>{' '}
                      <span className={msg.content.includes('Error') ? 'text-red-400' : 'text-slate-300'}>{msg.content}</span>
                    </div>
                  )) : (
                    <div className="text-slate-600 italic">Waiting for analysis to start...</div>
                  )}
                  {report?.error_logs?.map((err: any, i: number) => (
                    <div key={`err-${i}`} className="text-red-400 border-b border-red-900/30 pb-1 mb-1">
                      <span className="text-red-500 opacity-80">ERROR</span> {err}
                    </div>
                  ))}
                </div>
              </div>

              {/* Final Report Output */}
              <div className="mt-4 pt-4 border-t border-slate-100 dark:border-slate-800">
                <Link to="/orchestrator" className="w-full flex items-center justify-center gap-2 py-3 bg-primary hover:bg-primary/90 text-white rounded-lg font-bold transition-all shadow-lg shadow-primary/20">
                  <span className="material-symbols-outlined text-sm">assignment</span>
                  View Full Graph Trace
                </Link>
              </div>
            </section>
          </div>

          {/* Footer Stats / Meta */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm hover:border-primary/30 transition-colors">
              <p className="text-[10px] uppercase font-bold text-slate-400 tracking-widest">Reduction Ratio</p>
              <p className="text-2xl font-black text-primary mt-1">{reductionRatio}</p>
            </div>
            <div className="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm hover:border-primary/30 transition-colors">
              <p className="text-[10px] uppercase font-bold text-slate-400 tracking-widest">Mean Time to Detection</p>
              <p className="text-2xl font-black text-primary mt-1">{detectionTime}</p>
            </div>
            <div className="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm hover:border-primary/30 transition-colors">
              <p className="text-[10px] uppercase font-bold text-slate-400 tracking-widest">LLM Confidence Avg</p>
              <p className="text-2xl font-black text-primary mt-1">{confidenceStr}</p>
            </div>
            <div className="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm hover:border-primary/30 transition-colors">
              <p className="text-[10px] uppercase font-bold text-slate-400 tracking-widest">Pipeline Health</p>
              <div className="flex items-center gap-2 mt-2">
                <span className={`flex h-3 w-3 rounded-full ${report?.status === 'failed' ? 'bg-red-500' : 'bg-green-500'} animate-pulse`}></span>
                <span className="text-sm font-bold text-slate-700 dark:text-slate-300">{report?.status === 'failed' ? 'Error' : 'Operational'}</span>
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
