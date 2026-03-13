import { useEffect, useState } from 'react';
import type { Report } from '../types';
import { fetchLatestReport } from '../services/api';

export const GraphView = () => {
  const [report, setReport] = useState<Report | null>(null);

  const handleRunTrace = async () => {
    // Trigger new analysis
    const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
    try {
      await fetch(`${API_URL}/trigger/email`, { method: 'POST' });
      // Poll for updates
      const interval = setInterval(async () => {
        const data = await fetchLatestReport();
        if (data) setReport(data);
        if (data?.final_report) clearInterval(interval);
      }, 2000);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchLatestReport().then(setReport);
  }, []);

  return (
    <section className="flex-1 relative flex flex-col p-6 bg-slate-50 dark:bg-background-dark/30 overflow-hidden">
      <div className="flex items-center justify-between mb-8 z-10">
        <div>
          <h3 className="text-2xl font-black text-slate-900 dark:text-slate-100 tracking-tight">Orchestration Graph</h3>
          <p className="text-slate-500 dark:text-slate-400 text-sm">Real-time state transitions and task delegation</p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => window.location.reload()} className="bg-white dark:bg-primary/10 border border-slate-200 dark:border-primary/20 px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2 text-slate-800 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-primary/20 transition-colors">
            <span className="material-symbols-outlined text-sm">refresh</span> Reset View
          </button>
          <button onClick={handleRunTrace} className="bg-primary text-white px-4 py-2 rounded-lg text-sm font-bold flex items-center gap-2 hover:bg-primary/90 transition-colors shadow-lg shadow-primary/20">
            <span className="material-symbols-outlined text-sm">play_arrow</span> Run Trace
          </button>
        </div>
      </div>
      
      {/* Visualization Canvas */}
      <div className="flex-1 relative border border-slate-200 dark:border-primary/10 rounded-2xl bg-white dark:bg-background-dark node-connector overflow-hidden shadow-inner min-h-[500px]">
        {/* SVG Connections (Visualizing the flow) */}
        <svg className="absolute inset-0 w-full h-full pointer-events-none opacity-40" preserveAspectRatio="none" viewBox="0 0 100 100">
          <defs>
            <marker id="arrowhead" markerHeight="7" markerWidth="10" orient="auto" refX="0" refY="3.5">
              <polygon fill="#ec5b13" points="0 0, 10 3.5, 0 7"></polygon>
            </marker>
          </defs>
          {/* Supervisor to Agents */}
          <line markerEnd="url(#arrowhead)" stroke="#ec5b13" strokeWidth="0.2" x1="50" x2="20" y1="20" y2="50" vectorEffect="non-scaling-stroke"></line>
          <line markerEnd="url(#arrowhead)" stroke="#ec5b13" strokeWidth="0.2" x1="50" x2="50" y1="20" y2="50" vectorEffect="non-scaling-stroke"></line>
          <line markerEnd="url(#arrowhead)" stroke="#ec5b13" strokeWidth="0.2" x1="50" x2="80" y1="20" y2="50" vectorEffect="non-scaling-stroke"></line>
        {/* Shared State Connections */}
        <path d="M 20 58 Q 20 85 50 85" fill="none" stroke="#ec5b13" strokeDasharray="5,5" strokeWidth="0.15" vectorEffect="non-scaling-stroke"></path>
        <path d="M 50 58 Q 50 85 50 85" fill="none" stroke="#ec5b13" strokeDasharray="5,5" strokeWidth="0.15" vectorEffect="non-scaling-stroke"></path>
        <path d="M 80 58 Q 80 85 50 85" fill="none" stroke="#ec5b13" strokeDasharray="5,5" strokeWidth="0.15" vectorEffect="non-scaling-stroke"></path>
          {/* Return to Supervisor */}
          <path d="M 50 80 L 10 80 L 10 20 L 40 20" fill="none" markerEnd="url(#arrowhead)" stroke="#ec5b13" strokeWidth="0.2" vectorEffect="non-scaling-stroke"></path>
        </svg>

        {/* Nodes */}
        {/* Supervisor Node */}
        <div className="absolute top-[5%] sm:top-[10%] left-1/2 -translate-x-1/2 z-20">
          <div className="bg-primary p-1 rounded-xl shadow-2xl shadow-primary/40 group hover:scale-105 transition-transform duration-300">
            <div className="bg-background-dark px-6 py-4 rounded-lg flex items-center gap-4">
              <div className="size-12 rounded-full bg-primary/20 flex items-center justify-center">
                <span className="material-symbols-outlined text-primary text-3xl">psychology</span>
              </div>
              <div>
                <h4 className="text-white font-bold">Supervisor</h4>
                <span className="text-[10px] uppercase bg-primary text-white px-2 py-0.5 rounded-full font-black">Orchestrator</span>
              </div>
            </div>
          </div>
        </div>

        {/* Agent Nodes Row */}
        <div className="absolute top-[40%] sm:top-1/2 left-0 w-full -translate-y-1/2 flex justify-between px-[10%] sm:px-[15%] z-20">
          {/* Email Analyst */}
          <div className="bg-white dark:bg-slate-800 border-2 border-slate-200 dark:border-primary/20 p-4 rounded-xl shadow-lg w-48 hover:border-primary transition-colors group cursor-pointer hover:-translate-y-1 transform duration-200">
            <div className="flex items-center gap-3 mb-2">
              <span className="material-symbols-outlined text-primary group-hover:animate-pulse">mail</span>
              <span className="font-bold text-sm text-slate-800 dark:text-slate-100">Email Analyst</span>
            </div>
            <p className="text-[11px] text-slate-500">Processing headers and attachments...</p>
            <div className="mt-3 flex gap-1">
              <div className="h-1 flex-1 bg-green-500 rounded-full"></div>
              <div className="h-1 flex-1 bg-slate-200 dark:bg-slate-700 rounded-full"></div>
            </div>
          </div>

          {/* Forensic Analyst */}
          <div className="bg-white dark:bg-slate-800 border-2 border-primary p-4 rounded-xl shadow-lg w-48 shadow-primary/10 group cursor-pointer hover:-translate-y-1 transform duration-200 relative">
            <div className="absolute -top-2 -right-2 flex size-4 items-center justify-center rounded-full bg-primary animate-bounce">
                <span className="text-[8px] text-white font-bold">!</span>
            </div>
            <div className="flex items-center gap-3 mb-2">
              <span className="material-symbols-outlined text-primary">biotech</span>
              <span className="font-bold text-sm text-slate-800 dark:text-slate-100">Forensic Analyst</span>
            </div>
            <p className="text-[11px] text-slate-500">Analyzing binary signatures...</p>
            <div className="mt-3 flex gap-1">
              <div className="h-1 flex-1 bg-primary rounded-full animate-pulse"></div>
              <div className="h-1 flex-1 bg-primary/30 rounded-full"></div>
            </div>
          </div>

          {/* Threat Intel */}
          <div className="bg-white dark:bg-slate-800 border-2 border-slate-200 dark:border-primary/20 p-4 rounded-xl shadow-lg w-48 hover:border-primary transition-colors group cursor-pointer hover:-translate-y-1 transform duration-200">
            <div className="flex items-center gap-3 mb-2">
              <span className="material-symbols-outlined text-primary">public</span>
              <span className="font-bold text-sm text-slate-800 dark:text-slate-100">Threat Intel</span>
            </div>
            <p className="text-[11px] text-slate-500">Checking MISP/Taxii feeds...</p>
            <div className="mt-3 flex gap-1">
              <div className="h-1 flex-1 bg-slate-200 dark:bg-slate-700 rounded-full"></div>
              <div className="h-1 flex-1 bg-slate-200 dark:bg-slate-700 rounded-full"></div>
            </div>
          </div>
        </div>

        {/* Shared State Hub */}
        <div className="absolute bottom-[5%] left-1/2 -translate-x-1/2 w-80 z-20 hover:scale-[1.02] transition-transform duration-300 cursor-pointer">
          <div className="bg-slate-900 border border-primary/40 rounded-2xl p-4 shadow-2xl">
            <div className="flex items-center gap-3 mb-4 border-b border-white/10 pb-2">
              <span className="material-symbols-outlined text-primary">database</span>
              <h5 className="text-white font-bold text-sm">Shared State Hub</h5>
            </div>
            
            {report ? (
              <div className="space-y-3">
                <div className="flex items-center justify-between group">
                  <span className="text-[10px] text-slate-400 font-mono group-hover:text-slate-300">Findings:</span>
                  <span className="text-[10px] bg-primary/20 text-primary px-2 py-0.5 rounded">{report.findings?.length || 0} Detected</span>
                </div>
                <div className="flex items-center justify-between group">
                  <span className="text-[10px] text-slate-400 font-mono group-hover:text-slate-300">IOCs:</span>
                  <span className="text-[10px] bg-primary/20 text-primary px-2 py-0.5 rounded">{report.iocs?.length || 0} Collected</span>
                </div>
                <div className="flex items-center justify-between group">
                  <span className="text-[10px] text-slate-400 font-mono group-hover:text-slate-300">Error Logs:</span>
                  <span className={`text-[10px] px-2 py-0.5 rounded ${(report.error_logs?.length || 0) > 0 ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'}`}>
                    {(report.error_logs?.length || 0) > 0 ? `${report.error_logs?.length} Errors` : 'None'}
                  </span>
                </div>
              </div>
            ) : (
              <div className="flex justify-center p-2">
                 <span className="material-symbols-outlined animate-spin text-primary">autorenew</span>
              </div>
            )}
            
          </div>
        </div>
      </div>
    </section>
  );
};
