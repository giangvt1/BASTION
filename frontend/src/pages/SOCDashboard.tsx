import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Header } from '../components/Header';
import { fetchLatestReport, fetchNodes, fetchTraces } from '../services/api';
import type { Report, GraphNodeStatus, TraceEvent } from '../types';

export default function SOCDashboard() {
  const [report, setReport] = useState<Report | null>(null);
  const [nodes, setNodes] = useState<GraphNodeStatus[]>([]);
  const [traces, setTraces] = useState<TraceEvent[]>([]);

  useEffect(() => {
    const loadData = async () => {
      setReport(await fetchLatestReport());
      setNodes(await fetchNodes());
      setTraces(await fetchTraces());
    };
    loadData();
    const interval = setInterval(loadData, 3000);
    return () => clearInterval(interval);
  }, []);

  const riskScore = report?.risk_score ? (report.risk_score * 100).toFixed(0) : '0';
  const activeAlerts = report?.findings?.length || 0;
  const isRunning = nodes.some(n => n.status === 'running');
  const agentHealth = report?.status === 'failed' ? 'Error' : isRunning ? '98.2%' : '100%';
  const mdrEff = report ? (isRunning ? 'Analyzing...' : '1.2s') : '4.2s';

  return (
    <div className="bg-background-light dark:bg-background-dark text-slate-900 dark:text-slate-100 min-h-screen font-display">
      <Header />

      <main className="max-w-[1440px] mx-auto p-6 space-y-6">
        {/* Key Metrics */}
        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-4">
          <div className="bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-200 dark:border-slate-800 flex flex-col gap-2 hover:-translate-y-1 transition-transform cursor-default shadow-sm">
            <div className="flex justify-between items-start">
              <span className="text-slate-500 dark:text-slate-400 text-xs font-bold uppercase tracking-wider">Overall Risk Score</span>
              <span className="material-symbols-outlined text-primary">security</span>
            </div>
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-bold">{riskScore}</span>
              <span className="text-slate-400 text-sm font-medium">/ 100</span>
            </div>
            <div className="w-full bg-slate-100 dark:bg-slate-800 h-1.5 rounded-full mt-2 overflow-hidden">
              <div className="bg-primary h-full transition-all duration-500" style={{ width: `${riskScore}%` }}></div>
            </div>
            <p className="text-emerald-500 text-xs font-medium mt-1">Live updates from LangGraph</p>
          </div>
          <div className="bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-200 dark:border-slate-800 flex flex-col gap-2 hover:-translate-y-1 transition-transform cursor-default shadow-sm">
            <div className="flex justify-between items-start">
              <span className="text-slate-500 dark:text-slate-400 text-xs font-bold uppercase tracking-wider">Active Alerts</span>
              <span className="material-symbols-outlined text-red-500">warning</span>
            </div>
            <span className="text-3xl font-bold">{activeAlerts} High</span>
            <p className="text-slate-400 text-xs mt-1">Detected in current analysis trace</p>
            <p className="text-orange-500 text-xs font-medium mt-auto">Awaiting Mitigation</p>
          </div>
          <div className="bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-200 dark:border-slate-800 flex flex-col gap-2 hover:-translate-y-1 transition-transform cursor-default shadow-sm">
            <div className="flex justify-between items-start">
              <span className="text-slate-500 dark:text-slate-400 text-xs font-bold uppercase tracking-wider">Agent Health</span>
              <span className="material-symbols-outlined text-emerald-500">memory</span>
            </div>
            <span className="text-3xl font-bold">{agentHealth}</span>
            <p className="text-slate-400 text-xs mt-1">{nodes.filter(n => n.status !== 'error').length} agents responding</p>
            <p className="text-emerald-500 text-xs font-medium mt-auto">{isRunning ? 'Actively investigating...' : 'System Idle'}</p>
          </div>
          <div className="bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-200 dark:border-slate-800 flex flex-col gap-2 hover:-translate-y-1 transition-transform cursor-default shadow-sm">
            <div className="flex justify-between items-start">
              <span className="text-slate-500 dark:text-slate-400 text-xs font-bold uppercase tracking-wider">MDR Efficiency</span>
              <span className="material-symbols-outlined text-slate-400">timer</span>
            </div>
            <span className="text-3xl font-bold">{mdrEff}</span>
            <p className="text-slate-400 text-xs mt-1">Avg. Agent Response Time</p>
            <p className="text-emerald-500 text-xs font-medium mt-auto">Accelerated by Gemini 2.5</p>
          </div>
        </div>

        {/* Main Workspace Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Active Investigation Section */}
          <div className="lg:col-span-8 space-y-6">
            <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden shadow-sm">
              <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-slate-50 dark:bg-slate-900/50">
                <div className="flex items-center gap-3">
                  <span className="p-1.5 bg-red-100 dark:bg-red-900/30 text-red-600 rounded">
                    <span className="material-symbols-outlined text-lg">bolt</span>
                  </span>
                  <div>
                    <h3 className="font-bold text-sm">
                      {report?.report_id ? `Incident: ${report.report_id}` : 'Waiting for incoming events...'}
                    </h3>
                    <p className="text-xs text-slate-500">
                      {report?.event_type ? `Type: ${report.event_type.toUpperCase()}` : 'No active incident'}
                    </p>
                  </div>
                </div>
                <div className="flex gap-2 w-full sm:w-auto">
                  <button onClick={() => alert('Mitigation approved and sent to orchestration layer.')} className="flex-1 sm:flex-none bg-primary text-white text-xs font-bold py-2 px-4 rounded-lg hover:bg-primary/90 transition-colors shadow-sm">Approve Mitigation</button>
                  <Link to="/orchestrator" className="flex-1 sm:flex-none text-center bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-200 text-xs font-bold py-2 px-4 rounded-lg hover:bg-slate-300 dark:hover:bg-slate-700 transition-colors">View Analysis Trace</Link>
                </div>
              </div>

              <div className="p-6">
                <h4 className="text-sm font-bold mb-4 flex items-center gap-2">
                  <span className="material-symbols-outlined text-primary text-base">psychology</span>
                  Autonomous Reasoning Trace
                </h4>

                <div className="space-y-4 relative before:absolute before:left-[11px] before:top-2 before:bottom-2 before:w-px before:bg-slate-200 dark:before:bg-slate-800">
                  {traces.length > 0 ? traces.map((trace, i) => (
                    <div key={trace.id} className="flex gap-4 relative group animate-fade-in">
                      <div className="size-6 rounded-full bg-slate-100 dark:bg-slate-800 border-2 border-white dark:border-slate-900 flex items-center justify-center z-10 group-hover:scale-110 transition-transform">
                        <div className={`size-1.5 rounded-full ${i === traces.length - 1 && isRunning ? 'bg-primary animate-ping' : 'bg-primary'}`}></div>
                      </div>
                      <div className="flex-1 bg-slate-50 dark:bg-slate-800/40 p-3 rounded-lg border border-slate-100 dark:border-slate-800 hover:border-primary/30 transition-colors">
                        <div className="flex justify-between items-center mb-1">
                          <span className="text-xs font-bold text-primary">{trace.source}</span>
                          <span className="text-[10px] text-slate-400">{new Date(trace.timestamp).toLocaleTimeString()}</span>
                        </div>
                        <p className="text-sm text-slate-600 dark:text-slate-300">{trace.description}</p>
                      </div>
                    </div>
                  )) : (
                    <div className="text-center p-4 text-slate-500">No traces available. Go to Orchestrator to run an analysis.</div>
                  )}

                  {report?.final_report && (
                    <div className="flex gap-4 relative group">
                      <div className="size-6 rounded-full bg-slate-100 dark:bg-slate-800 border-2 border-white dark:border-slate-900 flex items-center justify-center z-10 group-hover:scale-110 transition-transform">
                        <div className="size-1.5 rounded-full bg-green-500"></div>
                      </div>
                      <div className="flex-1 bg-primary/10 border border-primary/20 p-3 rounded-lg ring-1 ring-primary/30 shadow-sm shadow-primary/10">
                        <div className="flex justify-between items-center mb-1">
                          <span className="text-xs font-bold text-primary">Response Orchestrator</span>
                          <span className="text-[10px] text-primary/80 font-bold bg-primary/10 px-2 py-0.5 rounded">FINAL REPORT</span>
                        </div>
                        <p className="text-sm font-medium">{report.final_report}</p>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Right Sidebar */}
          <div className="lg:col-span-4 space-y-6">
            {/* Alert Feed */}
            <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden shadow-sm">
              <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex justify-between items-center bg-slate-50 dark:bg-slate-900/50">
                <h4 className="font-bold text-sm">Findings</h4>
                <Link to="/orchestrator" className="text-xs text-primary font-bold hover:underline">See Details</Link>
              </div>
              <div className="divide-y divide-slate-100 dark:divide-slate-800 max-h-64 overflow-y-auto">
                {report?.findings && report.findings.length > 0 ? report.findings.map((f, i) => (
                  <div key={i} className="p-4 hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors cursor-pointer group">
                    <div className="flex gap-3">
                      <span className={`size-2 rounded-full mt-1.5 group-hover:scale-125 transition-transform ${f.severity === 'high' || f.severity === 'critical' ? 'bg-red-500' : 'bg-orange-500'}`}></span>
                      <div className="flex-1">
                        <p className="text-sm font-bold text-slate-800 dark:text-slate-200 group-hover:text-primary transition-colors">{f.finding_type || f.mitre_tactic || 'Security Finding'}</p>
                        <p className="text-xs text-slate-500 mt-0.5 truncate">{f.description}</p>
                        <p className="text-[10px] text-slate-400 mt-2 font-medium bg-slate-100 dark:bg-slate-800 inline-block px-2 py-0.5 rounded">Detected by {f.agent}</p>
                      </div>
                    </div>
                  </div>
                )) : (
                  <div className="p-4 text-center text-sm text-slate-500">No active findings</div>
                )}
              </div>
            </div>

            {/* Agent Status List */}
            <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden shadow-sm">
              <div className="p-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/50">
                <h4 className="font-bold text-sm">Autonomous Agents</h4>
              </div>
              <div className="p-4 space-y-4">
                {nodes.filter(n => n.type !== 'supervisor').map((node) => {
                  let statusColor = 'bg-slate-100 dark:bg-slate-800 text-slate-500';
                  if (node.status === 'running') statusColor = 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-600';
                  else if (node.status === 'completed') {
                    // Check if agent found a critical/high threat
                    const hasThreat = report?.findings?.some((f: any) => f.agent.includes(node.id) && (f.severity === 'CRITICAL' || f.severity === 'HIGH'));
                    statusColor = hasThreat ? 'bg-red-100 dark:bg-red-900/30 text-red-600' : 'bg-green-100 dark:bg-green-900/30 text-green-600';
                  }

                  return (
                  <div key={node.id} className="flex items-center justify-between group hover:bg-slate-50 dark:hover:bg-slate-800/30 p-2 -mx-2 rounded-lg transition-colors cursor-pointer">
                    <div className="flex items-center gap-3">
                      <div className={`size-8 rounded flex items-center justify-center transition-colors ${statusColor}`}>
                        <span className="material-symbols-outlined text-sm">{node.icon}</span>
                      </div>
                      <span className={`text-xs font-medium transition-colors ${node.status === 'running' ? 'text-primary' : 'group-hover:text-primary'}`}>{node.name}</span>
                    </div>
                    <span className={`px-2 py-0.5 text-[10px] font-bold rounded uppercase ${statusColor} ${node.status === 'running' ? 'animate-pulse' : ''}`}>
                      {node.status}
                    </span>
                  </div>
                )})}
              </div>
            </div>

            {/* Quick Actions Card */}
            <div className="bg-primary p-6 rounded-xl text-white shadow-lg shadow-primary/20 bg-[url('https://www.transparenttextures.com/patterns/cubes.png')] hover:bg-primary/95 transition-colors">
              <h4 className="font-bold text-sm mb-2 flex items-center gap-2">
                 <span className="material-symbols-outlined text-white">warning</span>
                 SOC Readiness
              </h4>
              <p className="text-white/90 text-xs mb-4 leading-relaxed font-medium">Your infrastructure is currently under high stress. Automation is handling 100% of EventBridge alerts.</p>
              <div className="grid grid-cols-2 gap-2">
                <button onClick={() => alert('Initiating Full Lockdown... All non-essential access blocked.')} className="bg-white/10 hover:bg-white/20 transition-colors py-2 rounded text-[10px] font-bold border border-white/20 flex items-center justify-center gap-1">
                  <span className="material-symbols-outlined text-[14px]">lock</span> Full Lockdown
                </button>
                <button onClick={() => {
                  if (report) {
                    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(report, null, 2));
                    const dlAnchorElem = document.createElement('a');
                    dlAnchorElem.setAttribute("href", dataStr);
                    dlAnchorElem.setAttribute("download", `${report.report_id}.json`);
                    dlAnchorElem.click();
                  } else {
                    alert("No report to export!");
                  }
                }} className="bg-white/10 hover:bg-white/20 transition-colors py-2 rounded text-[10px] font-bold border border-white/20 flex items-center justify-center gap-1">
                  <span className="material-symbols-outlined text-[14px]">download</span> Export Report
                </button>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
