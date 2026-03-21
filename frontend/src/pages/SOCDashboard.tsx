import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Header } from '../components/Header';
import { fetchLatestReport, fetchNodes, fetchTraces, triggerAnalysis } from '../services/api';
import type { Report, GraphNodeStatus, TraceEvent } from '../types';

export default function SOCDashboard() {
  const [report, setReport] = useState<Report | null>(null);
  const [nodes, setNodes] = useState<GraphNodeStatus[]>([]);
  const [traces, setTraces] = useState<TraceEvent[]>([]);
  const [auditTrail, setAuditTrail] = useState<{ time: string, action: string, user: string }[]>([]);
  const [showExplain, setShowExplain] = useState(false);
  const [showIntel, setShowIntel] = useState(false);
  const [selectedIP, setSelectedIP] = useState<string | null>(null);
  const [showFPFeedback, setShowFPFeedback] = useState(false);
  const [incidentStatus, setIncidentStatus] = useState<string | null>(null);

  const handleHiTLAction = (action: string) => {
    if (action === 'Marked False Positive') {
      setShowFPFeedback(true);
    }
    if (action === 'Escalated to Tier 3') {
      setIncidentStatus('HUMAN_INVESTIGATION');
    }
    setAuditTrail(prev => [{
      time: new Date().toLocaleTimeString(),
      action,
      user: "SOC_Analyst_01"
    }, ...prev]);
  };

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

  return (
    <div className="bg-background-light dark:bg-background-dark text-slate-900 dark:text-slate-100 min-h-screen font-display">
      <Header />

      <main className="max-w-[1440px] mx-auto p-6 space-y-6">
        {/* Key Metrics */}
        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-4">
          <div className="bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-200 dark:border-slate-800 flex flex-col gap-2 hover:-translate-y-1 transition-transform cursor-default shadow-sm">
            <div className="flex justify-between items-start">
              <span className="text-slate-500 dark:text-slate-400 text-xs font-bold uppercase tracking-wider">AI Confidence Score</span>
              <span className="material-symbols-outlined text-primary">psychology_alt</span>
            </div>
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-bold">{riskScore}</span>
              <span className="text-slate-400 text-sm font-medium">%</span>
            </div>
            <div className="w-full bg-slate-100 dark:bg-slate-800 h-1.5 rounded-full mt-2 overflow-hidden">
              <div
                className={`h-full transition-all duration-500 ${Number(riskScore) > 80 ? 'bg-gradient-to-r from-red-500 to-red-600' : Number(riskScore) > 50 ? 'bg-gradient-to-r from-orange-400 to-orange-500' : 'bg-gradient-to-r from-emerald-400 to-emerald-500'}`}
                style={{ width: `${riskScore}%` }}></div>
            </div>
            <p className="text-emerald-500 text-xs font-medium mt-1">Based on multi-agent consensus</p>
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
              <span className="text-slate-500 dark:text-slate-400 text-xs font-bold uppercase tracking-wider">Impact Analysis</span>
              <span className="material-symbols-outlined text-rose-500">groups</span>
            </div>
            <span className="text-3xl font-bold">{report?.iocs?.length ? Math.max(1, Math.floor(report.iocs.length / 2)) : 0}</span>
            <p className="text-slate-400 text-xs mt-1">Users/Systems Affected</p>
            <p className="text-rose-500 text-xs font-medium mt-auto">Requires Immediate Review</p>
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
                    <h3 className="font-bold text-sm flex items-center gap-2">
                      {report?.report_id ? `Incident: ${report.report_id}` : 'Waiting for incoming events...'}
                      {incidentStatus === 'HUMAN_INVESTIGATION' && (
                        <span className="bg-rose-600 text-[10px] text-white px-2 py-0.5 rounded-full animate-pulse border border-rose-400 shadow-sm shadow-rose-900/40">
                          HUMAN INVESTIGATION IN PROGRESS
                        </span>
                      )}
                    </h3>
                    <p className="text-xs text-slate-500">
                      {report?.event_type ? `Type: ${report.event_type.toUpperCase()}` : 'No active incident'}
                    </p>
                  </div>
                </div>
                <div className="flex gap-2 w-full sm:w-auto">
                  <button
                    onClick={async () => {
                      const res = await triggerAnalysis('email');
                      if (res) alert(`Analysis triggered: ${res.report_id}`);
                    }}
                    className="flex-1 sm:flex-none bg-emerald-600 text-white text-xs font-bold py-2 px-4 rounded-lg hover:bg-emerald-700 transition-colors shadow-sm flex items-center gap-2"
                  >
                    <span className="material-symbols-outlined text-sm">mail</span> Investigate Email
                  </button>
                  <button
                    onClick={async () => {
                      const res = await triggerAnalysis('cloudtrail');
                      if (res) alert(`Analysis triggered: ${res.report_id}`);
                    }}
                    className="flex-1 sm:flex-none bg-primary text-white text-xs font-bold py-2 px-4 rounded-lg hover:bg-primary/90 transition-colors shadow-sm flex items-center gap-2"
                  >
                    <span className="material-symbols-outlined text-sm">search_insights</span> Investigate CloudTrail
                  </button>
                  <Link to="/orchestrator" className="flex-1 sm:flex-none text-center bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-200 text-xs font-bold py-2 px-4 rounded-lg hover:bg-slate-300 dark:hover:bg-slate-700 transition-colors flex items-center justify-center gap-2">
                    <span className="material-symbols-outlined text-sm">account_tree</span> View Trace
                  </Link>
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
                    <div className="flex flex-col gap-4 mt-6">
                      <div className="flex gap-4 relative group">
                        <div className="size-6 rounded-full bg-slate-100 dark:bg-slate-800 border-2 border-white dark:border-slate-900 flex items-center justify-center z-10 group-hover:scale-110 transition-transform">
                          <div className="size-1.5 rounded-full bg-green-500"></div>
                        </div>
                        <div className="flex-1 bg-primary/10 border border-primary/20 p-4 rounded-lg ring-1 ring-primary/30 shadow-sm shadow-primary/10">
                          <div className="flex justify-between items-center mb-3">
                            <span className="text-sm font-bold text-primary flex items-center gap-2">
                              <span className="material-symbols-outlined text-base">verified_user</span>
                              Response Orchestrator
                            </span>
                            <span className="text-[10px] text-primary/80 font-bold bg-primary/20 px-2 py-1 rounded tracking-wider uppercase">Final Verdict</span>
                          </div>
                          <p className="text-sm font-medium leading-relaxed text-slate-800 dark:text-slate-200">{report.final_report}</p>

                          {/* HiTL Actions & Explain */}
                          <div className="mt-4 pt-4 border-t border-primary/20 flex flex-wrap gap-2">
                            <button onClick={() => setShowExplain(!showExplain)} className="bg-slate-800 text-white text-xs font-bold py-1.5 px-3 rounded flex items-center gap-1 hover:bg-slate-700 transition-colors">
                              <span className="material-symbols-outlined text-[14px]">psychology</span> Explain Verdict
                            </button>
                            <button onClick={() => handleHiTLAction('Approved Mitigation')} className="bg-emerald-600 text-white text-xs font-bold py-1.5 px-3 rounded flex items-center gap-1 hover:bg-emerald-700 transition-colors">
                              <span className="material-symbols-outlined text-[14px]">check_circle</span> Approve
                            </button>
                            <button onClick={() => handleHiTLAction('Marked False Positive')} className="bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-bold py-1.5 px-3 rounded flex items-center gap-1 hover:bg-slate-300 dark:hover:bg-slate-600 transition-colors">
                              <span className="material-symbols-outlined text-[14px]">cancel</span> False Positive
                            </button>
                            <button onClick={() => handleHiTLAction('Escalated to Tier 3')} className="bg-rose-600 text-white text-xs font-bold py-1.5 px-3 rounded flex items-center gap-1 hover:bg-rose-700 transition-colors ml-auto">
                              <span className="material-symbols-outlined text-[14px]">priority_high</span> Escalate
                            </button>
                          </div>
                        </div>
                      </div>

                      {/* Explainability Semantic Highlighting View */}
                      {showExplain && (
                        <div className="ml-10 bg-slate-900 text-slate-300 p-4 rounded-lg font-mono text-xs border border-slate-700 animate-fade-in shadow-inner">
                          <div className="flex items-center gap-2 mb-3 text-emerald-400 border-b border-slate-800 pb-2 font-bold uppercase tracking-wider text-[10px]">
                            <span className="material-symbols-outlined text-sm">code_blocks</span> Semantic Highlighting (Raw Input)
                          </div>
                          <p className="leading-relaxed">
                            {report?.event_payload?.body ? (
                              <>
                                <span className="text-slate-500">From:</span> {report.event_payload.sender || 'unknown@domain.com'}<br />
                                <span className="text-slate-500">Subject:</span> {report.event_payload.subject || 'No Subject'}<br /><br />
                                {report.event_payload.body.split(' ').map((word: string, i: number) => {
                                  const isIP = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(word);
                                  const isUrgent = /urgent|suspended|24 hours|verify/i.test(word);
                                  if (isIP) return <span key={i} onClick={() => { setSelectedIP(word); setShowIntel(true); }} className="bg-red-900/50 text-red-400 px-1 rounded font-bold cursor-pointer hover:bg-emerald-500 hover:text-white transition-all mx-0.5">{word} </span>;
                                  if (isUrgent) return <span key={i} className="bg-yellow-900/50 text-yellow-500 px-1 rounded font-bold mx-0.5">{word} </span>;
                                  return word + ' ';
                                })}
                              </>
                            ) : (
                              <>
                                <span className="text-slate-500">From:</span> attacker@<span className="bg-red-900/50 text-red-400 px-1 rounded font-bold" title="Malicious Infrastructure">suspicious-domain.com</span><br />
                                <span className="text-slate-500">Subject:</span> <span className="bg-yellow-900/50 text-yellow-500 px-1 rounded font-bold" title="Urgency Tone Detected">URGENT:</span> Account Suspension Notice<br />
                                <br />
                                Dear User,<br />
                                Your account will be suspended in <span className="bg-yellow-900/50 text-yellow-500 px-1 rounded font-bold">24 hours</span>.
                                Please verify your identity here: <span className="bg-red-900/50 text-red-400 px-1 rounded underline font-bold" title="Phishing Link">http://<span
                                  onClick={() => { setSelectedIP('185.123.45.67'); setShowIntel(true); }}
                                  className="cursor-pointer hover:bg-emerald-500 hover:text-white transition-all px-0.5 rounded"
                                >185.123.45.67</span>/login</span>
                              </>
                            )}
                          </p>
                          <div className="mt-4 pt-3 border-t border-slate-800 flex gap-4 text-[10px] uppercase font-bold tracking-wider">
                            <span className="flex items-center gap-1 text-red-400 transition-transform hover:scale-105 cursor-help" title="Click technical artifacts above for deep intel"><span className="size-2 rounded-full bg-red-500 mix-blend-screen"></span> High Risk Indicator</span>
                            <span className="flex items-center gap-1 text-yellow-500"><span className="size-2 rounded-full bg-yellow-500 mix-blend-screen"></span> Social Engineering Tone</span>
                          </div>
                        </div>
                      )}

                      {/* Audit Trail */}
                      {auditTrail.length > 0 && (
                        <div className="ml-10 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden animate-fade-in shadow-sm">
                          <div className="bg-slate-50 dark:bg-slate-800/50 p-2.5 text-xs font-bold text-slate-600 dark:text-slate-400 border-b border-slate-200 dark:border-slate-800 flex items-center gap-2 uppercase tracking-wider">
                            <span className="material-symbols-outlined text-[14px]">history</span> Human-in-the-Loop Audit Trail
                          </div>
                          <table className="w-full text-left text-xs">
                            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                              {auditTrail.map((log, idx) => (
                                <tr key={idx} className="hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors">
                                  <td className="p-2.5 text-slate-400 w-24 border-r border-slate-100 dark:border-slate-800">{log.time}</td>
                                  <td className="p-2.5 font-mono text-primary w-32 border-r border-slate-100 dark:border-slate-800">{log.user}</td>
                                  <td className="p-2.5 font-medium text-slate-700 dark:text-slate-200 flex items-center gap-2">
                                    <span className="material-symbols-outlined text-[14px] text-primary">done</span>
                                    {log.action}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}
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
                  )
                })}
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

      {/* Threat Intel Side-drawer */}
      {showIntel && (
        <div className="fixed inset-0 z-[100] flex justify-end">
          <div className="absolute inset-0 bg-black/40 backdrop-blur-sm" onClick={() => setShowIntel(false)}></div>
          <div className="relative w-96 bg-white dark:bg-slate-900 h-full shadow-2xl border-l border-slate-200 dark:border-slate-800 flex flex-col animate-slide-in-right">
            <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex justify-between items-center bg-primary text-white">
              <h4 className="font-bold text-sm uppercase tracking-widest flex items-center gap-2">
                <span className="material-symbols-outlined text-lg">public-off</span> Deep Threat Intel
              </h4>
              <button onClick={() => setShowIntel(false)} className="hover:bg-white/20 p-1 rounded-md transition-colors">
                <span className="material-symbols-outlined text-md">close</span>
              </button>
            </div>
            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              <div className="flex flex-col items-center gap-2 pb-6 border-b border-slate-100 dark:border-slate-800">
                <span className="text-4xl font-black text-slate-800 dark:text-white tracking-tight">{selectedIP}</span>
                <span className="px-3 py-1 bg-rose-100 dark:bg-rose-900/30 text-rose-600 dark:text-rose-400 rounded-full text-[10px] font-bold uppercase tracking-widest border border-rose-200 dark:border-rose-800">High Risk Asset</span>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="bg-slate-50 dark:bg-slate-800/40 p-4 rounded-xl border border-slate-100 dark:border-slate-800">
                  <p className="text-[10px] text-slate-500 uppercase font-bold mb-1">Reputation Score</p>
                  <p className="text-2xl font-black text-rose-500">92/100</p>
                </div>
                <div className="bg-slate-50 dark:bg-slate-800/40 p-4 rounded-xl border border-slate-100 dark:border-slate-800">
                  <p className="text-[10px] text-slate-500 uppercase font-bold mb-1">Tor Exit Node</p>
                  <p className="text-2xl font-black text-emerald-500 tracking-tighter">YES</p>
                </div>
              </div>

              <div className="space-y-4">
                <h5 className="text-[10px] text-slate-500 uppercase font-bold tracking-widest flex items-center gap-2">
                  <span className="size-1.5 rounded-full bg-primary"></span>
                  Actor Attribution
                </h5>
                <div className="p-4 bg-slate-900 rounded-xl border border-slate-800">
                  <p className="text-emerald-400 font-bold text-sm mb-1">COZY BEAR (APT29)</p>
                  <p className="text-slate-400 text-xs leading-relaxed">Infrastructure historically associated with Russian-backed cyber espionage campaigns targeting financial institutions.</p>
                </div>
              </div>

              <div className="space-y-4">
                <h5 className="text-[10px] text-slate-500 uppercase font-bold tracking-widest flex items-center gap-2">
                  <span className="size-1.5 rounded-full bg-primary"></span>
                  Geo-Location
                </h5>
                <div className="h-32 bg-slate-100 dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 overflow-hidden relative group">
                  <img src="https://api.mapbox.com/styles/v1/mapbox/dark-v10/static/45,45,2/400x200?access_token=pk.eyJ1IjoiZGVtbyIsImEiOiJjbTF6bmN6emUwMnkzMmpxeHpxZ3pxZ3pxIn0" alt="Map" className="w-full h-full object-cover grayscale brightness-75 group-hover:grayscale-0 transition-all" />
                  <div className="absolute inset-0 flex items-center justify-center">
                    <span className="material-symbols-outlined text-primary text-4xl animate-bounce">location_on</span>
                  </div>
                </div>
                <p className="text-[10px] text-slate-500 text-center font-mono">Russia, Moscow - 55.7558° N, 37.6173° E</p>
              </div>
            </div>
            <div className="p-4 bg-slate-50 dark:bg-slate-800/50 border-t border-slate-200 dark:border-slate-800">
              <button onClick={() => handleHiTLAction(`Blocked IP ${selectedIP}`)} className="w-full bg-rose-600 text-white font-bold py-3 rounded-xl hover:bg-rose-700 transition-colors flex items-center justify-center gap-2 shadow-lg shadow-rose-900/20 text-sm">
                <span className="material-symbols-outlined">block</span> Blacklist IP Immediately
              </button>
            </div>
          </div>
        </div>
      )}

      {/* FP Feedback Modal */}
      {showFPFeedback && (
        <div className="fixed inset-0 z-[110] flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/60 backdrop-blur-md" onClick={() => setShowFPFeedback(false)}></div>
          <div className="relative max-w-md w-full bg-white dark:bg-slate-900 rounded-3xl shadow-2xl overflow-hidden animate-zoom-in border border-slate-200 dark:border-slate-800">
            <div className="p-8 text-center space-y-4">
              <div className="size-16 bg-orange-100 dark:bg-orange-900/30 text-orange-600 rounded-full flex items-center justify-center mx-auto mb-4">
                <span className="material-symbols-outlined text-3xl">psychology_alt</span>
              </div>
              <h3 className="text-xl font-black tracking-tight">RLHF Feedback Loop</h3>
              <p className="text-slate-500 dark:text-slate-400 text-sm">Help the BASTION brain learn. Why is this incident a False Positive?</p>

              <div className="grid grid-cols-1 gap-2 py-4">
                {['Legitimate User Behavior', 'Incorrect Pattern Match', 'Test Incident / Drills', 'Outdated Global Feed'].map((reason) => (
                  <button
                    key={reason}
                    onClick={() => {
                      handleHiTLAction(`FP Reason: ${reason}`);
                      setShowFPFeedback(false);
                    }}
                    className="text-left p-4 rounded-2xl border border-slate-100 dark:border-slate-800 hover:border-primary hover:bg-primary/5 transition-all group flex items-center justify-between"
                  >
                    <span className="text-sm font-bold text-slate-700 dark:text-slate-300 group-hover:text-primary transition-colors">{reason}</span>
                    <span className="material-symbols-outlined text-transparent group-hover:text-primary transition-all">chevron_right</span>
                  </button>
                ))}
              </div>

              <button onClick={() => setShowFPFeedback(false)} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 text-xs font-bold transition-colors">
                Skip feedback loop
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
