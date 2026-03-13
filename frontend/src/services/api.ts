import type { Report, TraceEvent, GraphNodeStatus } from '../types';

export const fetchReports = async (): Promise<{reports: Report[], count: number}> => {
  try {
    const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
    
    const response = await fetch(`${API_URL}/reports`);
    if (!response.ok) throw new Error("Failed to fetch reports");
    const data = await response.json();
    return data;
  } catch (error) {
    console.error("API fetch error:", error);
    return { reports: [], count: 0 };
  }
};

export const fetchReport = async (id: string): Promise<Report | null> => {
  try {
    const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
    
    const response = await fetch(`${API_URL}/reports/${id}`);
    if (!response.ok) throw new Error("Failed to fetch report");
    const data = await response.json();
    return data.error ? null : data;
  } catch (error) {
    console.error("API fetch error:", error);
    return null;
  }
};

export const fetchLatestReport = async (): Promise<Report | null> => {
  const data = await fetchReports();
  if (data.reports && data.reports.length > 0) {
    // Return the latest one (assuming last added is at the end or sort by timestamp if available)
    return data.reports[data.reports.length - 1];
  }
  return null;
};

export const fetchTraces = async (): Promise<TraceEvent[]> => {
  const report = await fetchLatestReport();
  if (!report) return [];

  const traces: TraceEvent[] = [];
  
  // Create traces based on findings and iteration count
  if (report.findings && report.findings.length > 0) {
    report.findings.forEach((finding, idx) => {
      traces.push({
        id: `artifact-${idx}`,
        type: 'artifact',
        source: finding.agent,
        target: 'State Hub',
        description: `Produced: ${finding.mitre_tactic || finding.finding_type || 'Finding'}`,
        timestamp: new Date()
      });
    });
  }

  if (report.iocs && report.iocs.length > 0) {
    traces.push({
      id: 'enrichment-1',
      type: 'enrichment',
      source: 'Threat Intel',
      target: 'IOC Database',
      description: `Collected ${report.iocs.length} IOCs`,
      timestamp: new Date()
    });
  }

  if (report.final_report) {
    traces.push({
      id: 'synthesis',
      type: 'synthesis',
      source: 'Supervisor',
      target: 'Conclusion',
      description: 'Final Synthesis Generated',
      timestamp: new Date()
    });
  } else if (report.iteration_count > 0) {
    traces.push({
      id: `delegation-${report.iteration_count}`,
      type: 'delegation',
      source: 'Supervisor',
      target: 'Analysis Agents',
      description: `Iteration ${report.iteration_count} running...`,
      timestamp: new Date()
    });
  }

  return traces;
};

export const fetchNodes = async (): Promise<GraphNodeStatus[]> => {
  const report = await fetchLatestReport();
  
  const defaultNodes: GraphNodeStatus[] = [
    { id: 'supervisor', name: 'Supervisor', status: 'idle', type: 'supervisor', icon: 'psychology', message: 'Orchestrator' },
    { id: 'email', name: 'Email Analyst', status: 'idle', type: 'agent', icon: 'mail', message: 'Ready' },
    { id: 'forensic', name: 'Forensic Analyst', status: 'idle', type: 'agent', icon: 'biotech', message: 'Ready' },
    { id: 'threat', name: 'Threat Intel', status: 'idle', type: 'agent', icon: 'public', message: 'Ready' },
  ];

  if (!report) return defaultNodes;

  // Determine status based on findings
  const agentsUsed = new Set(report.findings?.map(f => f.agent));
  
  return defaultNodes.map(node => {
    if (node.id === 'supervisor') {
      return { ...node, status: report.final_report ? 'completed' : 'running', message: `Iterations: ${report.iteration_count || 0}` };
    }
    
    // Map agent names
    let agentKey = '';
    if (node.id === 'email') agentKey = 'email_analyst';
    if (node.id === 'forensic') agentKey = 'forensic_analyst';
    if (node.id === 'threat') agentKey = 'threat_intel';

    if (agentsUsed.has(agentKey)) {
      return { ...node, status: 'completed', message: 'Analysis complete' };
    }
    
    return node;
  });
};
