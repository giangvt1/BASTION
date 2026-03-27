import type { Report, TraceEvent, GraphNodeStatus } from '../types';

// Helper for API requests
const apiFetch = (url: string, options: RequestInit = {}) => {
  const isFormData = options.body instanceof FormData;
  const method = (options.method || 'GET').toUpperCase();
  const needsJson = !isFormData && method !== 'GET' && method !== 'HEAD';

  return fetch(url, {
    ...options,
    headers: {
      // Accept is a CORS-safe header — does NOT trigger preflight
      // AND ngrok detects it as an API client, skipping its HTML interstitial
      'Accept': 'application/json',
      ...(needsJson ? { 'Content-Type': 'application/json' } : {}),
      ...(options.headers || {}),
    },
  });
};



export const fetchReports = async (): Promise<{ reports: Report[], count: number }> => {
  try {
    const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8001';

    const response = await apiFetch(`${API_URL}/reports`);
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
    const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8001';

    const response = await apiFetch(`${API_URL}/reports/${id}`);
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

  if (report.event_type) {
    traces.push({
      id: 'ingest',
      type: 'delegation',
      source: 'EventBridge',
      target: 'Supervisor',
      description: `Ingested new ${report.event_type} event`,
      timestamp: new Date(Date.now() - 10000)
    });
  }

  if (report.messages && report.messages.length > 0) {
    report.messages.forEach((msg: any, idx: number) => {
      let source = 'Agent';
      let content = msg.content || '';

      if (content.startsWith('[')) {
        const endBracket = content.indexOf(']');
        if (endBracket !== -1) {
          source = content.substring(1, endBracket);
          content = content.substring(endBracket + 1).trim();
        }
      }

      traces.push({
        id: `msg-${idx}`,
        type: 'artifact',
        source: source,
        target: 'State Hub',
        description: content.substring(0, 150) + (content.length > 150 ? '...' : ''),
        timestamp: new Date(Date.now() - (report.messages.length - idx) * 1000)
      });
    });
  } else {
    // Fallback if no messages yet
    if (report.iteration_count > 0) {
      traces.push({
        id: `delegation-${report.iteration_count}`,
        type: 'delegation',
        source: 'Supervisor',
        target: report.next_agent || 'Analysis Agents',
        description: `Delegating task (Iteration ${report.iteration_count})...`,
        timestamp: new Date()
      });
    }
  }

  if (report.error_logs && report.error_logs.length > 0) {
    report.error_logs.forEach((err: string, idx: number) => {
      traces.push({
        id: `err-${idx}`,
        type: 'error',
        source: 'System',
        target: 'Logger',
        description: err,
        timestamp: new Date()
      });
    });
  }

  if (report.final_report) {
    traces.push({
      id: 'synthesis',
      type: 'synthesis',
      source: 'Supervisor',
      target: 'Final Output',
      description: 'Final Synthesis Generated',
      timestamp: new Date()
    });
  }

  return traces;
};

export const fetchAgentLogs = async (agentId: string | null): Promise<any[]> => {
  if (!agentId) return [];
  const report: any = await fetchLatestReport();
  if (!report || !report.pipeline_logs) return [];

  const nodeLogMap: Record<string, string[]> = {
    'supervisor': ['supervisor'],
    'email': ['email_analyst'],
    'forensic': ['forensic_analyst'],
    'threat': ['threat_intel'],
  };

  const matchNodes = nodeLogMap[agentId] || [agentId];
  return report.pipeline_logs.filter((log: any) => matchNodes.includes(log.node));
};

export const triggerAnalysis = async (eventType: string): Promise<{ message: string, report_id: string } | null> => {
  try {
    const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8001';
    const response = await apiFetch(`${API_URL}/trigger/${eventType}`, { method: 'POST' });
    if (!response.ok) throw new Error("Failed to trigger analysis");
    return await response.json();
  } catch (error) {
    console.error("API trigger error:", error);
    return null;
  }
};

export const fetchStats = async (): Promise<any> => {
  try {
    const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8001';
    const response = await apiFetch(`${API_URL}/stats`);
    if (!response.ok) throw new Error("Failed to fetch stats");
    return await response.json();
  } catch (error) {
    console.error("API stats error:", error);
    return null;
  }
};

export const uploadFile = async (file: File): Promise<{ message: string, report_id: string, event_type: string } | null> => {
  try {
    const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8001';
    const formData = new FormData();
    formData.append('file', file);
    const response = await apiFetch(`${API_URL}/upload`, { method: 'POST', body: formData });
    if (!response.ok) throw new Error("Failed to upload file");
    return await response.json();
  } catch (error) {
    console.error("API upload error:", error);
    return null;
  }
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

  const isRunning = report.status === 'running';
  const agentsUsed = new Set(report.findings?.map((f: any) => f.agent));

  // Track the most recent delegation to highlight the active agent
  let currentActiveAgent = '';
  if (isRunning && report.messages && report.messages.length > 0) {
    const lastMsg = report.messages[report.messages.length - 1];
    const content = lastMsg.content || '';
    if (content.includes('DELEGATE_EMAIL')) currentActiveAgent = 'email';
    else if (content.includes('DELEGATE_FORENSIC')) currentActiveAgent = 'forensic';
    else if (content.includes('DELEGATE_THREAT')) currentActiveAgent = 'threat';
    else if (content.includes('SYNTHESIZE')) currentActiveAgent = 'synthesis';
  }

  return defaultNodes.map(node => {
    if (node.id === 'supervisor') {
      if (report.final_report) return { ...node, status: 'completed', message: 'Synthesis complete' };
      if (isRunning && (!currentActiveAgent || currentActiveAgent === 'synthesis')) {
        return { ...node, status: 'running', message: `Thinking...` };
      }
      return { ...node, status: isRunning ? 'idle' : 'completed', message: `Iterations: ${report.iteration_count || 0}` };
    }

    let agentKey = '';
    if (node.id === 'email') { agentKey = 'email_analyst'; }
    if (node.id === 'forensic') { agentKey = 'forensic_analyst'; }
    if (node.id === 'threat') { agentKey = 'threat_intel'; }

    if (isRunning && currentActiveAgent === node.id) {
      return { ...node, status: 'running', message: 'Analyzing...' };
    }

    if (agentsUsed.has(agentKey) || (node.id === 'threat' && report.findings?.some((f: any) => f.agent === 'threat_intel'))) {
      return { ...node, status: 'completed', message: 'Analysis complete' };
    }

    return node;
  });
};

export const submitFeedback = async (reportId: string, feedbackType: string, notes: string = '') => {
  try {
    const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8001';
    const response = await apiFetch(`${API_URL}/reports/${reportId}/feedback`, {
      method: 'POST',
      body: JSON.stringify({ feedback_type: feedbackType, notes })
    });
    return response.ok;
  } catch (error) {
    console.error("Feedback error:", error);
    return false;
  }
};

export const pushSigmaRule = async (reportId: string) => {
  try {
    const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8001';
    const response = await apiFetch(`${API_URL}/reports/${reportId}/push-sigma`, {
      method: 'POST'
    });
    const data = await response.json();
    return data;
  } catch (error) {
    console.error("Push sigma error:", error);
    return null;
  }
};
