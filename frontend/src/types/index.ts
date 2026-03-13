export interface Finding {
  agent: string;
  finding_type?: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  mitre_tactic?: string;
  description: string;
  evidence?: Record<string, any>;
}

export interface IOC {
  ioc_type: string;
  value: string;
  source_agent: string;
}

export interface Report {
  report_id: string;
  event_type: string;
  risk_score: number;
  final_report: string;
  findings: Finding[];
  iocs: IOC[];
  iteration_count: number;
  error_logs: string[];
  timestamp?: string;
}

export interface GraphNodeStatus {
  id: string;
  name: string;
  status: 'idle' | 'running' | 'completed' | 'error';
  type: 'supervisor' | 'agent' | 'hub';
  icon: string;
  message?: string;
}

export interface TraceEvent {
  id: string;
  type: 'delegation' | 'artifact' | 'enrichment' | 'synthesis' | 'error';
  source: string;
  target: string;
  description: string;
  timestamp: Date;
}
