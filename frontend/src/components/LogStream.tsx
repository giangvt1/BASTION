/**
 * LogStream.tsx
 *
 * Real-time streaming log viewer for BASTION pipeline_logs.
 * Replaces the static "Sequence Flow" and "Findings" sections.
 * Supports "View Details" popup modal for full log inspection.
 */
import { useState } from 'react';

// ── Types ─────────────────────────────────────────────────────────────────────
export interface PipelineLog {
  node: string;
  action: string;
  detail: string;
  status: 'running' | 'ok' | 'warn' | 'error';
  ts: string;
}

interface LogStreamProps {
  logs: PipelineLog[];
  /** If true, show a compact card with a "View Details" button instead of full list */
  compact?: boolean;
  title?: string;
  maxVisible?: number;
}

// ── Helpers ───────────────────────────────────────────────────────────────────
const STATUS_CONFIG = {
  running: {
    dot: 'bg-blue-400 animate-pulse',
    bar: 'border-l-blue-400',
    badge: 'bg-blue-900/40 text-blue-300',
    // dot-only: rendered as pulsing circle, not an icon
    icon: null,
    iconClass: '',
  },
  ok: {
    dot: 'bg-emerald-400',
    bar: 'border-l-emerald-500',
    badge: 'bg-emerald-900/40 text-emerald-300',
    icon: 'check_circle',
    iconClass: 'text-emerald-400',
  },
  warn: {
    dot: 'bg-amber-400',
    bar: 'border-l-amber-400',
    badge: 'bg-amber-900/40 text-amber-300',
    icon: 'warning',
    iconClass: 'text-amber-400',
  },
  error: {
    dot: 'bg-red-500',
    bar: 'border-l-red-500',
    badge: 'bg-red-900/40 text-red-300',
    icon: 'error',
    iconClass: 'text-red-400',
  },
};

const NODE_COLORS: Record<string, string> = {
  email_analyst:   'text-violet-400',
  forensic_analyst:'text-cyan-400',
  threat_intel:    'text-rose-400',
  supervisor:      'text-amber-400',
  synthesis:       'text-emerald-400',
};

function fmtTime(ts: string) {
  try { return new Date(ts).toLocaleTimeString(); } catch { return ts; }
}

// ── Log Modal ─────────────────────────────────────────────────────────────────
function LogModal({ logs, onClose }: { logs: PipelineLog[]; onClose: () => void }) {
  const [filter, setFilter] = useState<string>('all');
  const nodes = ['all', ...Array.from(new Set(logs.map(l => l.node)))];

  const visible = filter === 'all' ? logs : logs.filter(l => l.node === filter);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 animate-fade-in"
      onClick={onClose}
    >
      <div
        className="bg-slate-950 border border-slate-700 rounded-2xl shadow-2xl w-full max-w-3xl max-h-[85vh] flex flex-col overflow-hidden"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-slate-800 bg-slate-900/60">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-emerald-400 text-lg">terminal</span>
            <h2 className="text-sm font-bold text-slate-100 uppercase tracking-widest">
              Pipeline Log Stream
            </h2>
            <span className="text-[10px] text-slate-500">({logs.length} entries)</span>
          </div>
          <button
            onClick={onClose}
            className="size-7 rounded-lg flex items-center justify-center text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <span className="material-symbols-outlined text-sm">close</span>
          </button>
        </div>

        {/* Agent filter tabs */}
        <div className="flex gap-1.5 px-4 py-2.5 border-b border-slate-800 bg-slate-900/40 overflow-x-auto">
          {nodes.map(n => (
            <button
              key={n}
              onClick={() => setFilter(n)}
              className={`px-2.5 py-1 rounded-md text-[10px] font-bold uppercase tracking-wider whitespace-nowrap transition-colors
                ${filter === n
                  ? 'bg-slate-700 text-white'
                  : 'text-slate-500 hover:text-slate-300 hover:bg-slate-800'}`}
            >
              {n === 'all' ? '⬛ All' : n.replace('_', ' ')}
            </button>
          ))}
        </div>

        {/* Log list */}
        <div className="flex-1 overflow-y-auto p-3 space-y-1.5 font-mono">
          {visible.map((log, i) => {
            const cfg = STATUS_CONFIG[log.status] || STATUS_CONFIG.ok;
            const nodeColor = NODE_COLORS[log.node] || 'text-slate-400';
            return (
              <div
                key={i}
                className={`flex gap-3 p-2.5 rounded-lg border-l-2 ${cfg.bar} bg-slate-900/60 hover:bg-slate-800/60 transition-colors group`}
              >
                {/* Status icon */}
                {cfg.icon
                  ? <span className={`material-symbols-outlined text-[14px] mt-0.5 flex-shrink-0 ${cfg.iconClass}`}>{cfg.icon}</span>
                  : <span className={`size-2 rounded-full mt-1 flex-shrink-0 ${cfg.dot}`} />}

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-2 mb-0.5">
                    <div className="flex items-center gap-1.5 min-w-0">
                      <span className={`text-[9px] font-bold uppercase ${nodeColor} flex-shrink-0`}>
                        [{log.node}]
                      </span>
                      <span className="text-[11px] font-bold text-slate-200 truncate">{log.action}</span>
                    </div>
                    <span className="text-[9px] text-slate-600 flex-shrink-0">{fmtTime(log.ts)}</span>
                  </div>
                  <p className="text-[10px] text-slate-400 leading-relaxed">{log.detail}</p>
                </div>
              </div>
            );
          })}

          {visible.length === 0 && (
            <p className="text-center text-slate-600 text-sm py-8">No logs for this agent.</p>
          )}
        </div>

        {/* Footer */}
        <div className="p-3 border-t border-slate-800 bg-slate-900/40 flex items-center justify-between">
          <div className="flex items-center gap-3 text-[10px]">
            {(['ok','warn','error','running'] as const).map(s => (
              <span key={s} className="flex items-center gap-1 text-slate-500">
                <span className={`size-1.5 rounded-full ${STATUS_CONFIG[s].dot}`}></span>
                {s}
              </span>
            ))}
          </div>
          <button
            onClick={onClose}
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-bold rounded-lg transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Main LogStream Component ──────────────────────────────────────────────────
export function LogStream({ logs, compact = false, title = 'Pipeline Log Stream', maxVisible = 6 }: LogStreamProps) {
  const [showModal, setShowModal] = useState(false);

  if (!logs || logs.length === 0) {
    return (
      <div className="bg-slate-900 rounded-xl border border-slate-800 p-4 text-center text-slate-600 text-sm">
        <span className="material-symbols-outlined text-2xl mb-1 block text-slate-700">terminal</span>
        No pipeline logs yet. Trigger an investigation to start.
      </div>
    );
  }

  // Compact card mode — for Dashboard sidebar
  if (compact) {
    const lastLog = logs[logs.length - 1];
    const errorCount = logs.filter(l => l.status === 'error').length;
    const warnCount  = logs.filter(l => l.status === 'warn').length;
    const okCount    = logs.filter(l => l.status === 'ok').length;

    return (
      <>
        {showModal && <LogModal logs={logs} onClose={() => setShowModal(false)} />}
        <div
          className="bg-slate-900 rounded-xl border border-slate-800 overflow-hidden hover:border-slate-700 transition-colors"
          onClick={() => setShowModal(true)}
        >
          <div className="p-3 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-emerald-400 text-sm">terminal</span>
              <span className="text-[11px] font-bold text-slate-300 uppercase tracking-widest">{title}</span>
              <span className="text-[10px] text-slate-600">({logs.length})</span>
            </div>
            <button
              className="px-2 py-0.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] font-bold rounded transition-colors flex items-center gap-1"
              onClick={e => { e.stopPropagation(); setShowModal(true); }}
            >
              <span className="material-symbols-outlined text-[11px]">open_in_full</span>
              View Details
            </button>
          </div>

          {/* Stats row */}
          <div className="flex divide-x divide-slate-800">
            {[
              { label: 'OK', count: okCount, color: 'text-emerald-400' },
              { label: 'WARN', count: warnCount, color: 'text-amber-400' },
              { label: 'ERROR', count: errorCount, color: 'text-red-400' },
            ].map(s => (
              <div key={s.label} className="flex-1 p-2 text-center">
                <p className={`text-base font-bold ${s.color}`}>{s.count}</p>
                <p className="text-[9px] text-slate-600 uppercase tracking-wider">{s.label}</p>
              </div>
            ))}
          </div>

          {/* Latest log line */}
          {lastLog && (
            <div className={`px-3 py-2 border-t border-slate-800 border-l-2 ${STATUS_CONFIG[lastLog.status]?.bar || 'border-l-slate-700'} bg-slate-900/40`}>
              <p className="text-[10px] font-bold text-slate-300 truncate">{lastLog.action}</p>
              <p className="text-[9px] text-slate-500 truncate mt-0.5">{lastLog.detail?.substring(0, 80)}</p>
            </div>
          )}
        </div>
      </>
    );
  }

  // Full inline mode — for Orchestrator page
  const visible = logs.slice(-maxVisible);
  const hasMore = logs.length > maxVisible;

  return (
    <>
      {showModal && <LogModal logs={logs} onClose={() => setShowModal(false)} />}

      <div className="bg-slate-900 rounded-xl border border-slate-800 overflow-hidden">
        {/* Header */}
        <div className="p-3 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-emerald-400 text-sm">terminal</span>
            <span className="text-[11px] font-bold text-slate-300 uppercase tracking-widest">{title}</span>
            <span className="text-[10px] text-slate-600">({logs.length} entries)</span>
          </div>
          <button
            onClick={() => setShowModal(true)}
            className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] font-bold rounded-lg transition-colors flex items-center gap-1"
          >
            <span className="material-symbols-outlined text-[11px]">open_in_full</span>
            View All Logs
          </button>
        </div>

        {/* Log entries */}
        <div className="p-2 space-y-1 max-h-64 overflow-y-auto font-mono">
          {visible.map((log, i) => {
            const cfg = STATUS_CONFIG[log.status] || STATUS_CONFIG.ok;
            const nodeColor = NODE_COLORS[log.node] || 'text-slate-400';
            return (
              <div
                key={i}
                className={`flex gap-2.5 p-2 rounded-lg border-l-2 ${cfg.bar} bg-slate-800/50 hover:bg-slate-800 transition-colors`}
              >
                {cfg.icon
                  ? <span className={`material-symbols-outlined text-[12px] mt-0.5 flex-shrink-0 ${cfg.iconClass}`}>{cfg.icon}</span>
                  : <span className={`size-2 rounded-full mt-1 flex-shrink-0 ${cfg.dot}`} />}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-1.5 mb-0.5">
                    <span className={`text-[8px] font-bold uppercase ${nodeColor} flex-shrink-0`}>
                      [{log.node}]
                    </span>
                    <span className="text-[10px] font-bold text-slate-200 truncate">{log.action}</span>
                    <span className="text-[9px] text-slate-600 ml-auto flex-shrink-0">{fmtTime(log.ts)}</span>
                  </div>
                  <p className="text-[9px] text-slate-400 leading-relaxed truncate">{log.detail}</p>
                </div>
              </div>
            );
          })}
        </div>

        {/* Show more */}
        {hasMore && (
          <button
            onClick={() => setShowModal(true)}
            className="w-full py-2 text-[10px] text-slate-500 hover:text-slate-300 hover:bg-slate-800/50 transition-colors border-t border-slate-800 font-bold uppercase tracking-wider"
          >
            +{logs.length - maxVisible} more entries — View Full Log
          </button>
        )}
      </div>
    </>
  );
}

export default LogStream;
