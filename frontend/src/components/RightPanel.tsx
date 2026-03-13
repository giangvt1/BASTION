import { useEffect, useState } from 'react';
import type { TraceEvent } from '../types';
import { fetchTraces } from '../services/api';

export const RightPanel = () => {
  const [traces, setTraces] = useState<TraceEvent[]>([]);

  useEffect(() => {
    fetchTraces().then(setTraces);
    const interval = setInterval(() => {
      fetchTraces().then(setTraces);
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  const getIconForType = (type: string) => {
    switch (type) {
      case 'delegation': return 'play_arrow';
      case 'artifact': return 'edit_document';
      case 'enrichment': return 'verified';
      case 'synthesis': return 'auto_fix_high';
      case 'error': return 'error';
      default: return 'circle';
    }
  };

  return (
    <aside className="w-full lg:w-80 border-l border-slate-200 dark:border-primary/10 p-6 flex flex-col gap-6 overflow-y-auto bg-white/50 dark:bg-transparent">
      <div>
        <h4 className="text-sm font-bold uppercase tracking-wider text-slate-400 mb-4">Sequence Flow</h4>
        <div className="space-y-6 relative before:absolute before:left-[11px] before:top-2 before:bottom-2 before:w-[2px] before:bg-slate-200 dark:before:bg-primary/20">
          
          {traces.map((trace, idx) => (
            <div key={trace.id} className="flex gap-4 relative">
              <div className={`size-6 rounded-full flex items-center justify-center z-10 ${
                idx === 0 
                  ? 'bg-primary text-white' 
                  : 'bg-slate-200 dark:bg-primary/20 text-primary'
              }`}>
                <span className="material-symbols-outlined text-[14px]">
                  {getIconForType(trace.type)}
                </span>
              </div>
              <div>
                <p className="text-sm font-bold text-slate-800 dark:text-slate-200">{trace.description}</p>
                <p className="text-xs text-slate-500">{trace.source} → {trace.target}</p>
              </div>
            </div>
          ))}

        </div>
      </div>
      
      <div className="border-t border-slate-200 dark:border-primary/10 pt-6">
        <h4 className="text-sm font-bold uppercase tracking-wider text-slate-400 mb-4">Node Metrics</h4>
        <div className="grid grid-cols-2 gap-3">
          <div className="p-3 rounded-xl bg-slate-100 dark:bg-primary/5 border border-slate-200 dark:border-primary/10">
            <p className="text-[10px] text-slate-500">Latency</p>
            <p className="text-lg font-bold text-slate-800 dark:text-slate-200">42ms</p>
          </div>
          <div className="p-3 rounded-xl bg-slate-100 dark:bg-primary/5 border border-slate-200 dark:border-primary/10">
            <p className="text-[10px] text-slate-500">Cost</p>
            <p className="text-lg font-bold text-slate-800 dark:text-slate-200">$0.02</p>
          </div>
        </div>
      </div>
    </aside>
  );
};
