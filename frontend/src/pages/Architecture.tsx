import { Header } from '../components/Header';
import { Link } from 'react-router-dom';

export default function Architecture() {
  return (
    <div className="bg-[#1a120e] dark text-slate-100 font-display min-h-screen">
      <div className="relative flex min-h-screen w-full flex-col overflow-x-hidden">
        <div className="layout-container flex h-full grow flex-col">
          <Header />

          <main className="flex-1 flex flex-col p-6 lg:p-12 max-w-[1400px] mx-auto w-full">
            {/* Title Section */}
            <div className="mb-12 animate-fade-in">
              <h1 className="text-4xl lg:text-5xl font-black tracking-tight text-slate-100 mb-4">
                BASTION: <span className="text-primary">Banking Agentic Security</span>
              </h1>
              <p className="text-slate-400 text-lg max-w-3xl leading-relaxed">
                Threat Intelligence & Orchestration Network. A high-fidelity real-time pipeline for autonomous security response and forensic analysis.
              </p>
            </div>

            {/* Architecture Diagram Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 items-stretch">

              {/* 1. Input Layer */}
              <div className="flex flex-col gap-4 p-6 rounded-xl bg-[#2a1d17] border border-[#3d2b22] relative group hover:border-primary/50 hover:shadow-lg hover:shadow-primary/5 transition-all duration-300">
                <div className="flex items-center gap-2 mb-4">
                  <span className="material-symbols-outlined text-primary text-2xl">cloud_download</span>
                  <h3 className="font-bold text-lg text-white">1. Input Layer</h3>
                </div>
                <div className="flex flex-col gap-3">
                  <div className="flex items-center gap-4 p-4 rounded-lg bg-[#1a120e] border border-[#3d2b22] group-hover:border-primary/30 transition-colors">
                    <span className="material-symbols-outlined text-slate-400">monitoring</span>
                    <div>
                      <p className="text-sm font-bold text-slate-200">AWS CloudTrail</p>
                      <p className="text-xs text-slate-500">Global API Logs</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-4 p-4 rounded-lg bg-[#1a120e] border border-[#3d2b22] group-hover:border-primary/30 transition-colors">
                    <span className="material-symbols-outlined text-slate-400">database</span>
                    <div>
                      <p className="text-sm font-bold text-slate-200">Amazon S3</p>
                      <p className="text-xs text-slate-500">Security Lake / VPC Flow</p>
                    </div>
                  </div>
                </div>
                {/* Connector Arrow */}
                <div className="hidden lg:flex absolute -right-6 top-1/2 -translate-y-1/2 z-10 text-primary w-6 items-center justify-center">
                  <span className="material-symbols-outlined text-3xl group-hover:translate-x-1 transition-transform">arrow_forward</span>
                </div>
              </div>

              {/* 2. Trigger & Pre-Processing */}
              <div className="flex flex-col gap-4 p-6 rounded-xl bg-[#2a1d17] border border-[#3d2b22] relative group hover:border-primary/50 hover:shadow-lg hover:shadow-primary/5 transition-all duration-300">
                <div className="flex items-center gap-2 mb-4">
                  <span className="material-symbols-outlined text-primary text-2xl">bolt</span>
                  <h3 className="font-bold text-lg text-white">2. Trigger Tier</h3>
                </div>
                <div className="flex flex-col gap-3">
                  <div className="flex items-center gap-4 p-4 rounded-lg bg-[#1a120e] border border-[#3d2b22] border-l-4 border-l-primary group-hover:bg-[#1a120e]/80 transition-colors">
                    <span className="material-symbols-outlined text-primary">hub</span>
                    <div>
                      <p className="text-sm font-bold text-primary">EventBridge</p>
                      <p className="text-xs text-slate-500">Pattern Matching</p>
                    </div>
                  </div>
                  {/* Callout: PII Scrubbing */}
                  <div className="bg-primary/10 border border-primary/20 rounded-lg p-3 my-2 text-center relative overflow-hidden">
                    <div className="absolute inset-0 bg-primary/5 animate-pulse"></div>
                    <span className="relative text-[10px] font-bold uppercase tracking-widest text-primary">Filtering & PII Scrubbing</span>
                  </div>
                  <div className="flex items-center gap-4 p-4 rounded-lg bg-[#1a120e] border border-[#3d2b22] group-hover:border-primary/30 transition-colors">
                    <span className="material-symbols-outlined text-slate-400">function</span>
                    <div>
                      <p className="text-sm font-bold text-slate-200">Lambda Tier 1</p>
                      <p className="text-xs text-slate-500">Normalizer</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-4 p-4 rounded-lg bg-[#1a120e] border border-[#3d2b22] group-hover:border-primary/30 transition-colors">
                    <span className="material-symbols-outlined text-slate-400">queue</span>
                    <div>
                      <p className="text-sm font-bold text-slate-200">Amazon SQS</p>
                      <p className="text-xs text-slate-500">Reliable Handover</p>
                    </div>
                  </div>
                </div>
                <div className="hidden lg:flex absolute -right-6 top-1/2 -translate-y-1/2 z-10 text-primary w-6 items-center justify-center">
                  <span className="material-symbols-outlined text-3xl group-hover:translate-x-1 transition-transform">arrow_forward</span>
                </div>
              </div>

              {/* 3. Multi-Agent Core */}
              <div className="flex flex-col gap-4 p-6 rounded-xl bg-primary/5 border-2 border-primary relative shadow-[0_0_30px_-5px_rgba(236,91,19,0.2)] group hover:shadow-[0_0_40px_-5px_rgba(236,91,19,0.3)] transition-all duration-500 hover:-translate-y-1">
                <div className="absolute -top-3 -right-3 flex size-6 items-center justify-center rounded-full bg-primary animate-bounce shadow-lg shadow-primary/40">
                  <span className="material-symbols-outlined text-[14px] text-white">star</span>
                </div>
                <div className="flex items-center gap-2 mb-4">
                  <span className="material-symbols-outlined text-primary text-2xl animate-pulse">smart_toy</span>
                  <h3 className="font-bold text-lg text-white">3. Multi-Agent Core</h3>
                </div>
                <div className="space-y-4">
                  <div className="p-4 rounded-lg bg-[#2a1d17] border border-primary/30 text-center relative overflow-hidden">
                    <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-primary to-transparent opacity-50"></div>
                    <p className="text-xs font-black text-primary mb-2 tracking-widest">ORCHESTRATOR</p>
                    <div className="flex justify-center gap-3 text-xs">
                      <span className="px-2 py-1 rounded bg-primary/20 text-primary font-bold">LangGraph</span>
                      <span className="px-2 py-1 rounded bg-primary/20 text-primary font-bold">Gemini 2.5</span>
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div className="p-3 rounded-lg bg-[#1a120e] border border-[#3d2b22] flex flex-col items-center gap-2 text-center group/item hover:bg-[#2a1d17] hover:border-primary/40 transition-colors cursor-default">
                      <span className="material-symbols-outlined text-slate-400 group-hover/item:text-primary transition-colors">mail</span>
                      <p className="text-[10px] font-bold text-slate-300">Email Agent</p>
                    </div>
                    <div className="p-3 rounded-lg bg-[#1a120e] border border-[#3d2b22] flex flex-col items-center gap-2 text-center group/item hover:bg-[#2a1d17] hover:border-primary/40 transition-colors cursor-default">
                      <span className="material-symbols-outlined text-slate-400 group-hover/item:text-primary transition-colors">search_insights</span>
                      <p className="text-[10px] font-bold text-slate-300">Forensic Agent</p>
                    </div>
                    <div className="p-3 rounded-lg bg-[#1a120e] border border-[#3d2b22] flex flex-col items-center gap-2 text-center group/item hover:bg-[#2a1d17] hover:border-primary/40 transition-colors cursor-default">
                      <span className="material-symbols-outlined text-slate-400 group-hover/item:text-primary transition-colors">gpp_bad</span>
                      <p className="text-[10px] font-bold text-slate-300">Threat Agent</p>
                    </div>
                    <div className="p-3 rounded-lg bg-[#1a120e] border border-[#3d2b22] flex flex-col items-center gap-2 text-center group/item hover:bg-[#2a1d17] hover:border-primary/40 transition-colors cursor-default">
                      <span className="material-symbols-outlined text-slate-400 group-hover/item:text-primary transition-colors">supervisor_account</span>
                      <p className="text-[10px] font-bold text-slate-300">Supervisor</p>
                    </div>
                  </div>
                </div>
                <div className="hidden lg:flex absolute -right-6 top-1/2 -translate-y-1/2 z-10 text-primary w-6 items-center justify-center">
                  <span className="material-symbols-outlined text-3xl group-hover:translate-x-1 transition-transform">arrow_forward</span>
                </div>
              </div>

              {/* 4. Storage & Interface */}
              <div className="flex flex-col gap-4 p-6 rounded-xl bg-[#2a1d17] border border-[#3d2b22] group hover:border-primary/50 hover:shadow-lg hover:shadow-primary/5 transition-all duration-300">
                <div className="flex items-center gap-2 mb-4">
                  <span className="material-symbols-outlined text-primary text-2xl">dashboard</span>
                  <h3 className="font-bold text-lg text-white">4. Storage & UI</h3>
                </div>
                <div className="flex flex-col gap-3">
                  <div className="flex items-center gap-4 p-4 rounded-lg bg-[#1a120e] border border-[#3d2b22] group-hover:border-primary/30 transition-colors">
                    <span className="material-symbols-outlined text-slate-400">table_rows</span>
                    <div>
                      <p className="text-sm font-bold text-slate-200">DynamoDB</p>
                      <p className="text-xs text-slate-500">State & History Store</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-4 p-4 rounded-lg bg-[#1a120e] border border-[#3d2b22] group-hover:border-primary/30 transition-colors">
                    <span className="material-symbols-outlined text-slate-400">api</span>
                    <div>
                      <p className="text-sm font-bold text-slate-200">API Gateway</p>
                      <p className="text-xs text-slate-500">Secure REST Access</p>
                    </div>
                  </div>
                  <Link to="/" className="mt-4 p-4 rounded-lg bg-primary/10 border border-primary/30 flex flex-col items-center gap-2 group-hover:bg-primary/20 transition-colors cursor-pointer">
                    <span className="material-symbols-outlined text-primary text-3xl">terminal</span>
                    <p className="text-sm font-bold text-slate-100">SOC Dashboard</p>
                    <p className="text-[10px] text-slate-400 text-center uppercase tracking-widest">Human-in-the-loop Interface</p>
                  </Link>
                </div>
              </div>
            </div>

            {/* Footer Stats / Legend */}
            <div className="mt-12 flex flex-wrap gap-8 justify-between items-center border-t border-[#3d2b22] pt-8">
              <div className="flex gap-12">
                <div className="flex flex-col">
                  <span className="text-slate-500 text-xs uppercase font-bold tracking-widest">Latency</span>
                  <span className="text-2xl font-bold text-slate-100">&lt; 2.4s</span>
                </div>
                <div className="flex flex-col">
                  <span className="text-slate-500 text-xs uppercase font-bold tracking-widest">Throughput</span>
                  <span className="text-2xl font-bold text-slate-100">50k EPS</span>
                </div>
                <div className="flex flex-col">
                  <span className="text-slate-500 text-xs uppercase font-bold tracking-widest">Model</span>
                  <span className="text-2xl font-black text-primary drop-shadow-[0_0_10px_rgba(236,91,19,0.5)]">Gemini 2.5</span>
                </div>
              </div>
              <div className="flex items-center gap-4 bg-[#2a1d17] px-5 py-3 rounded-xl border border-[#3d2b22]">
                <div className="flex items-center gap-3">
                  <span className="relative flex h-3 w-3">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-3 w-3 bg-primary"></span>
                  </span>
                  <span className="text-sm font-bold text-slate-200 tracking-wide">Live Orchestration Active</span>
                </div>
              </div>
            </div>
          </main>
        </div>
      </div>
    </div>
  );
}
