export const Footer = () => {
  return (
    <footer className="bg-white dark:bg-background-dark/80 border-t border-slate-200 dark:border-primary/10 px-10 py-4 flex justify-between items-center text-[10px] text-slate-400 uppercase tracking-widest font-bold">
      <div className="flex gap-6">
        <span>Graph ID: BASTION-7742</span>
        <span>Version: 2.1.0-alpha</span>
      </div>
      <div className="flex items-center gap-2">
        <div className="size-2 rounded-full bg-green-500 animate-pulse"></div>
        <span>System Operational</span>
      </div>
    </footer>
  );
};
