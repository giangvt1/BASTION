import { Link, useLocation } from 'react-router-dom';

export const Header = () => {
  const location = useLocation();

  const getLinkClass = (path: string) => {
    const isActive = location.pathname === path;
    return isActive
      ? "text-primary text-sm font-bold border-b-2 border-primary py-1 leading-normal"
      : "text-slate-600 dark:text-slate-400 hover:text-primary dark:hover:text-primary text-sm font-medium transition-colors leading-normal";
  };

  return (
    <header className="flex items-center justify-between whitespace-nowrap border-b border-slate-200 dark:border-slate-800 px-6 lg:px-10 py-3 bg-white dark:bg-background-dark sticky top-0 z-50">
      <div className="flex items-center gap-4">
        <div className="size-8 flex items-center justify-center rounded bg-primary">
          <span className="material-symbols-outlined text-white">shield_with_heart</span>
        </div>
        <h2 className="text-slate-900 dark:text-slate-100 text-lg font-bold leading-tight tracking-tight">BASTION SOC</h2>
      </div>
      
      <div className="flex flex-1 justify-end gap-8">
        <nav className="hidden md:flex items-center gap-9">
          <Link to="/" className={getLinkClass("/")}>Dashboard</Link>
          <Link to="/pipeline" className={getLinkClass("/pipeline")}>Pipeline</Link>
          <Link to="/orchestrator" className={getLinkClass("/orchestrator")}>Orchestrator</Link>
          <Link to="/architecture" className={getLinkClass("/architecture")}>Architecture</Link>
        </nav>
        
        <div className="flex items-center gap-4">
          <div className="relative hidden sm:block">
            <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 text-lg">search</span>
            <input className="w-64 pl-10 pr-4 py-2 rounded-xl border-none bg-slate-100 dark:bg-slate-800 text-sm focus:ring-2 focus:ring-primary/50 text-slate-900 dark:text-slate-100" placeholder="Search signals or entities..." type="text" onKeyDown={(e) => { if(e.key === 'Enter') alert('Search functionality coming soon.') }} />
          </div>
          <button onClick={() => alert('No new notifications')} className="p-2 rounded-xl text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors relative">
            <span className="material-symbols-outlined">notifications</span>
            <span className="absolute top-2 right-2 size-2 bg-primary rounded-full"></span>
          </button>
          <div onClick={() => alert('Profile settings coming soon')} className="bg-center bg-no-repeat aspect-square bg-cover rounded-full size-9 border border-primary/30 cursor-pointer hover:border-primary transition-colors" style={{ backgroundImage: 'url("https://lh3.googleusercontent.com/aida-public/AB6AXuAegP43hGK90czstinMrzeEDLlt-KccgwBtSkQcFw28P5hZPetU53co4lKxqJ0DGeZGLKEnDKL6iyyr2PC2sxjOhxvnADWTjio9BURcpcGMxszVTHrw9z0ZT3QKyYt3JKI0_h1mckRWJwmgeryvDVjgpuIR3_LumnC_IbmnqI3nQYe6h4WSoFVQHAGuaB2SjXIFBLmhutNybKfJNW7d1bhIM9jWGEiKkzxsOb1gON2ja52hvCGlpjszjlS5PDuLPPyURXEe86VtkA")' }}></div>
        </div>
      </div>
    </header>
  );
};
