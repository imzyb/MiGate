import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import {
  Boxes,
  ChevronLeft,
  ChevronRight,
  Gauge,
  GitBranch,
  Languages,
  LogOut,
  Moon,
  ServerCog,
  Settings,
  Shield,
  Sun,
} from 'lucide-react';
import { useMutation, useQuery } from '@tanstack/react-query';
import clsx from 'clsx';
import { api } from '../api/endpoints';
import { useI18n } from '../lib/i18n';
import { useToast } from '../components/ui';
import { useState } from 'react';

const navItems = [
  { to: '/', key: 'overview', icon: Gauge },
  { to: '/inbounds', key: 'inbounds', icon: Shield },
  { to: '/outbounds', key: 'outbounds', icon: Boxes },
  { to: '/core', key: 'core', icon: ServerCog },
  { to: '/routing', key: 'routing', icon: GitBranch },
  { to: '/topology', key: 'topology', icon: GitBranch },
  { to: '/settings', key: 'settings', icon: Settings },
] as const;

export default function AppLayout() {
  const navigate = useNavigate();
  const location = useLocation();
  const { lang, setLang, t } = useI18n();
  const { showToast } = useToast();
  const [theme, setTheme] = useState(() => document.documentElement.dataset.theme || 'light');
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const session = useQuery({ queryKey: ['session'], queryFn: api.session, staleTime: 5 * 60_000 });
  const version = useQuery({ queryKey: ['version'], queryFn: api.version, staleTime: 10 * 60_000 });
  const logout = useMutation({
    mutationFn: api.logout,
    onSuccess: () => navigate('/login', { replace: true }),
    onError: () => showToast(t('logoutFailed'), 'error'),
  });

  const toggleTheme = () => {
    const next = theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    localStorage.setItem('migate-theme', next);
    setTheme(next);
  };

  return (
    <div className={clsx('min-h-screen bg-panel-bg text-panel-text', sidebarOpen && 'sidebar-open', sidebarCollapsed && 'sidebar-collapsed')}>
      <div className="mobile-topbar">
        <button className="icon-button" onClick={() => setSidebarOpen(true)} title={t('expandMenu')} aria-label={t('expandMenu')}>
          <ChevronRight className="h-5 w-5" />
        </button>
        <div className="font-semibold">MiGate</div>
      </div>
      <aside className="sidebar">
        <div className="sidebar-header">
          <div className="sidebar-brand">
            <MiGateMark />
            <div className="sidebar-brand-text text-lg font-semibold tracking-normal">MiGate</div>
          </div>
          <button className="icon-button mobile-sidebar-close" onClick={() => setSidebarOpen(false)} title={t('closeMenu')} aria-label={t('closeMenu')}>
            <ChevronLeft className="h-5 w-5" />
          </button>
        </div>
        <nav className="grid gap-1 px-2">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === '/'}
                className={({ isActive }) => clsx('nav-link', isActive && 'nav-link-active')}
                onClick={() => setSidebarOpen(false)}
              >
                <Icon className="h-4 w-4" />
                <span className="nav-link-label">{t(item.key)}</span>
              </NavLink>
            );
          })}
        </nav>
        <div className="mt-auto border-t border-panel-line p-3">
          <div className="sidebar-footer-card">
            <div className="sidebar-version-button">
              <GitBranch className="h-4 w-4" />
              <span className="sidebar-footer-text truncate">{version.data?.version || 'dev'}</span>
            </div>
            <div className="sidebar-footer-text mt-2 truncate text-xs text-panel-muted">{session.data?.username || t('notLoggedIn')}</div>
          </div>
          <div className="sidebar-actions mt-3 grid grid-cols-4 gap-2">
            <button className="icon-button h-9" onClick={toggleTheme} title={t('toggleTheme')} aria-label={t('toggleTheme')}>
              {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            </button>
            <button className="icon-button h-9" onClick={() => setLang(lang === 'zh' ? 'en' : 'zh')} title={t('toggleLanguage')} aria-label={t('toggleLanguage')}>
              <Languages className="h-4 w-4" />
            </button>
            <button className="icon-button h-9" onClick={() => logout.mutate()} title={t('logout')} aria-label={t('logout')}>
              <LogOut className="h-4 w-4" />
            </button>
            <button className="icon-button h-9 desktop-sidebar-collapse" onClick={() => setSidebarCollapsed((value) => !value)} title={t(sidebarCollapsed ? 'expandMenu' : 'collapseMenu')} aria-label={t(sidebarCollapsed ? 'expandMenu' : 'collapseMenu')}>
              {sidebarCollapsed ? <ChevronRight className="h-5 w-5" /> : <ChevronLeft className="h-5 w-5" />}
            </button>
          </div>
        </div>
      </aside>
      <div className="sidebar-overlay" onClick={() => setSidebarOpen(false)} />
      <main className="main-shell" key={location.pathname}>
        <Outlet />
      </main>
    </div>
  );
}

function MiGateMark() {
  return (
    <svg className="sidebar-brand-mark" viewBox="0 0 64 64" aria-hidden="true">
      <defs>
        <linearGradient id="migate-mark-bg" x1="10" x2="54" y1="8" y2="56" gradientUnits="userSpaceOnUse">
          <stop stopColor="#10b981" />
          <stop offset="0.55" stopColor="#0f766e" />
          <stop offset="1" stopColor="#2563eb" />
        </linearGradient>
        <linearGradient id="migate-mark-shine" x1="18" x2="46" y1="13" y2="39" gradientUnits="userSpaceOnUse">
          <stop stopColor="#ecfeff" stopOpacity="0.72" />
          <stop offset="1" stopColor="#ecfeff" stopOpacity="0" />
        </linearGradient>
      </defs>
      <rect width="64" height="64" rx="16" fill="url(#migate-mark-bg)" />
      <path d="M15 45V19h9l8 13 8-13h9v26h-8V32.8l-6.4 10.6h-5.2L23 32.8V45z" fill="#f8fafc" />
      <path d="M13 17c8-7 24-8 36-2v7c-13-5-26-4-36 4z" fill="url(#migate-mark-shine)" />
    </svg>
  );
}
