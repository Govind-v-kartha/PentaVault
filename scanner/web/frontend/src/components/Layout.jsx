import { NavLink, Outlet } from 'react-router-dom';
import './Layout.css';

const NAV_ITEMS = [
  { to: '/',          icon: '⊕', label: 'New Scan' },
  { to: '/dashboard', icon: '◈', label: 'Dashboard' },
  { to: '/history',   icon: '◷', label: 'History' },
  { to: '/mitre',     icon: '⬡', label: 'MITRE ATT&CK' },
  { to: '/owasp',     icon: '⊞', label: 'OWASP 2025' },
];

export default function Layout() {
  return (
    <div className="pv-layout">
      <aside className="pv-sidebar">
        <div className="sidebar-brand">
          <div className="brand-shield">
            <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="M9 12l2 2 4-4" />
            </svg>
          </div>
          <div className="brand-text">
            <span className="brand-name">PentaVault</span>
            <span className="brand-ver">v2.0</span>
          </div>
        </div>

        <nav className="sidebar-nav">
          {NAV_ITEMS.map(item => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
            >
              <span className="nav-icon">{item.icon}</span>
              <span className="nav-label">{item.label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="footer-copy">© 2026 Govind V Kartha</div>
        </div>
      </aside>

      <main className="pv-main">
        <Outlet />
      </main>
    </div>
  );
}
