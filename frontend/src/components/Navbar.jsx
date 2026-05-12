import { NavLink } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.jsx';
import { useTheme } from '../context/ThemeContext.jsx';

export default function Navbar() {
  const { user, logout } = useAuth();
  const { isDarkMode, toggleTheme } = useTheme();

  const links = [
    { to: '/', label: 'Dashboard', roles: ['employee', 'manager', 'hr'] },
    { to: '/leave/new', label: 'Đơn nghỉ phép', roles: ['employee', 'manager', 'hr'] },
    { to: '/leaves', label: 'Đơn của tôi', roles: ['employee', 'manager', 'hr'] },
    { to: '/approvals', label: 'Duyệt đơn', roles: ['manager', 'hr'] },
    { to: '/meetings', label: 'Phòng họp', roles: ['employee', 'manager', 'hr'] },
    { to: '/users', label: 'Người dùng', roles: ['hr'] },
    { to: '/settings', label: 'Cài đặt', roles: ['hr'] },
    { to: '/profile', label: 'Hồ sơ', roles: ['employee', 'manager', 'hr'] },
  ];

  const visibleLinks = links.filter(l => l.roles.includes(user?.role));

  return (
    <nav className="navbar">
      <div style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
        <span className="navbar-brand">ApproveHub</span>
        <div className="navbar-links">
          {visibleLinks.map(l => (
            <NavLink key={l.to} to={l.to} end={l.to === '/'}>
              {l.label}
            </NavLink>
          ))}
        </div>
      </div>
      <div className="navbar-user">
        <button onClick={toggleTheme} className="theme-toggle" aria-label="Toggle theme">
          {isDarkMode ? '☀️' : '🌙'}
        </button>
        <span>{user?.name} ({user?.role})</span>
        <button onClick={logout} className="logout-btn">Đăng xuất</button>
      </div>
    </nav>
  );
}
