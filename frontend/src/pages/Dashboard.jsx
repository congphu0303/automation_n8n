import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { getLeaves, getLeavesForApproval } from '../api/index.js';
import { useAuth } from '../context/AuthContext.jsx';

const statusBadge = (s) => {
  const map = {
    pending: { class: 'badge-pending', label: 'Chờ duyệt' },
    approved: { class: 'badge-approved', label: 'Đã duyệt' },
    rejected: { class: 'badge-rejected', label: 'Từ chối' },
    cancelled: { class: 'badge-cancelled', label: 'Đã hủy' },
  };
  const b = map[s] || map.pending;
  return (
    <span className={`badge ${b.class}`} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
      <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'currentColor' }} />
      {b.label}
    </span>
  );
};

const StatCard = ({ icon, value, label, accent }) => (
  <div className="stat-card" style={{ borderLeft: `4px solid ${accent}` }}>
    <div style={{
      width: 56, height: 56, borderRadius: 14,
      background: accent + '18',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      fontSize: '1.5rem', flexShrink: 0,
    }}>{icon}</div>
    <div className="stat-info">
      <h3>{value}</h3>
      <p>{label}</p>
    </div>
  </div>
);

const QuickAction = ({ to, icon, label, color }) => (
  <Link to={to} className="card" style={{
    display: 'flex', alignItems: 'center', gap: 12,
    padding: '16px 20px', borderRadius: 12,
    color: 'var(--text)', fontSize: '0.95rem', fontWeight: 600,
    textDecoration: 'none', transition: 'all 0.3s ease',
  }}
  onMouseEnter={e => { e.currentTarget.style.borderColor = color; e.currentTarget.style.transform = 'translateY(-3px)'; e.currentTarget.style.boxShadow = `0 8px 16px ${color}22`; }}
  onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.transform = 'translateY(0)'; e.currentTarget.style.boxShadow = 'var(--shadow-sm)'; }}>
    <span style={{ fontSize: '1.2rem' }}>{icon}</span>
    {label}
  </Link>
);

export default function Dashboard() {
  const { user } = useAuth();
  const [stats, setStats] = useState({ total: 0, pending: 0, approved: 0, rejected: 0, pendingApprovalsCount: 0 });
  const [recentLeaves, setRecentLeaves] = useState([]);
  const [pendingApprovals, setPendingApprovals] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [leavesRes, approvalsRes] = await Promise.all([
          getLeaves(),
          user.role !== 'employee' ? getLeavesForApproval() : Promise.resolve({ data: [] }),
        ]);
        const leaves = Array.isArray(leavesRes.data) ? leavesRes.data : (leavesRes.data.data || []);
        const approvals = Array.isArray(approvalsRes.data) ? approvalsRes.data : (approvalsRes.data.data || []);
        setStats({
          total: leaves.length,
          pending: leaves.filter(l => l.status === 'pending').length,
          approved: leaves.filter(l => l.status === 'approved').length,
          rejected: leaves.filter(l => l.status === 'rejected').length,
          pendingApprovalsCount: approvals.length,
        });
        setRecentLeaves(leaves.slice(0, 5));
        setPendingApprovals(approvals.slice(0, 5));
      } catch (err) {
        console.error('Dashboard error:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [user.role]);

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: 300 }}>
      <div style={{ width: 36, height: 36, border: '3px solid #e2e8f0', borderTopColor: '#2563eb', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
    </div>
  );

  const formatDate = (d) => d ? new Date(d).toLocaleDateString('vi-VN', { day: 'numeric', month: 'short', year: 'numeric' }) : '-';

  return (
    <div style={{ maxWidth: 1100, margin: '0 auto' }}>
      {/* Header */}
      <div style={{ marginBottom: 32 }}>
        <h1 className="page-title">
          Xin chào, {user?.name}! 👋
        </h1>
        <p className="page-subtitle">Chúc bạn một ngày làm việc hiệu quả</p>
      </div>

      {/* Stats */}
      <div className="stats-grid">
        <StatCard icon="📋" value={stats.total} label="Tổng đơn" accent="#6366f1" />
        <StatCard icon="⏳" value={stats.pending} label="Đang chờ" accent="#f59e0b" />
        <StatCard icon="✅" value={stats.approved} label="Đã duyệt" accent="#10b981" />
        {(user.role === 'manager' || user.role === 'hr') && (
          <StatCard icon="📥" value={stats.pendingApprovalsCount} label="Chờ bạn duyệt" accent="#3b82f6" />
        )}
      </div>

      <div className="form-row" style={{ marginBottom: 24 }}>
        {/* Recent leaves */}
        <div className="card">
          <div className="card-header">
            <h2>Đơn gần đây</h2>
            <Link to="/leaves" style={{ fontSize: '0.85rem', color: 'var(--primary)', fontWeight: 600 }}>Xem tất cả →</Link>
          </div>
          <div>
            {recentLeaves.length === 0 ? (
              <div className="empty-state">
                <div style={{ fontSize: '2.5rem', marginBottom: 12 }}>📭</div>
                <p>Chưa có đơn nào</p>
                <Link to="/leave/new" style={{ display: 'inline-block', marginTop: 12, color: 'var(--primary)', fontWeight: 500 }}>Gửi đơn nghỉ phép →</Link>
              </div>
            ) : (
              recentLeaves.map(l => (
                <div key={l._id} style={{
                  padding: '16px 24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  borderBottom: '1px solid var(--border)',
                }}>
                  <div>
                    <div style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text)' }}>{formatDate(l.leave_date)}</div>
                    <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginTop: 4 }}>{l.leave_days} ngày nghỉ</div>
                  </div>
                  {statusBadge(l.status)}
                </div>
              ))
            )}
          </div>
        </div>

        {/* Pending approvals (manager/hr) */}
        {(user.role === 'manager' || user.role === 'hr') && (
          <div className="card">
            <div className="card-header">
              <h2>Cần duyệt</h2>
              <Link to="/approvals" style={{ fontSize: '0.85rem', color: 'var(--primary)', fontWeight: 600 }}>Xem tất cả →</Link>
            </div>
            <div>
              {pendingApprovals.length === 0 ? (
                <div className="empty-state">
                  <div style={{ fontSize: '2.5rem', marginBottom: 12 }}>🎉</div>
                  <p>Tất cả đơn đã được xử lý!</p>
                </div>
              ) : (
                pendingApprovals.map(l => (
                  <div key={l._id} style={{
                    padding: '16px 24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                    borderBottom: '1px solid var(--border)',
                  }}>
                    <div>
                      <div style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text)' }}>{l.employee_name}</div>
                      <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginTop: 4 }}>{formatDate(l.leave_date)} · {l.leave_days} ngày</div>
                    </div>
                    <span className="badge badge-manager">
                      {user.role === 'hr' ? 'HR' : 'Manager'}
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>
        )}
      </div>

      {/* Quick actions */}
      <div className="card">
        <div className="card-header">
          <h2>Hành động nhanh</h2>
        </div>
        <div className="card-body">
          <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
          <QuickAction to="/leave/new" icon="🏖️" label="Gửi đơn nghỉ phép" color="#6366f1" />
          <QuickAction to="/leaves" icon="📄" label="Lịch sử đơn" color="#10b981" />
          <QuickAction to="/meetings" icon="🏢" label="Đặt phòng họp" color="#f59e0b" />
          {(user.role === 'manager' || user.role === 'hr') && (
            <QuickAction to="/approvals" icon="✅" label="Duyệt đơn" color="#3b82f6" />
          )}
          {user.role === 'hr' && (
            <QuickAction to="/users" icon="👥" label="Quản lý nhân viên" color="#8b5cf6" />
          )}
        </div>
        </div>
      </div>

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
