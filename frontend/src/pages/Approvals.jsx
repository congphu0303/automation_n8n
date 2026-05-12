import { useState, useEffect } from 'react';
import { getLeavesForApproval, approveLeaveById } from '../api/index.js';
import { useAuth } from '../context/AuthContext.jsx';

const APPROVE = 'approve';
const REJECT = 'reject';

export default function Approvals() {
  const { user } = useAuth();
  const [leaves, setLeaves] = useState([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(null);

  const fetchLeaves = async () => {
    try {
      const res = await getLeavesForApproval();
      const data = Array.isArray(res.data) ? res.data : (res.data.data || []);
      setLeaves(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchLeaves(); }, []);

  const handleAction = async (id, action) => {
    const msg = action === APPROVE ? 'duyệt' : 'từ chối';
    if (!confirm(`Bạn muốn ${msg} đơn này?`)) return;
    setActionLoading(id);
    try {
      await approveLeaveById(id, action);
      fetchLeaves();
    } catch (err) {
      alert(err.response?.data?.message || 'Lỗi');
    } finally {
      setActionLoading(null);
    }
  };

  const formatDate = (d) => d ? new Date(d).toLocaleDateString('vi-VN', { day: 'numeric', month: 'short', year: 'numeric' }) : '-';

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: 300 }}>
      <div style={{ width: 36, height: 36, border: '3px solid #e2e8f0', borderTopColor: '#2563eb', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
    </div>
  );

  const isHR = user.role === 'hr';
  const roleLabel = isHR ? 'HR' : 'Manager';
  const roleColor = isHR ? '#7c3aed' : '#0369a1';

  return (
    <div style={{ maxWidth: 900, margin: '0 auto' }}>
      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <h1 className="page-title">Duyệt đơn nghỉ phép</h1>
        <p className="page-subtitle" style={{ marginBottom: 0 }}>
          {isHR ? 'Đơn đã qua Manager, chờ bạn duyệt cuối' : `Đơn trong phòng ban "${user.department}"`}
        </p>
      </div>

      {/* Summary bar */}
      <div className="card" style={{
        display: 'flex', alignItems: 'center', gap: 16,
        padding: '16px 24px', marginBottom: 24,
      }}>
        <span className={isHR ? 'badge badge-hr' : 'badge badge-manager'}>
          {roleLabel}
        </span>
        <span style={{ color: 'var(--text-muted)', fontSize: '0.95rem' }}>
          Có <strong style={{ color: 'var(--text)' }}>{leaves.length}</strong> đơn chờ duyệt
        </span>
      </div>

      {leaves.length === 0 ? (
        <div className="card empty-state">
          <div style={{ fontSize: '3rem', marginBottom: 16 }}>🎉</div>
          <h3 style={{ fontWeight: 700, color: 'var(--text)', marginBottom: 8 }}>Tất cả đơn đã được xử lý!</h3>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.95rem' }}>Không có đơn nào cần duyệt lúc này</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {leaves.map(l => (
            <div key={l._id} className="card">
              {/* Card header */}
              <div className="card-header" style={{ padding: '16px 24px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                  <div style={{
                    width: 48, height: 48, borderRadius: 12,
                    background: 'var(--bg)', color: 'var(--text)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontSize: '1.2rem', fontWeight: 600,
                  }}>
                    {(l.employee_name || '?').charAt(0).toUpperCase()}
                  </div>
                  <div>
                    <div style={{ fontWeight: 700, color: 'var(--text)', fontSize: '1.05rem' }}>{l.employee_name}</div>
                    <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>{l.department}</div>
                  </div>
                </div>
                <span className={isHR ? 'badge badge-hr' : 'badge badge-manager'}>
                  {roleLabel}
                </span>
              </div>

              {/* Card body */}
              <div className="card-body">
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16, marginBottom: 20 }}>
                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: 4 }}>Ngày bắt đầu</div>
                    <div style={{ fontWeight: 600, color: 'var(--text)', fontSize: '0.95rem' }}>{formatDate(l.leave_date)}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: 4 }}>Số ngày nghỉ</div>
                    <div style={{ fontWeight: 600, color: 'var(--text)', fontSize: '0.95rem' }}>{l.leave_days} ngày</div>
                  </div>
                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: 4 }}>Manager</div>
                    <div style={{ fontWeight: 600, color: 'var(--text)', fontSize: '0.95rem' }}>
                      {l.manager_status === 'approved' ? (
                        <span style={{ color: 'var(--success)', display: 'flex', alignItems: 'center', gap: 4 }}>
                          <span style={{ fontSize: '0.7rem' }}>✓</span> Đã duyệt
                        </span>
                      ) : (
                        <span style={{ color: 'var(--warning)', display: 'flex', alignItems: 'center', gap: 4 }}>
                          <span style={{ fontSize: '0.7rem' }}>⏳</span> Chờ duyệt
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                {/* Reason */}
                <div style={{
                  background: 'var(--bg)', borderRadius: 10, padding: '16px',
                  fontSize: '0.95rem', color: 'var(--text)', marginBottom: 24,
                  borderLeft: '4px solid var(--border)',
                }}>
                  <span style={{ fontWeight: 600, color: 'var(--text-muted)' }}>Lý do: </span>{l.reason}
                </div>

                {/* Actions */}
                <div style={{ display: 'flex', gap: 16 }}>
                  <button
                    onClick={() => handleAction(l._id, APPROVE)}
                    disabled={actionLoading === l._id}
                    className="btn btn-success" style={{ flex: 1 }}>
                    {actionLoading === l._id ? 'Đang xử lý...' : '✓ Duyệt đơn'}
                  </button>
                  <button
                    onClick={() => handleAction(l._id, REJECT)}
                    disabled={actionLoading === l._id}
                    className="btn btn-outline" style={{ flex: 1, borderColor: 'var(--danger)', color: 'var(--danger)' }}>
                    ✕ Từ chối
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
