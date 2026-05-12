import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { DayPicker } from 'react-day-picker';
import 'react-day-picker/dist/style.css';
import { getLeaves, cancelLeave, returnEarly, updateLeave } from '../api/index.js';

const statusConfig = {
  pending: { bg: '#fef3c7', color: '#92400e', label: 'Chờ duyệt', dot: '#f59e0b' },
  approved: { bg: '#d1fae5', color: '#065f46', label: 'Đã duyệt', dot: '#10b981' },
  rejected: { bg: '#fee2e2', color: '#991b1b', label: 'Từ chối', dot: '#ef4444' },
  cancelled: { bg: '#f3f4f6', color: '#374151', label: 'Đã hủy', dot: '#6b7280' },
};

const StatusBadge = ({ s }) => {
  const b = statusConfig[s] || statusConfig.pending;
  const classes = {
    pending: 'badge-pending',
    approved: 'badge-approved',
    rejected: 'badge-rejected',
    cancelled: 'badge-cancelled',
  };
  return (
    <span className={`badge ${classes[s] || 'badge-pending'}`} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
      <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'currentColor' }} />
      {b.label}
    </span>
  );
};

const FILTERS = [
  { key: 'all', label: 'Tất cả' },
  { key: 'pending', label: 'Chờ duyệt' },
  { key: 'approved', label: 'Đã duyệt' },
  { key: 'rejected', label: 'Từ chối' },
  { key: 'cancelled', label: 'Đã hủy' },
];

function toLocalDate(d) {
  const year = d.getFullYear();
  const month = d.getMonth();
  const day = d.getDate();
  return new Date(year, month, day);
}

function toLocalDateString(d) {
  if (!d) return '';
  const date = d instanceof Date ? d : new Date(d);
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;
}

function fromLocalDateString(s) {
  if (!s) return undefined;
  // Handle ISO string like "2025-12-01T00:00:00.000Z" or "2025-12-01"
  let y, m, d;
  if (typeof s === 'string') {
    const iso = s.includes('T');
    if (iso) {
      const date = new Date(s);
      if (!isNaN(date)) return toLocalDate(date);
    }
    const parts = s.split('-');
    if (parts.length >= 3) {
      [y, m, d] = parts.map(Number);
    }
  } else if (s instanceof Date) {
    return toLocalDate(s);
  }
  if (y !== undefined) return new Date(y, m - 1, d);
  return undefined;
}

// ── Edit Leave Modal ──────────────────────────────────────────────
function EditLeaveModal({ leave, onClose, onSuccess }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const today = toLocalDate(new Date());
  const [selectedDay, setSelectedDay] = useState(fromLocalDateString(leave.leave_date));
  const [form, setForm] = useState({
    leave_date: leave.leave_date,
    leave_days: leave.leave_days,
    reason: leave.reason || '',
  });

  const handleDaySelect = (day) => {
    setSelectedDay(day ? toLocalDate(day) : undefined);
    setForm(prev => ({ ...prev, leave_date: day ? toLocalDateString(day) : '' }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!selectedDay) { setError('Vui lòng chọn ngày bắt đầu nghỉ.'); return; }
    setLoading(true);
    setError('');
    try {
      await updateLeave(leave._id, {
        leave_date: toLocalDateString(selectedDay),
        leave_days: parseInt(form.leave_days),
        reason: form.reason,
      });
      onSuccess();
    } catch (err) {
      setError(err.response?.data?.message || 'Cập nhật thất bại');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.4)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000
    }}>
      <div className="card" style={{ width: '100%', maxWidth: 540, margin: 16 }}>
        <div className="card-body">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
            <h2 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 700 }}>Sửa đơn nghỉ phép</h2>
            <button onClick={onClose} style={{ background: 'none', border: 'none', fontSize: '1.4rem', cursor: 'pointer', color: 'var(--text-muted)', lineHeight: 1 }}>×</button>
          </div>

          {error && <div className="alert alert-error" style={{ marginBottom: 16 }}>{error}</div>}

          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label>Ngày bắt đầu nghỉ *</label>
              <div style={{ marginTop: 8 }}>
                <DayPicker
                  mode="single"
                  selected={selectedDay}
                  onSelect={handleDaySelect}
                  fromDate={today}
                  style={{ '--rdp-accent-color': '#007bff' }}
                />
              </div>
              {selectedDay && (
                <small style={{ color: 'var(--success)', display: 'block', marginTop: 4 }}>
                  Đã chọn: <strong>{selectedDay.toLocaleDateString('vi-VN', { day: 'numeric', month: 'long', year: 'numeric' })}</strong>
                </small>
              )}
            </div>

            <div className="form-group">
              <label>Số ngày nghỉ *</label>
              <input type="number" min={1} max={365} required value={form.leave_days}
                onChange={e => setForm({ ...form, leave_days: e.target.value })} />
            </div>

            <div className="form-group">
              <label>Lý do nghỉ phép *</label>
              <textarea required maxLength={1000} value={form.reason} rows={3}
                onChange={e => setForm({ ...form, reason: e.target.value })} />
            </div>

            <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: 16, background: '#f8fafc', padding: '10px 14px', borderRadius: 8 }}>
              Nếu thay đổi ngày hoặc số ngày, đơn sẽ được gửi lại cho Manager xét duyệt.
            </div>

            <div style={{ display: 'flex', gap: 12, justifyContent: 'flex-end' }}>
              <button type="button" className="btn btn-secondary" onClick={onClose}>Hủy</button>
              <button type="submit" className="btn btn-primary" disabled={loading}>
                {loading ? 'Đang lưu...' : 'Lưu thay đổi'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}

// ── Return Early Modal ─────────────────────────────────────────────
function ReturnEarlyModal({ leave, onClose, onSuccess }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [selectedDay, setSelectedDay] = useState(undefined);

  const plannedEnd = (() => {
    const d = new Date(leave.leave_date);
    d.setDate(d.getDate() + (leave.leave_days || 1) - 1);
    return d;
  })();

  const today = toLocalDate(new Date());
  // Ngày về sớm: tối thiểu = ngày bắt đầu nghỉ + 1, tối đa = ngày kết thúc dự kiến
  const startDate = toLocalDate(new Date(leave.leave_date));
  const endDate = toLocalDate(plannedEnd);
  // minDate = ngày bắt đầu + 1 (không thể về ngay ngày đầu tiên nghỉ)
  const minDate = (() => {
    const d = new Date(startDate);
    d.setDate(d.getDate() + 1);
    return d;
  })();
  // maxDate = min(ngày kết thúc, hôm nay) — không thể về ngày trong tương lai
  const maxDate = endDate < today ? endDate : today;
  // Edge case: nếu hôm nay nằm trước minDate (vd: nghỉ bắt đầu hôm nay → minDate = ngày mai)
  // thì maxDate sẽ < minDate, khiến không chọn được ngày nào. Cho phép chọn từ ngày mai đến endDate.
  const effectiveMaxDate = maxDate < minDate ? endDate : maxDate;

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!selectedDay) { setError('Vui lòng chọn ngày về thực tế.'); return; }
    if (selectedDay < minDate || selectedDay > effectiveMaxDate) {
      setError('Ngày về không hợp lệ. Vui lòng chọn ngày trong khoảng cho phép.');
      return;
    }
    setLoading(true);
    setError('');
    try {
      await returnEarly(leave._id, toLocalDateString(selectedDay));
      onSuccess();
    } catch (err) {
      setError(err.response?.data?.message || 'Xử lý thất bại');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.4)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000
    }}>
      <div className="card" style={{ width: '100%', maxWidth: 480, margin: 16 }}>
        <div className="card-body">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
            <h2 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 700 }}>Về sớm</h2>
            <button onClick={onClose} style={{ background: 'none', border: 'none', fontSize: '1.4rem', cursor: 'pointer', color: 'var(--text-muted)', lineHeight: 1 }}>×</button>
          </div>

          <div style={{ background: '#f8fafc', borderRadius: 10, padding: '12px 16px', marginBottom: 20, fontSize: '0.875rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
              <span style={{ color: 'var(--text-muted)' }}>Ngày nghỉ</span>
              <strong>{new Date(leave.leave_date).toLocaleDateString('vi-VN')}</strong>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
              <span style={{ color: 'var(--text-muted)' }}>Ngày kết thúc dự kiến</span>
              <strong>{plannedEnd.toLocaleDateString('vi-VN')}</strong>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Số ngày đã đăng ký</span>
              <strong>{leave.leave_days} ngày</strong>
            </div>
          </div>

          {error && <div className="alert alert-error" style={{ marginBottom: 16 }}>{error}</div>}

          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label>Ngày về thực tế *</label>
              <div style={{ marginTop: 8 }}>
                <DayPicker
                  mode="single"
                  selected={selectedDay}
                  onSelect={d => setSelectedDay(d ? toLocalDate(d) : undefined)}
                  fromDate={minDate}
                  toDate={effectiveMaxDate}
                  disabled={(d) => {
                    const local = toLocalDate(d);
                    return local < minDate || local > effectiveMaxDate;
                  }}
                  style={{ '--rdp-accent-color': '#007bff' }}
                />
              </div>
              <small style={{ color: 'var(--text-muted)', display: 'block', marginTop: 4 }}>
                Chọn từ <strong>{minDate.toLocaleDateString('vi-VN')}</strong> đến <strong>{effectiveMaxDate.toLocaleDateString('vi-VN')}</strong>
              </small>
            </div>

            <div style={{ display: 'flex', gap: 12, justifyContent: 'flex-end', marginTop: 12 }}>
              <button type="button" className="btn btn-secondary" onClick={onClose}>Hủy</button>
              <button type="submit" className="btn btn-primary" disabled={loading}>
                {loading ? 'Đang xử lý...' : 'Xác nhận về sớm'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────────
export default function MyLeaves() {
  const [leaves, setLeaves] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');
  const [actionLoading, setActionLoading] = useState(null);
  const [success, setSuccess] = useState('');
  const [editingLeave, setEditingLeave] = useState(null);
  const [returningLeave, setReturningLeave] = useState(null);

  const fetchLeaves = async () => {
    try {
      const res = await getLeaves();
      const data = Array.isArray(res.data) ? res.data : (res.data.data || []);
      setLeaves(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchLeaves(); }, []);

  const handleCancel = async (id) => {
    if (!confirm('Bạn có chắc muốn hủy đơn này?')) return;
    setActionLoading(id);
    try {
      await cancelLeave(id, 'Hủy bởi nhân viên');
      setSuccess('Đơn đã được hủy thành công!');
      setTimeout(() => setSuccess(''), 3000);
      fetchLeaves();
    } catch (err) {
      alert(err.response?.data?.message || 'Lỗi khi hủy đơn');
    } finally {
      setActionLoading(null);
    }
  };

  const filtered = filter === 'all' ? leaves : leaves.filter(l => l.status === filter);
  const formatDate = (d) => d ? new Date(d).toLocaleDateString('vi-VN', { day: 'numeric', month: 'short', year: 'numeric' }) : '-';

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: 300 }}>
      <div style={{ width: 36, height: 36, border: '3px solid #e2e8f0', borderTopColor: '#2563eb', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
    </div>
  );

  return (
    <>
      <div style={{ maxWidth: 1000, margin: '0 auto' }}>
        {/* Header */}
        <div className="flex-between mb-3">
          <div>
            <h1 className="page-title">Đơn nghỉ phép của tôi</h1>
            <p className="page-subtitle" style={{ marginBottom: 0 }}>Lịch sử và trạng thái các đơn đã gửi</p>
          </div>
          <Link to="/leave/new" className="btn btn-primary">+ Gửi đơn mới</Link>
        </div>

        {/* Success */}
        {success && (
          <div className="alert alert-success" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span>✓</span> {success}
          </div>
        )}

        {/* Filters */}
        <div className="tabs">
          {FILTERS.map(f => (
            <div key={f.key} onClick={() => setFilter(f.key)} className={`tab ${filter === f.key ? 'active' : ''}`} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              {f.label}
              {f.key !== 'all' && (
                <span className="badge" style={{ background: filter === f.key ? 'var(--primary)' : 'var(--border)', color: filter === f.key ? 'white' : 'var(--text-muted)', padding: '2px 8px' }}>
                  {f.key === 'all' ? leaves.length : leaves.filter(l => l.status === f.key).length}
                </span>
              )}
            </div>
          ))}
        </div>

        {/* Cards */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {filtered.length === 0 ? (
            <div className="card empty-state">
              <div style={{ fontSize: '2.5rem', marginBottom: 12 }}>📭</div>
              <p>Không có đơn nào</p>
              <Link to="/leave/new" style={{ color: 'var(--primary)', fontWeight: 500, display: 'inline-block', marginTop: 8 }}>Gửi đơn nghỉ phép mới →</Link>
            </div>
          ) : (
            filtered.map(l => (
              <div key={l._id} className="card" style={{
                padding: '20px 24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                gap: 16,
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                  <div style={{
                    width: 48, height: 48, borderRadius: 12,
                    background: 'var(--primary-light)', color: 'var(--primary)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontSize: '1.3rem', flexShrink: 0,
                  }}>🏖️</div>
                  <div>
                    <div style={{ fontWeight: 700, color: 'var(--text)', fontSize: '0.95rem' }}>
                      {formatDate(l.leave_date)}
                      <span style={{ marginLeft: 8, color: 'var(--text-muted)', fontWeight: 400, fontSize: '0.85rem' }}>
                        · {l.leave_days} ngày
                      </span>
                    </div>
                    <div style={{
                      color: 'var(--text-muted)', fontSize: '0.85rem', marginTop: 4,
                      maxWidth: 400, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                    }}>
                      {l.reason}
                    </div>
                    {l.actualReturnDate && (
                      <div style={{ color: '#10b981', fontSize: '0.8rem', marginTop: 2, fontWeight: 500 }}>
                        ↩ Về sớm ngày {formatDate(l.actualReturnDate)}
                        {l.refundDays > 0 && <span style={{ color: 'var(--text-muted)' }}> · Hoàn lại {l.refundDays} ngày</span>}
                      </div>
                    )}
                  </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexShrink: 0 }}>
                  <StatusBadge s={l.status} />
                  {l.status === 'pending' && (
                    <>
                      <button
                        onClick={() => setEditingLeave(l)}
                        className="btn btn-outline btn-sm"
                        style={{ borderColor: 'var(--primary)', color: 'var(--primary)' }}>
                        Sửa
                      </button>
                      <button
                        onClick={() => handleCancel(l._id)}
                        disabled={actionLoading === l._id}
                        className="btn btn-outline btn-sm"
                        style={{ borderColor: 'var(--danger)', color: 'var(--danger)' }}>
                        {actionLoading === l._id ? '...' : 'Hủy đơn'}
                      </button>
                    </>
                  )}
                  {l.status === 'approved' && !l.actualReturnDate && (
                    <button
                      onClick={() => setReturningLeave(l)}
                      className="btn btn-outline btn-sm"
                      style={{ borderColor: '#10b981', color: '#10b981' }}>
                      Về sớm
                    </button>
                  )}
                </div>
              </div>
            ))
          )}
        </div>

        <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
      </div>

      {editingLeave && (
        <EditLeaveModal
          leave={editingLeave}
          onClose={() => setEditingLeave(null)}
          onSuccess={() => { setEditingLeave(null); setSuccess('Đơn đã được cập nhật!'); setTimeout(() => setSuccess(''), 3000); fetchLeaves(); }}
        />
      )}

      {returningLeave && (
        <ReturnEarlyModal
          leave={returningLeave}
          onClose={() => setReturningLeave(null)}
          onSuccess={() => { setReturningLeave(null); setSuccess('Đã cập nhật ngày về sớm!'); setTimeout(() => setSuccess(''), 4000); fetchLeaves(); }}
        />
      )}
    </>
  );
}
