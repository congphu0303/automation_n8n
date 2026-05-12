import { useState, useEffect } from 'react';
import { getUsers, createUser, updateUser, deleteUser } from '../api/index.js';

const roleConfig = {
  hr: { bg: '#f3e8ff', color: '#6d28d9', label: 'HR' },
  manager: { bg: '#e0f2fe', color: '#0369a1', label: 'Manager' },
  employee: { bg: '#f1f5f9', color: '#475569', label: 'Employee' },
};

const RoleBadge = ({ role }) => {
  const r = roleConfig[role] || roleConfig.employee;
  const classes = { hr: 'badge-hr', manager: 'badge-manager', employee: 'badge-cancelled' };
  return (
    <span className={`badge ${classes[role] || 'badge-cancelled'}`}>
      {r.label}
    </span>
  );
};

export default function Users() {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState(null);
  const [saving, setSaving] = useState(false);
  const [success, setSuccess] = useState('');
  const [error, setError] = useState('');
  const [confirmDelete, setConfirmDelete] = useState(null);

  const [form, setForm] = useState({ name: '', email: '', password: '', department: 'IT', role: 'employee' });

  const fetchUsers = async () => {
    try { const res = await getUsers(); const data = Array.isArray(res.data) ? res.data : (res.data.data || []); setUsers(data); }
    catch (err) { console.error(err); }
    finally { setLoading(false); }
  };

  useEffect(() => { fetchUsers(); }, []);

  const resetForm = () => {
    setForm({ name: '', email: '', password: '', department: 'IT', role: 'employee' });
    setEditing(null);
    setShowForm(false);
    setError('');
    setSuccess('');
  };

  const handleEdit = (u) => {
    setForm({ name: u.name, email: u.email, password: '', department: u.department, role: u.role });
    setEditing(u._id);
    setShowForm(true);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSaving(true);
    setError('');
    setSuccess('');
    try {
      if (editing) {
        const data = { ...form };
        if (!data.password) delete data.password;
        await updateUser(editing, data);
        setSuccess('Cập nhật thành công!');
      } else {
        await createUser(form);
        setSuccess('Tạo nhân viên thành công!');
      }
      fetchUsers();
      resetForm();
    } catch (err) {
      setError(err.response?.data?.message || 'Lỗi');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id) => {
    try {
      await deleteUser(id);
      setConfirmDelete(null);
      fetchUsers();
    } catch (err) {
      alert(err.response?.data?.message || 'Lỗi');
    }
  };

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: 300 }}>
      <div style={{ width: 36, height: 36, border: '3px solid #e2e8f0', borderTopColor: '#2563eb', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
    </div>
  );

  return (
    <div style={{ maxWidth: 1000, margin: '0 auto' }}>
      {/* Header */}
      <div className="flex-between mb-3">
        <div>
          <h1 className="page-title">Quản lý nhân viên</h1>
          <p className="page-subtitle" style={{ marginBottom: 0 }}>Tổng cộng {users.length} nhân viên</p>
        </div>
        <button onClick={() => { resetForm(); setShowForm(true); }} className="btn btn-primary">
          + Thêm nhân viên
        </button>
      </div>

      {/* Alerts */}
      {success && (
        <div className="alert alert-success" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span>✓</span> {success}
        </div>
      )}
      {error && (
        <div className="alert alert-error" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span>✕</span> {error}
        </div>
      )}

      {/* Form modal */}
      {showForm && (
        <div className="card mb-3">
          <div className="card-header">
            <h2>{editing ? 'Sửa thông tin nhân viên' : 'Tạo nhân viên mới'}</h2>
            <button onClick={resetForm} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', fontSize: '1.2rem', padding: 4 }}>✕</button>
          </div>
          <div className="card-body">
            <form onSubmit={handleSubmit}>
              <div className="form-row">
                <div className="form-group">
                  <label>Họ tên *</label>
                  <input type="text" required placeholder="Nguyen Van A" value={form.name}
                    onChange={e => setForm({ ...form, name: e.target.value })}
                  />
                </div>
                <div className="form-group">
                  <label>Email *</label>
                  <input type="email" required placeholder="email@company.com" value={form.email}
                    onChange={e => setForm({ ...form, email: e.target.value })}
                  />
                </div>
              </div>
              <div className="form-group">
                <label>
                  Mật khẩu {editing ? '(bỏ trống nếu không đổi)' : '*'}
                </label>
                <input type="password" value={form.password}
                  onChange={e => setForm({ ...form, password: e.target.value })}
                  {...(!editing && { required: true })}
                  placeholder={editing ? 'Không đổi mật khẩu' : 'Tối thiểu 6 ký tự'}
                />
              </div>
              <div className="form-row">
                <div className="form-group">
                  <label>Phòng ban *</label>
                  <select value={form.department} onChange={e => setForm({ ...form, department: e.target.value })}>
                    {['IT', 'Marketing', 'Finance', 'Sales', 'HR', 'Operations'].map(d => <option key={d} value={d}>{d}</option>)}
                  </select>
                </div>
                <div className="form-group">
                  <label>Vai trò *</label>
                  <select value={form.role} onChange={e => setForm({ ...form, role: e.target.value })}>
                    {['employee', 'manager', 'hr'].map(r => <option key={r} value={r}>{r.charAt(0).toUpperCase() + r.slice(1)}</option>)}
                  </select>
                </div>
              </div>
              <div style={{ display: 'flex', gap: 12 }}>
                <button type="submit" disabled={saving} className="btn btn-primary">
                  {saving ? 'Đang lưu...' : editing ? 'Cập nhật' : 'Tạo nhân viên'}
                </button>
                <button type="button" onClick={resetForm} className="btn btn-secondary">
                  Hủy
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Users table */}
      <div className="card table-wrapper">
        <div style={{ overflowX: 'auto' }}>
          <table>
            <thead>
              <tr>
                {['Nhân viên', 'Email', 'Phòng ban', 'Vai trò', 'Hành động'].map((h, i) => (
                  <th key={i}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {users.map(u => (
                <tr key={u._id}>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                      <div style={{
                        width: 36, height: 36, borderRadius: 10,
                        background: 'var(--primary-light)', color: 'var(--primary)',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        fontWeight: 700, fontSize: '0.9rem', flexShrink: 0,
                      }}>{(u.name || '?').charAt(0).toUpperCase()}</div>
                      <span style={{ fontWeight: 600, color: 'var(--text)', fontSize: '0.95rem' }}>{u.name}</span>
                    </div>
                  </td>
                  <td style={{ color: 'var(--text-muted)' }}>{u.email}</td>
                  <td style={{ color: 'var(--text-muted)' }}>{u.department}</td>
                  <td><RoleBadge role={u.role} /></td>
                  <td>
                    <div style={{ display: 'flex', gap: 8 }}>
                      <button onClick={() => handleEdit(u)} className="btn btn-outline btn-sm">Sửa</button>
                      {confirmDelete === u._id ? (
                        <div style={{ display: 'flex', gap: 8 }}>
                          <button onClick={() => handleDelete(u._id)} className="btn btn-danger btn-sm">Xác nhận</button>
                          <button onClick={() => setConfirmDelete(null)} className="btn btn-secondary btn-sm">Hủy</button>
                        </div>
                      ) : (
                        <button onClick={() => setConfirmDelete(u._id)} className="btn btn-outline btn-sm" style={{ borderColor: 'var(--danger)', color: 'var(--danger)' }}>Xóa</button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
