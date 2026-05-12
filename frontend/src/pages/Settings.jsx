import { useState, useEffect } from 'react';
import { getManagerEmails, updateManagerEmails } from '../api/index.js';

const DEPARTMENTS = ['IT', 'Marketing', 'Finance', 'Sales'];

export default function Settings() {
  const [emails, setEmails] = useState({ IT: '', Marketing: '', Finance: '', Sales: '', hrEmail: '' });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [success, setSuccess] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    getManagerEmails()
      .then(res => setEmails({
        IT: res.data.IT || '',
        Marketing: res.data.Marketing || '',
        Finance: res.data.Finance || '',
        Sales: res.data.Sales || '',
        hrEmail: res.data.hrEmail || '',
      }))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const handleSave = async (e) => {
    e.preventDefault();
    setSaving(true);
    setError('');
    setSuccess('');
    try {
      await updateManagerEmails(emails);
      setSuccess('Cập nhật thành công!');
      setTimeout(() => setSuccess(''), 3000);
    } catch (err) {
      setError(err.response?.data?.message || 'Lỗi khi lưu');
    } finally {
      setSaving(false);
    }
  };

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: 300 }}>
      <div style={{ width: 36, height: 36, border: '3px solid #e2e8f0', borderTopColor: '#2563eb', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
    </div>
  );

  return (
    <div style={{ maxWidth: 700, margin: '0 auto' }}>
      {/* Header */}
      <div style={{ marginBottom: 32 }}>
        <h1 className="page-title">Cài đặt hệ thống</h1>
        <p className="page-subtitle" style={{ marginBottom: 0 }}>Cấu hình email nhận thông báo phê duyệt cho từng phòng ban</p>
      </div>

      {/* Alert info */}
      <div className="alert alert-info" style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
        <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24" style={{ marginTop: 2, flexShrink: 0 }}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
        </svg>
        <p style={{ margin: 0, lineHeight: 1.6 }}>
          Email Manager/HR sẽ nhận <strong>thông báo tự động qua n8n</strong> khi có nhân viên trong phòng ban gửi đơn nghỉ phép cần phê duyệt.
        </p>
      </div>

      {/* Success / Error */}
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

      {/* Form card */}
      <form onSubmit={handleSave}>
        <div className="card" style={{ marginBottom: 24 }}>
          {/* Manager emails */}
          <div style={{ padding: '24px', borderBottom: '1px solid var(--border)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24 }}>
              <div style={{ width: 40, height: 40, borderRadius: 10, background: 'var(--primary-light)', color: 'var(--primary)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '1.2rem' }}>👤</div>
              <div>
                <h2 style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--text)' }}>Email Manager theo phòng ban</h2>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>Nhận email khi nhân viên trong phòng ban gửi đơn</p>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
              {DEPARTMENTS.map(dept => (
                <div key={dept} className="form-group" style={{ marginBottom: 0 }}>
                  <label>{dept}</label>
                  <input type="email"
                    placeholder={`manager.${dept.toLowerCase()}@company.com`}
                    value={emails[dept]}
                    onChange={e => setEmails({ ...emails, [dept]: e.target.value })}
                  />
                </div>
              ))}
            </div>
          </div>

          {/* HR email */}
          <div style={{ padding: '24px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24 }}>
              <div style={{ width: 40, height: 40, borderRadius: 10, background: 'rgba(111, 66, 193, 0.1)', color: '#6f42c1', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '1.2rem' }}>👔</div>
              <div>
                <h2 style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--text)' }}>Email HR</h2>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>Nhận email sau khi Manager duyệt đơn</p>
              </div>
            </div>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label>HR Email</label>
              <input type="email"
                placeholder="hr@company.com"
                value={emails.hrEmail}
                onChange={e => setEmails({ ...emails, hrEmail: e.target.value })}
              />
            </div>
          </div>
        </div>

        {/* Save button */}
        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <button type="submit" disabled={saving} className="btn btn-primary" style={{ padding: '12px 32px' }}>
            {saving ? (
              <>
                <div style={{ width: 16, height: 16, border: '2px solid rgba(255,255,255,0.3)', borderTopColor: '#fff', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
                Đang lưu...
              </>
            ) : (
              <>💾 Lưu cài đặt</>
            )}
          </button>
        </div>
      </form>

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
