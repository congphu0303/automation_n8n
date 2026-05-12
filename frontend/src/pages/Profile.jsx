import { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.jsx';
import { getGmailStatus, disconnectGmail, getGmailAuthUrl } from '../api/index.js';

const roleLabelMap = {
  employee: 'Nhân viên',
  manager: 'Quản lý',
  hr: 'Nhân sự (HR)',
};

export default function Profile() {
  const { user } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const [gmailStatus, setGmailStatus] = useState({ connected: false, gmailEmail: null });
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [success, setSuccess] = useState('');
  const [error, setError] = useState('');

  // Check for gmail callback params
  useEffect(() => {
    const gmailParam = searchParams.get('gmail');
    if (gmailParam === 'connected') {
      setSuccess('Kết nối Gmail thành công! 🎉');
      setSearchParams({}, { replace: true });
      setTimeout(() => setSuccess(''), 5000);
    } else if (gmailParam === 'denied') {
      setError('Bạn đã từ chối quyền truy cập Gmail.');
      setSearchParams({}, { replace: true });
      setTimeout(() => setError(''), 5000);
    } else if (gmailParam === 'error') {
      const reason = searchParams.get('reason') || 'unknown';
      const reasonMap = {
        missing_params: 'Thiếu thông tin xác thực từ Google.',
        invalid_state: 'Phiên xác thực không hợp lệ. Vui lòng thử lại.',
        no_user: 'Không xác định được tài khoản. Vui lòng đăng nhập lại.',
        no_refresh_token: 'Google không cung cấp mã xác thực. Vui lòng thử lại.',
        exchange_failed: 'Không thể hoàn tất xác thực. Vui lòng thử lại.',
      };
      setError(reasonMap[reason] || 'Đã xảy ra lỗi khi kết nối Gmail.');
      setSearchParams({}, { replace: true });
      setTimeout(() => setError(''), 8000);
    }
  }, [searchParams, setSearchParams]);

  // Fetch Gmail connection status
  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const res = await getGmailStatus();
        setGmailStatus(res.data);
      } catch (err) {
        console.error('Gmail status error:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchStatus();
  }, [success]); // Re-fetch when connection succeeds

  const handleConnectGmail = async () => {
    setActionLoading(true);
    setError('');
    try {
      const res = await getGmailAuthUrl();
      // Redirect to Google consent screen
      window.location.href = res.data.authUrl;
    } catch (err) {
      setError(err.response?.data?.message || 'Không thể tạo liên kết Google. Vui lòng thử lại.');
      setActionLoading(false);
    }
  };

  const handleDisconnectGmail = async () => {
    if (!confirm('Bạn có chắc muốn ngắt kết nối Gmail? Hệ thống sẽ không thể gửi email từ tài khoản của bạn.')) return;
    setActionLoading(true);
    setError('');
    try {
      await disconnectGmail();
      setGmailStatus({ connected: false, gmailEmail: null });
      setSuccess('Đã ngắt kết nối Gmail.');
      setTimeout(() => setSuccess(''), 4000);
    } catch (err) {
      setError(err.response?.data?.message || 'Lỗi khi ngắt kết nối');
    } finally {
      setActionLoading(false);
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
        <h1 className="page-title">Hồ sơ cá nhân</h1>
        <p className="page-subtitle" style={{ marginBottom: 0 }}>Thông tin tài khoản và cài đặt kết nối</p>
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

      {/* Personal Info Card */}
      <div className="card" style={{ marginBottom: 24 }}>
        <div style={{ padding: '24px', borderBottom: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24 }}>
            <div style={{
              width: 40, height: 40, borderRadius: 10,
              background: 'var(--primary-light)', color: 'var(--primary)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: '1.2rem',
            }}>👤</div>
            <div>
              <h2 style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--text)' }}>Thông tin cá nhân</h2>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>Thông tin tài khoản của bạn trong hệ thống</p>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {[
              { label: 'Họ tên', value: user?.name, icon: '📝' },
              { label: 'Email', value: user?.email, icon: '📧' },
              { label: 'Phòng ban', value: user?.department, icon: '🏢' },
              { label: 'Vai trò', value: roleLabelMap[user?.role] || user?.role, icon: '🏷️' },
            ].map(({ label, value, icon }) => (
              <div key={label} style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                padding: '14px 18px', background: 'var(--bg)', borderRadius: 12,
              }}>
                <span style={{ color: 'var(--text-muted)', fontSize: '0.9rem', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ fontSize: '1rem' }}>{icon}</span> {label}
                </span>
                <span style={{ fontWeight: 600, color: 'var(--text)', fontSize: '0.95rem' }}>{value || '-'}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Gmail Connection Card */}
      <div className="card" style={{ marginBottom: 24 }}>
        <div style={{ padding: '24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24 }}>
            <div style={{
              width: 40, height: 40, borderRadius: 10,
              background: gmailStatus.connected ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.08)',
              color: gmailStatus.connected ? '#10b981' : '#ef4444',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: '1.2rem',
            }}>
              {/* Gmail SVG Icon */}
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
                <path d="M20 4H4C2.9 4 2 4.9 2 6V18C2 19.1 2.9 20 4 20H20C21.1 20 22 19.1 22 18V6C22 4.9 21.1 4 20 4Z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                <path d="M22 6L12 13L2 6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </div>
            <div>
              <h2 style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--text)' }}>Kết nối Gmail</h2>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                {gmailStatus.connected
                  ? 'Gmail đã được kết nối để gửi thông báo'
                  : 'Kết nối Gmail để hệ thống gửi email từ tài khoản của bạn'}
              </p>
            </div>
          </div>

          {gmailStatus.connected ? (
            /* ── Connected State ── */
            <div>
              {/* Status badge */}
              <div style={{
                display: 'flex', alignItems: 'center', gap: 12,
                padding: '16px 20px', background: 'rgba(16, 185, 129, 0.06)',
                borderRadius: 12, border: '1px solid rgba(16, 185, 129, 0.15)',
                marginBottom: 20,
              }}>
                <div style={{
                  width: 36, height: 36, borderRadius: 10,
                  background: 'rgba(16, 185, 129, 0.15)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: '1.1rem',
                }}>✅</div>
                <div>
                  <div style={{ fontWeight: 700, color: '#059669', fontSize: '0.9rem' }}>Đã kết nối</div>
                  <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginTop: 2 }}>
                    {gmailStatus.gmailEmail}
                  </div>
                </div>
              </div>

              {/* Info message */}
              <div style={{
                padding: '12px 16px', background: 'var(--bg)', borderRadius: 10,
                fontSize: '0.85rem', color: 'var(--text-muted)', lineHeight: 1.6,
                marginBottom: 20,
              }}>
                Hệ thống sẽ gửi các thông báo nghỉ phép (xác nhận đơn, kết quả phê duyệt) từ chính tài khoản Gmail <strong style={{ color: 'var(--text)' }}>{gmailStatus.gmailEmail}</strong> của bạn.
              </div>

              {/* Disconnect button */}
              <button
                onClick={handleDisconnectGmail}
                disabled={actionLoading}
                className="btn btn-outline btn-sm"
                style={{ borderColor: 'var(--danger)', color: 'var(--danger)' }}
              >
                {actionLoading ? 'Đang xử lý...' : '🔌 Ngắt kết nối Gmail'}
              </button>
            </div>
          ) : (
            /* ── Not Connected State ── */
            <div>
              {/* Explanation */}
              <div className="alert alert-info" style={{ marginBottom: 20, border: 'none', borderLeft: '4px solid var(--primary)' }}>
                <strong>Tại sao cần kết nối Gmail?</strong>
                <ul style={{ margin: '8px 0 0', paddingLeft: 20, lineHeight: 1.8 }}>
                  <li>Email thông báo sẽ được gửi <strong>từ tài khoản của bạn</strong>, không phải từ hệ thống</li>
                  <li>Giảm khả năng email bị rơi vào thư rác</li>
                  <li>Hệ thống <strong>không lưu mật khẩu</strong> — chỉ lưu quyền gửi email</li>
                  <li>Bạn có thể ngắt kết nối bất cứ lúc nào</li>
                </ul>
              </div>

              {/* Connect button */}
              <button
                onClick={handleConnectGmail}
                disabled={actionLoading}
                className="btn btn-primary"
                style={{
                  display: 'flex', alignItems: 'center', gap: 10,
                  padding: '14px 28px', fontSize: '0.95rem',
                }}
              >
                {actionLoading ? (
                  <>
                    <div style={{
                      width: 18, height: 18,
                      border: '2px solid rgba(255,255,255,0.3)',
                      borderTopColor: '#fff',
                      borderRadius: '50%',
                      animation: 'spin 0.8s linear infinite',
                    }} />
                    Đang chuyển hướng...
                  </>
                ) : (
                  <>
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M20 4H4C2.9 4 2 4.9 2 6V18C2 19.1 2.9 20 4 20H20C21.1 20 22 19.1 22 18V6C22 4.9 21.1 4 20 4Z" strokeLinecap="round" strokeLinejoin="round"/>
                      <path d="M22 6L12 13L2 6" strokeLinecap="round" strokeLinejoin="round"/>
                    </svg>
                    Kết nối Gmail để gửi thông báo
                  </>
                )}
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Security note */}
      <div style={{
        padding: '16px 20px', borderRadius: 12,
        background: 'var(--bg)',
        border: '1px solid var(--border)',
        display: 'flex', alignItems: 'flex-start', gap: 12,
      }}>
        <span style={{ fontSize: '1.2rem', flexShrink: 0 }}>🔒</span>
        <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', lineHeight: 1.6 }}>
          <strong style={{ color: 'var(--text)' }}>Bảo mật:</strong> ApproveHub sử dụng <strong>OAuth 2.0</strong> của Google — tiêu chuẩn bảo mật cao nhất hiện nay.
          Hệ thống chỉ yêu cầu quyền <em>gửi email</em>, không thể đọc, xóa hoặc truy cập dữ liệu khác trong tài khoản Google của bạn.
        </div>
      </div>

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
