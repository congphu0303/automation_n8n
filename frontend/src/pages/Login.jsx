import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { login as apiLogin, register as apiRegister } from '../api/index.js';
import { useAuth } from '../context/AuthContext.jsx';

// ── Sidebar (defined outside so it never re-creates on re-render) ──────────
function Sidebar() {
  return (
    <div style={{
      width: '45%',
      minHeight: '100vh',
      background: 'linear-gradient(160deg, #0f172a 0%, #1e3a5f 60%, #2563eb 100%)',
      display: 'flex',
      flexDirection: 'column',
      justifyContent: 'center',
      padding: '48px 52px',
      position: 'relative',
      overflow: 'hidden',
    }}>
      <div style={{
        position: 'absolute', top: -80, right: -80,
        width: 280, height: 280,
        borderRadius: '50%',
        background: 'rgba(255,255,255,0.04)',
        border: '1px solid rgba(255,255,255,0.08)',
      }} />
      <div style={{
        position: 'absolute', bottom: -60, left: -60,
        width: 220, height: 220,
        borderRadius: '50%',
        background: 'rgba(255,255,255,0.04)',
        border: '1px solid rgba(255,255,255,0.08)',
      }} />

      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 48 }}>
        <div style={{
          width: 44, height: 44,
          borderRadius: 12,
          background: 'linear-gradient(135deg, #60a5fa, #3b82f6)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          boxShadow: '0 4px 14px rgba(59,130,246,0.4)',
        }}>
          <svg width="24" height="24" fill="white" viewBox="0 0 24 24">
            <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
          </svg>
        </div>
        <span style={{ fontSize: '1.6rem', fontWeight: 700, color: '#fff', letterSpacing: '-0.02em' }}>
          ApproveHub
        </span>
      </div>

      <h2 style={{ fontSize: '1.7rem', fontWeight: 700, color: '#fff', lineHeight: 1.3, marginBottom: 16 }}>
        Công cụ quản lý<br /> thông minh
      </h2>
      <p style={{ color: 'rgba(255,255,255,0.6)', fontSize: '0.95rem', lineHeight: 1.7, marginBottom: 48 }}>
        Tự động hóa quy trình , phê duyệt đến thông báo — giúp tiết kiệm thời gian cho nhân viên và quản lý.
      </p>

      {[
        'Gửi đơn chỉ trong 30 giây',
        'Phê duyệt mọi lúc mọi nơi',
        'Thông báo tự động qua email',
      ].map((text, i) => (
        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 14 }}>
          <div style={{
            width: 28, height: 28, borderRadius: 8,
            background: 'rgba(59,130,246,0.25)',
            border: '1px solid rgba(59,130,246,0.4)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
          }}>
            <svg width="14" height="14" fill="none" stroke="#60a5fa" strokeWidth="2.5" viewBox="0 0 24 24">
              <polyline points="20 6 9 17 4 12"/>
            </svg>
          </div>
          <span style={{ color: 'rgba(255,255,255,0.8)', fontSize: '0.9rem' }}>{text}</span>
        </div>
      ))}

      <div style={{
        marginTop: 'auto', paddingTop: 48,
        borderTop: '1px solid rgba(255,255,255,0.08)',
      }}>
        <p style={{ color: 'rgba(255,255,255,0.4)', fontSize: '0.8rem' }}>
          Hệ thống tự động hóa quy trình
        </p>
      </div>
    </div>
  );
}

// ── Form wrapper ───────────────────────────────────────────────────────────
function FormWrap({ children }) {
  return (
    <div style={{
      flex: 1,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '48px 40px',
      background: '#f8fafc',
    }}>
      <div style={{ width: '100%', maxWidth: 420 }}>
        {children}
      </div>
    </div>
  );
}

export default function Login() {
  const [showRegister, setShowRegister] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const [loginForm, setLoginForm] = useState({ email: '', password: '' });
  const [registerForm, setRegisterForm] = useState({
    name: '', email: '', password: '', department: 'IT', role: 'employee',
  });

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const res = await apiLogin(loginForm);
      login(res.data.token, res.data.user);
      navigate('/');
    } catch (err) {
      setError(err.response?.data?.message || 'Đăng nhập thất bại');
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      await apiRegister(registerForm);
      setShowRegister(false);
      setLoginForm({ email: registerForm.email, password: registerForm.password });
      setError('');
    } catch (err) {
      setError(err.response?.data?.message || 'Đăng ký thất bại');
    } finally {
      setLoading(false);
    }
  };

  // Register form ──────────────────────────────────────────────────────────
  if (showRegister) {
    return (
      <div style={{ display: 'flex', minHeight: '100vh' }}>
        <Sidebar />
        <FormWrap>
          <div style={{ marginBottom: 32 }}>
            <h2 style={{ fontSize: '1.7rem', fontWeight: 700, color: '#0f172a', marginBottom: 8, letterSpacing: '-0.02em' }}>
              Tạo tài khoản mới
            </h2>
            <p style={{ color: '#64748b', fontSize: '0.9rem' }}>
              Đăng ký để bắt đầu sử dụng ApproveHub
            </p>
          </div>

          {error && <div style={{
            background: '#fef2f2', border: '1px solid #fecaca', borderRadius: 10,
            color: '#dc2626', padding: '10px 14px', fontSize: '0.875rem', marginBottom: 20,
          }}>{error}</div>}

          <form onSubmit={handleRegister} style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
            <div style={{ display: 'flex', gap: 14 }}>
              <div style={{ flex: 1 }}>
                <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, color: '#374151', marginBottom: 6 }}>Họ tên</label>
                <input type="text" required placeholder="Nguyen Van A" value={registerForm.name}
                  onChange={e => setRegisterForm({ ...registerForm, name: e.target.value })}
                  style={{ width: '100%', padding: '11px 14px', border: '1.5px solid #e2e8f0', borderRadius: 10, fontSize: '0.9rem', outline: 'none', boxSizing: 'border-box', background: '#fff', transition: 'border-color 0.2s' }} />
              </div>
              <div style={{ flex: 1 }}>
                <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, color: '#374151', marginBottom: 6 }}>Email</label>
                <input type="email" required placeholder="email@company.com" value={registerForm.email}
                  onChange={e => setRegisterForm({ ...registerForm, email: e.target.value })}
                  style={{ width: '100%', padding: '11px 14px', border: '1.5px solid #e2e8f0', borderRadius: 10, fontSize: '0.9rem', outline: 'none', boxSizing: 'border-box', background: '#fff', transition: 'border-color 0.2s' }} />
              </div>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, color: '#374151', marginBottom: 6 }}>Mật khẩu</label>
              <div style={{ position: 'relative' }}>
                <input
                  type={showPassword ? 'text' : 'password'}
                  required placeholder="Tối thiểu 6 ký tự" minLength={6} value={registerForm.password}
                  onChange={e => setRegisterForm({ ...registerForm, password: e.target.value })}
                  style={{ width: '100%', padding: '11px 44px 11px 14px', border: '1.5px solid #e2e8f0', borderRadius: 10, fontSize: '0.9rem', outline: 'none', boxSizing: 'border-box', background: '#fff', transition: 'border-color 0.2s' }} />
                <button type="button" onClick={() => setShowPassword(v => !v)} style={{
                  position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)',
                  background: 'none', border: 'none', cursor: 'pointer', color: '#94a3b8',
                  padding: 0, display: 'flex', alignItems: 'center',
                }}>
                  {showPassword ? (
                    <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21"/>
                    </svg>
                  ) : (
                    <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
                    </svg>
                  )}
                </button>
              </div>
            </div>

            <div style={{ display: 'flex', gap: 14 }}>
              <div style={{ flex: 1 }}>
                <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, color: '#374151', marginBottom: 6 }}>Phòng ban</label>
                <select value={registerForm.department}
                  onChange={e => setRegisterForm({ ...registerForm, department: e.target.value })}
                  style={{ width: '100%', padding: '11px 14px', border: '1.5px solid #e2e8f0', borderRadius: 10, fontSize: '0.9rem', outline: 'none', boxSizing: 'border-box', background: '#fff', color: '#374151' }}>
                  {['IT', 'Marketing', 'Finance', 'Sales', 'HR', 'Operations'].map(d => <option key={d} value={d}>{d}</option>)}
                </select>
              </div>
              <div style={{ flex: 1 }}>
                <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, color: '#374151', marginBottom: 6 }}>Vai trò</label>
                <select value={registerForm.role}
                  onChange={e => setRegisterForm({ ...registerForm, role: e.target.value })}
                  style={{ width: '100%', padding: '11px 14px', border: '1.5px solid #e2e8f0', borderRadius: 10, fontSize: '0.9rem', outline: 'none', boxSizing: 'border-box', background: '#fff', color: '#374151' }}>
                  {['employee', 'manager', 'hr'].map(r => <option key={r} value={r}>{r.charAt(0).toUpperCase() + r.slice(1)}</option>)}
                </select>
              </div>
            </div>

            <button type="submit" disabled={loading} style={{
              marginTop: 8, padding: '13px', borderRadius: 10, border: 'none',
              background: 'linear-gradient(135deg, #2563eb, #1d4ed8)',
              color: '#fff', fontSize: '0.95rem', fontWeight: 600, cursor: 'pointer',
              boxShadow: '0 4px 14px rgba(37,99,235,0.3)', transition: 'opacity 0.2s',
            }}>
              {loading ? 'Đang đăng ký...' : 'Tạo tài khoản'}
            </button>
          </form>

          <p style={{ textAlign: 'center', marginTop: 24, color: '#64748b', fontSize: '0.875rem' }}>
            Đã có tài khoản?{' '}
            <span style={{ color: '#2563eb', fontWeight: 600, cursor: 'pointer' }}
              onClick={() => { setShowRegister(false); setError(''); }}>
              Đăng nhập ngay
            </span>
          </p>
        </FormWrap>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', minHeight: '100vh' }}>
      <Sidebar />
      <FormWrap>
        <div style={{ marginBottom: 32 }}>
          <h2 style={{ fontSize: '1.7rem', fontWeight: 700, color: '#0f172a', marginBottom: 8, letterSpacing: '-0.02em' }}>
            Chào trở lại! 👋
          </h2>
          <p style={{ color: '#64748b', fontSize: '0.9rem' }}>
            Đăng nhập để tiếp tục sử dụng ApproveHub
          </p>
        </div>

        {error && <div style={{
          background: '#fef2f2', border: '1px solid #fecaca', borderRadius: 10,
          color: '#dc2626', padding: '10px 14px', fontSize: '0.875rem', marginBottom: 20,
        }}>{error}</div>}

        <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
          <div>
            <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, color: '#374151', marginBottom: 6 }}>Email</label>
            <input type="email" required placeholder="email@company.com" value={loginForm.email}
              onChange={e => setLoginForm({ ...loginForm, email: e.target.value })}
              style={{ width: '100%', padding: '12px 14px', border: '1.5px solid #e2e8f0', borderRadius: 10, fontSize: '0.9rem', outline: 'none', boxSizing: 'border-box', background: '#fff', transition: 'border-color 0.2s' }} />
          </div>

          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
              <label style={{ fontSize: '0.85rem', fontWeight: 600, color: '#374151' }}>Mật khẩu</label>
              <span style={{ fontSize: '0.8rem', color: '#2563eb', cursor: 'pointer', fontWeight: 500 }}>Quên mật khẩu?</span>
            </div>
            <div style={{ position: 'relative' }}>
              <input
                type={showPassword ? 'text' : 'password'}
                required placeholder="••••••••" value={loginForm.password}
                onChange={e => setLoginForm({ ...loginForm, password: e.target.value })}
                style={{ width: '100%', padding: '12px 44px 12px 14px', border: '1.5px solid #e2e8f0', borderRadius: 10, fontSize: '0.9rem', outline: 'none', boxSizing: 'border-box', background: '#fff', transition: 'border-color 0.2s' }} />
              <button type="button" onClick={() => setShowPassword(v => !v)} style={{
                position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)',
                background: 'none', border: 'none', cursor: 'pointer', color: '#94a3b8',
                padding: 0, display: 'flex', alignItems: 'center',
              }}>
                {showPassword ? (
                  <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21"/>
                  </svg>
                ) : (
                  <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
                  </svg>
                )}
              </button>
            </div>
          </div>

          <button type="submit" disabled={loading} style={{
            marginTop: 8, padding: '13px', borderRadius: 10, border: 'none',
            background: 'linear-gradient(135deg, #2563eb, #1d4ed8)',
            color: '#fff', fontSize: '0.95rem', fontWeight: 600, cursor: 'pointer',
            boxShadow: '0 4px 14px rgba(37,99,235,0.3)', transition: 'opacity 0.2s',
          }}>
            {loading ? 'Đang đăng nhập...' : 'Đăng nhập'}
          </button>
        </form>

        <div style={{ display: 'flex', alignItems: 'center', gap: 16, margin: '24px 0' }}>
          <div style={{ flex: 1, height: '1px', background: '#e2e8f0' }} />
          <span style={{ color: '#94a3b8', fontSize: '0.8rem' }}>hoặc</span>
          <div style={{ flex: 1, height: '1px', background: '#e2e8f0' }} />
        </div>

        <p style={{ textAlign: 'center', marginTop: 24, color: '#64748b', fontSize: '0.875rem' }}>
          Chưa có tài khoản?{' '}
          <span style={{ color: '#2563eb', fontWeight: 600, cursor: 'pointer' }}
            onClick={() => { setShowRegister(true); setError(''); }}>
            Đăng ký ngay
          </span>
        </p>
      </FormWrap>
    </div>
  );
}
