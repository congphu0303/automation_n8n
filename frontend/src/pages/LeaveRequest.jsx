import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { DayPicker } from 'react-day-picker';
import 'react-day-picker/dist/style.css';
import { submitLeave, getLeaves } from '../api/index.js';
import { useAuth } from '../context/AuthContext.jsx';

function toLocalDate(d) {
  const year = d.getFullYear();
  const month = d.getMonth();
  const day = d.getDate();
  return new Date(year, month, day);
}

function toLocalDateString(d) {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

function sameDay(a, b) {
  if (!a || !b) return false;
  return a.getFullYear() === b.getFullYear()
    && a.getMonth() === b.getMonth()
    && a.getDate() === b.getDate();
}

export default function LeaveRequest() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const [form, setForm] = useState({ leave_date: '', leave_days: 1, reason: '' });
  const [selectedDay, setSelectedDay] = useState(undefined);
  const [existingDates, setExistingDates] = useState([]);

  useEffect(() => {
    const fetchMyLeaves = async () => {
      try {
        const res = await getLeaves();
        const raw = res.data;
        const leaves = Array.isArray(raw) ? raw : (raw.data || []);
        const dates = [];
        leaves.forEach(leave => {
          if (leave.status === 'cancelled' || leave.status === 'rejected') return;
          const start = new Date(leave.leave_date);
          for (let i = 0; i < (leave.leave_days || 1); i++) {
            const d = new Date(start);
            d.setDate(d.getDate() + i);
            dates.push(toLocalDate(d));
          }
        });
        setExistingDates([...new Set(dates)]);
      } catch (err) {
        console.error('Không lấy được danh sách đơn:', err);
      }
    };
    fetchMyLeaves();
  }, []);

  const today = toLocalDate(new Date());

  const isExistingDate = (d) => {
    const local = toLocalDate(d);
    return existingDates.some(existing => sameDay(local, existing));
  };

  const validateRange = (startDay, days) => {
    if (!startDay || !days) return { valid: true };
    for (let i = 0; i < parseInt(days); i++) {
      const d = new Date(startDay);
      d.setDate(d.getDate() + i);
      if (isExistingDate(d)) {
        return { valid: false, conflictDate: toLocalDate(d) };
      }
    }
    return { valid: true };
  };

  const handleDaySelect = (day) => {
    if (!day) {
      setSelectedDay(undefined);
      setForm({ ...form, leave_date: '' });
      setError('');
      return;
    }
    const result = validateRange(day, form.leave_days);
    if (!result.valid) {
      setSelectedDay(undefined);
      setForm({ ...form, leave_date: '' });
      setError(
        `Khoảng nghỉ trùng với đơn đã có (ngày ${result.conflictDate.toLocaleDateString('vi-VN')}). Vui lòng chọn ngày khác.`
      );
      return;
    }
    setError('');
    setSelectedDay(toLocalDate(day));
    setForm({ ...form, leave_date: toLocalDateString(day) });
  };

  const handleDaysChange = (e) => {
    const days = e.target.value;
    setForm({ ...form, leave_days: days });
    if (selectedDay) {
      const result = validateRange(selectedDay, days);
      if (!result.valid) {
        setError(
          `Khoảng nghỉ trùng với đơn đã có (ngày ${result.conflictDate.toLocaleDateString('vi-VN')}). Vui lòng chọn ngày khác.`
        );
        setSelectedDay(undefined);
        setForm(prev => ({ ...prev, leave_date: '' }));
      } else {
        setError('');
      }
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!selectedDay) {
      setError('Vui lòng chọn ngày bắt đầu nghỉ.');
      return;
    }
    const result = validateRange(selectedDay, form.leave_days);
    if (!result.valid) {
      setError(
        `Khoảng nghỉ trùng với đơn đã có (ngày ${result.conflictDate.toLocaleDateString('vi-VN')}). Vui lòng chọn ngày khác.`
      );
      return;
    }
    setLoading(true);
    setError('');
    setSuccess('');
    try {
      const res = await submitLeave({
        leave_date: form.leave_date,
        leave_days: parseInt(form.leave_days),
        reason: form.reason,
        department: user.department,
      });
      setSuccess(`Đơn đã được gửi thành công! Mã đơn: ${res.data.leaveId}`);
      setTimeout(() => navigate('/leaves'), 2000);
    } catch (err) {
      setError(err.response?.data?.message || 'Gửi đơn thất bại');
    } finally {
      setLoading(false);
    }
  };

  const proposedDays = selectedDay && form.leave_days > 0
    ? Array.from({ length: parseInt(form.leave_days) || 0 }, (_, i) => {
        const d = new Date(selectedDay);
        d.setDate(d.getDate() + i);
        return toLocalDate(d);
      })
    : [];

  return (
    <div style={{ maxWidth: 640, margin: '0 auto' }}>
      <h1 className="page-title">Gửi đơn nghỉ phép</h1>
      <p className="page-subtitle" style={{ marginBottom: 24 }}>N8N sẽ tự động xử lý luồng phê duyệt cho bạn</p>

      <div className="card">
        <div className="card-body">
          <div className="alert alert-info" style={{ marginBottom: 24 }}>
            <strong>Luồng xử lý tự động:</strong><br />
            1 ngày: AI tự động duyệt | 2-3 ngày: Manager duyệt | 4+ ngày: Manager + HR duyệt
          </div>
          {error && <div className="alert alert-error">{error}</div>}
          {success && <div className="alert alert-success">{success}</div>}

          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label>Ngày bắt đầu nghỉ *</label>

              <div style={{ marginTop: 8 }}>
                <DayPicker
                  mode="single"
                  selected={selectedDay}
                  onSelect={handleDaySelect}
                  disabled={(d) => d < today || isExistingDate(d)}
                  fromDate={today}
                  modifiers={
                    selectedDay && form.leave_days > 0
                      ? { proposed: proposedDays }
                      : {}
                  }
                  modifiersClassNames={{
                    proposed: 'rdp-day_proposed',
                  }}
                  style={{ '--rdp-accent-color': '#007bff' }}
                />
                <style>{`
                  .rdp-day_proposed {
                    background-color: rgba(25, 135, 84, 0.1) !important;
                    color: var(--success) !important;
                    font-weight: 600;
                    border-radius: 6px;
                    border: 1.5px solid var(--success);
                  }
                  [data-disabled="true"] {
                    opacity: 0.4;
                  }
                `}</style>
                {selectedDay && (
                  <small style={{ color: 'var(--success)', display: 'block', marginTop: 8 }}>
                    Khoảng nghỉ dự kiến:{' '}
                    <strong>
                      {proposedDays.map(d => d.toLocaleDateString('vi-VN', { day: 'numeric', month: 'short' })).join(' → ')}
                    </strong>
                    {' '}({form.leave_days} ngày)
                  </small>
                )}
                {existingDates.length > 0 && (
                  <small className="text-muted" style={{ display: 'block', marginTop: 8 }}>
                    Ngày <strong style={{ color: 'var(--primary)' }}>bị gạch chéo</strong> đã có đơn nghỉ phép, không thể chọn.
                  </small>
                )}
              </div>
            </div>

            <div className="form-group">
              <label>Số ngày nghỉ *</label>
              <input
                type="number" min={1} max={365} required
                value={form.leave_days}
                onChange={handleDaysChange}
              />
            </div>

            <div className="form-group">
              <label>Lý do nghỉ phép *</label>
              <textarea
                placeholder="VD: Đi khám bệnh, công tác, du lịch..." required maxLength={1000}
                value={form.reason}
                onChange={e => setForm({ ...form, reason: e.target.value })}
              />
              <small className="text-muted">{form.reason.length}/1000</small>
            </div>

            <div className="flex-between mt-2">
              <button type="button" className="btn btn-secondary" onClick={() => navigate('/leaves')}>Hủy</button>
              <button type="submit" className="btn btn-primary" disabled={loading}>
                {loading ? 'Đang gửi...' : 'Gửi đơn'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}
