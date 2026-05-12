import { useState, useEffect } from 'react';
import { getRooms, getRoomSlots, getBookings, createBooking, cancelBooking } from '../api/index.js';

const statusConfig = {
  pending: { bg: '#fef3c7', color: '#92400e', label: 'Chờ duyệt', dot: '#f59e0b' },
  approved: { bg: '#d1fae5', color: '#065f46', label: 'Đã duyệt', dot: '#10b981' },
  rejected: { bg: '#fee2e2', color: '#991b1b', label: 'Từ chối', dot: '#ef4444' },
  cancelled: { bg: '#f3f4f6', color: '#374151', label: 'Đã hủy', dot: '#6b7280' },
};

const StatusBadge = ({ s }) => {
  const b = statusConfig[s] || statusConfig.pending;
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 5,
      padding: '3px 10px', borderRadius: 20, fontSize: '0.75rem', fontWeight: 700,
      background: b.bg, color: b.color,
    }}>
      <span style={{ width: 6, height: 6, borderRadius: '50%', background: b.dot }} />
      {b.label}
    </span>
  );
};

export default function MeetingRoom() {
  const [rooms, setRooms] = useState([]);
  const [bookings, setBookings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedRoom, setSelectedRoom] = useState(null);
  const [selectedRoomName, setSelectedRoomName] = useState('');
  const [bookedSlots, setBookedSlots] = useState([]);
  const [tab, setTab] = useState('rooms');
  const [loadingSlots, setLoadingSlots] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [success, setSuccess] = useState('');
  const [error, setError] = useState('');

  const [form, setForm] = useState({
    room_id: '', room_name: '', meeting_date: '', start_time: '09:00', end_time: '10:00',
    purpose: '', attendees: 1, priority: 'normal', notes: '',
  });

  useEffect(() => {
    Promise.all([getRooms(), getBookings()])
      .then(([r, b]) => { setRooms(r.data); setBookings(b.data); })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (selectedRoom && form.meeting_date) {
      setLoadingSlots(true);
      getRoomSlots(selectedRoom, form.meeting_date)
        .then(res => setBookedSlots(res.data.booked_slots || []))
        .catch(console.error)
        .finally(() => setLoadingSlots(false));
    }
  }, [selectedRoom, form.meeting_date]);

  const handleSelectRoom = (room) => {
    setSelectedRoom(room._id);
    setSelectedRoomName(room.name);
    setForm(f => ({ ...f, room_id: room._id, room_name: room.name }));
    setError('');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (form.end_time && form.start_time && form.end_time <= form.start_time) {
      setError('Giờ kết thúc phải sau giờ bắt đầu.');
      return;
    }
    setSubmitting(true);
    setError('');
    setSuccess('');
    try {
      await createBooking(form);
      setSuccess('Yêu cầu đặt phòng đã được gửi!');
      const res = await getBookings();
      setBookings(res.data);
      setForm({ room_id: '', room_name: '', meeting_date: '', start_time: '09:00', end_time: '10:00', purpose: '', attendees: 1, priority: 'normal', notes: '' });
      setSelectedRoom(null);
      setSelectedRoomName('');
      setTab('bookings');
      setTimeout(() => setSuccess(''), 3000);
    } catch (err) {
      setError(err.response?.data?.message || 'Đặt phòng thất bại');
    } finally {
      setSubmitting(false);
    }
  };

  const handleCancel = async (id) => {
    if (!confirm('Hủy đặt phòng này?')) return;
    try {
      await cancelBooking(id, 'Hủy bởi người dùng');
      const res = await getBookings();
      setBookings(res.data);
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
      <div style={{ marginBottom: 28 }}>
        <h1 style={{ fontSize: '1.6rem', fontWeight: 800, color: '#0f172a', marginBottom: 4, letterSpacing: '-0.02em' }}>Đặt phòng họp</h1>
        <p style={{ color: '#64748b', fontSize: '0.875rem' }}>Chọn phòng và gửi yêu cầu — n8n sẽ tự động phê duyệt</p>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 4, borderBottom: '2px solid #e2e8f0', marginBottom: 28 }}>
        {[{ key: 'rooms', label: 'Đặt phòng', icon: '🏢' }, { key: 'bookings', label: 'Lịch sử đặt', icon: '📋' }].map(t => (
          <button key={t.key} onClick={() => setTab(t.key)} style={{
            padding: '10px 20px', borderBottom: '2px solid',
            borderColor: tab === t.key ? '#2563eb' : 'transparent',
            background: 'none', color: tab === t.key ? '#2563eb' : '#64748b',
            fontSize: '0.9rem', fontWeight: 600, cursor: 'pointer',
            marginBottom: -2, transition: 'all 0.2s', display: 'flex', alignItems: 'center', gap: 6,
          }}>
            <span>{t.icon}</span> {t.label}
          </button>
        ))}
      </div>

      {tab === 'rooms' && (
        <div>
          {/* Success / Error */}
          {success && (
            <div style={{ background: '#d1fae5', border: '1px solid #a7f3d0', borderRadius: 10, color: '#065f46', padding: '12px 16px', fontSize: '0.875rem', marginBottom: 20, display: 'flex', alignItems: 'center', gap: 10 }}>
              <span>✓</span> {success}
            </div>
          )}
          {error && (
            <div style={{ background: '#fee2e2', border: '1px solid #fca5a5', borderRadius: 10, color: '#991b1b', padding: '12px 16px', fontSize: '0.875rem', marginBottom: 20, display: 'flex', alignItems: 'center', gap: 10 }}>
              <span>✕</span> {error}
            </div>
          )}

          {/* Room cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))', gap: 16, marginBottom: 28 }}>
            {rooms.map(r => (
              <div key={r._id} onClick={() => handleSelectRoom(r)} style={{
                background: '#fff', borderRadius: 14, cursor: 'pointer',
                border: '2px solid',
                borderColor: selectedRoom === r._id ? '#2563eb' : '#e2e8f0',
                boxShadow: selectedRoom === r._id
                  ? '0 4px 16px rgba(37,99,235,0.2)'
                  : '0 1px 4px rgba(0,0,0,0.06)',
                transition: 'all 0.2s',
                overflow: 'hidden',
              }}>
                <div style={{
                  height: 6,
                  background: selectedRoom === r._id
                    ? 'linear-gradient(135deg, #2563eb, #1d4ed8)'
                    : '#e2e8f0',
                  transition: 'background 0.2s',
                }} />
                <div style={{ padding: '18px 20px' }}>
                  <div style={{ fontWeight: 700, color: '#0f172a', fontSize: '1rem', marginBottom: 6 }}>{r.name}</div>
                  <div style={{ display: 'flex', gap: 12, color: '#64748b', fontSize: '0.8rem', marginBottom: 10 }}>
                    <span>🏢 Tầng {r.floor}</span>
                    <span>👥 {r.capacity} người</span>
                  </div>
                  {r.facilities?.length > 0 && (
                    <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
                      {r.facilities.map(f => (
                        <span key={f} style={{
                          padding: '2px 8px', borderRadius: 20, fontSize: '0.7rem', fontWeight: 600,
                          background: '#f1f5f9', color: '#475569',
                        }}>{f}</span>
                      ))}
                    </div>
                  )}
                  {selectedRoom === r._id && (
                    <div style={{ marginTop: 10, color: '#2563eb', fontSize: '0.8rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>
                      <span>✓</span> Đã chọn
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>

          {/* Booking form */}
          {selectedRoom && (
            <div style={{
              background: '#fff', borderRadius: 16,
              boxShadow: '0 1px 4px rgba(0,0,0,0.06), 0 4px 12px rgba(0,0,0,0.04)',
              overflow: 'hidden',
            }}>
              <div style={{ padding: '16px 24px', borderBottom: '1px solid #f1f5f9' }}>
                <h2 style={{ fontSize: '0.95rem', fontWeight: 700, color: '#0f172a' }}>
                  📅 Thông tin đặt phòng — <span style={{ color: '#2563eb' }}>{selectedRoomName}</span>
                </h2>
              </div>
              <div style={{ padding: '24px' }}>
                <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                    <div>
                      <label style={{ display: 'block', fontSize: '0.825rem', fontWeight: 600, color: '#374151', marginBottom: 6 }}>Ngày họp *</label>
                      <input type="date" required value={form.meeting_date} min={new Date().toLocaleDateString('en-CA')}
                        onChange={e => setForm({ ...form, meeting_date: e.target.value })}
                        style={{ width: '100%', padding: '10px 14px', border: '1.5px solid #e2e8f0', borderRadius: 10, fontSize: '0.875rem', outline: 'none', boxSizing: 'border-box', background: '#fff' }} />
                    </div>
                    <div>
                      <label style={{ display: 'block', fontSize: '0.825rem', fontWeight: 600, color: '#374151', marginBottom: 6 }}>Số người *</label>
                      <input type="number" min={1} required value={form.attendees}
                        onChange={e => setForm({ ...form, attendees: e.target.value })}
                        style={{ width: '100%', padding: '10px 14px', border: '1.5px solid #e2e8f0', borderRadius: 10, fontSize: '0.875rem', outline: 'none', boxSizing: 'border-box', background: '#fff' }} />
                    </div>
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                    <div>
                      <label style={{ display: 'block', fontSize: '0.825rem', fontWeight: 600, color: '#374151', marginBottom: 6 }}>Giờ bắt đầu *</label>
                      <input type="time" required value={form.start_time}
                        onChange={e => setForm({ ...form, start_time: e.target.value })}
                        style={{ width: '100%', padding: '10px 14px', border: '1.5px solid #e2e8f0', borderRadius: 10, fontSize: '0.875rem', outline: 'none', boxSizing: 'border-box', background: '#fff' }} />
                    </div>
                    <div>
                      <label style={{ display: 'block', fontSize: '0.825rem', fontWeight: 600, color: '#374151', marginBottom: 6 }}>Giờ kết thúc *</label>
                      <input type="time" required value={form.end_time}
                        onChange={e => setForm({ ...form, end_time: e.target.value })}
                        style={{ width: '100%', padding: '10px 14px', border: '1.5px solid #e2e8f0', borderRadius: 10, fontSize: '0.875rem', outline: 'none', boxSizing: 'border-box', background: '#fff' }} />
                    </div>
                  </div>

                  {loadingSlots && <p style={{ color: '#94a3b8', fontSize: '0.875rem' }}>Đang kiểm tra slot...</p>}
                  {!loadingSlots && bookedSlots.length > 0 && (
                    <div style={{ background: '#fef3c7', border: '1px solid #fcd34d', borderRadius: 10, padding: '10px 14px', fontSize: '0.875rem', color: '#92400e' }}>
                      ⚠️ Slot đã đặt: <strong>{bookedSlots.join(', ')}</strong>
                    </div>
                  )}

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                    <div>
                      <label style={{ display: 'block', fontSize: '0.825rem', fontWeight: 600, color: '#374151', marginBottom: 6 }}>Mục đích *</label>
                      <input type="text" required placeholder="Họp team, phỏng vấn..." value={form.purpose}
                        onChange={e => setForm({ ...form, purpose: e.target.value })}
                        style={{ width: '100%', padding: '10px 14px', border: '1.5px solid #e2e8f0', borderRadius: 10, fontSize: '0.875rem', outline: 'none', boxSizing: 'border-box', background: '#fff' }} />
                    </div>
                    <div>
                      <label style={{ display: 'block', fontSize: '0.825rem', fontWeight: 600, color: '#374151', marginBottom: 6 }}>Độ ưu tiên</label>
                      <select value={form.priority} onChange={e => setForm({ ...form, priority: e.target.value })}
                        style={{ width: '100%', padding: '10px 14px', border: '1.5px solid #e2e8f0', borderRadius: 10, fontSize: '0.875rem', outline: 'none', boxSizing: 'border-box', background: '#fff' }}>
                        <option value="normal">Bình thường</option>
                        <option value="high">Cao</option>
                        <option value="urgent">Khẩn cấp</option>
                      </select>
                    </div>
                  </div>

                  <div>
                    <label style={{ display: 'block', fontSize: '0.825rem', fontWeight: 600, color: '#374151', marginBottom: 6 }}>Ghi chú</label>
                    <textarea value={form.notes} placeholder="Thông tin bổ sung..."
                      onChange={e => setForm({ ...form, notes: e.target.value })}
                      style={{ width: '100%', padding: '10px 14px', border: '1.5px solid #e2e8f0', borderRadius: 10, fontSize: '0.875rem', outline: 'none', boxSizing: 'border-box', background: '#fff', resize: 'vertical', minHeight: 80 }} />
                  </div>

                  <button type="submit" disabled={submitting} style={{
                    padding: '12px', borderRadius: 10, border: 'none',
                    background: 'linear-gradient(135deg, #2563eb, #1d4ed8)',
                    color: '#fff', fontSize: '0.9rem', fontWeight: 700, cursor: 'pointer',
                    boxShadow: '0 4px 14px rgba(37,99,235,0.3)',
                    opacity: submitting ? 0.6 : 1,
                  }}>
                    {submitting ? 'Đang gửi...' : '📅 Gửi yêu cầu đặt phòng'}
                  </button>
                </form>
              </div>
            </div>
          )}
        </div>
      )}

      {tab === 'bookings' && (
        <div>
          {bookings.length === 0 ? (
            <div style={{ background: '#fff', borderRadius: 16, padding: '64px 32px', textAlign: 'center', boxShadow: '0 1px 4px rgba(0,0,0,0.06)' }}>
              <div style={{ fontSize: '3rem', marginBottom: 16 }}>🏢</div>
              <h3 style={{ fontWeight: 700, color: '#0f172a', marginBottom: 8 }}>Chưa có đặt phòng nào</h3>
              <p style={{ color: '#94a3b8', fontSize: '0.875rem' }}>Hãy đặt một phòng họp ngay!</p>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              {bookings.map(b => (
                <div key={b._id || b.booking_id} style={{
                  background: '#fff', borderRadius: 14,
                  boxShadow: '0 1px 4px rgba(0,0,0,0.06), 0 4px 12px rgba(0,0,0,0.04)',
                  padding: '18px 24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 16,
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                    <div style={{ width: 44, height: 44, borderRadius: 12, background: '#f1f5f9', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '1.2rem' }}>🏢</div>
                    <div>
                      <div style={{ fontWeight: 700, color: '#0f172a', fontSize: '0.95rem' }}>{b.room_name}</div>
                      <div style={{ color: '#64748b', fontSize: '0.8rem', marginTop: 3 }}>
                        📅 {b.meeting_date} · ⏰ {b.start_time} – {b.end_time}
                      </div>
                      <div style={{ color: '#64748b', fontSize: '0.8rem', marginTop: 2 }}>📝 {b.purpose}</div>
                    </div>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexShrink: 0 }}>
                    <StatusBadge s={b.status} />
                    {b.status === 'pending' && (
                      <button onClick={() => handleCancel(b.booking_id || b._id)} style={{
                        padding: '7px 14px', borderRadius: 8, border: '1.5px solid #fca5a5',
                        background: '#fff', color: '#dc2626', fontSize: '0.8rem', fontWeight: 600, cursor: 'pointer',
                      }}>Hủy</button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
