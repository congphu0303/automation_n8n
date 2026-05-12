import axios from 'axios';

const API_BASE = '/api';

const api = axios.create({
  baseURL: API_BASE,
  headers: { 'Content-Type': 'application/json' },
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      window.location.href = '/login';
    }
    return Promise.reject(err);
  }
);

export const login = (data) => api.post('/auth/login', data);
export const register = (data) => api.post('/auth/register', data);
export const getMe = () => api.get('/auth/me');

export const getUsers = () => api.get('/users');
export const createUser = (data) => api.post('/users', data);
export const updateUser = (id, data) => api.put(`/users/${id}`, data);
export const deleteUser = (id) => api.delete(`/users/${id}`);

export const getLeaves = () => api.get('/leave');
export const getLeaveById = (id) => api.get(`/leave/${id}`);
export const submitLeave = (data) => api.post('/leave', data);
export const updateLeave = (id, data) => api.put(`/leave/${id}`, data);
export const cancelLeave = (id, reason) => api.post(`/leave/${id}/cancel`, { reason });
export const returnEarly = (id, actualReturnDate) => api.post(`/leave/${id}/return-early`, { actualReturnDate });
export const getLeavesForApproval = () => api.get('/leave/for-approval');
export const getPendingApprovals = () => api.get('/leave/pending-approvals');

export const approveLeaveById = (leaveId, action) => api.post('/approval/approve-by-id', { leaveId, action });
export const validateToken = (token) => api.get(`/approval/token/${token}`);
export const autoApproveCallback = (data) => api.post('/approval/auto-approve', data);

export const getRooms = () => api.get('/rooms');
export const getRoomSlots = (roomId, date) => api.get(`/rooms/${roomId}/slots`, { params: { date } });
export const getBookings = () => api.get('/meeting-room');
export const createBooking = async (data) => {
  const user = JSON.parse(localStorage.getItem('user') || '{}');
  const payload = {
    bookingId: 'BK-' + Date.now(),
    requesterId: user._id || user.id || '',
    requesterName: user.name || '',
    requesterEmail: user.email || '',
    department: user.department || '',
    roomId: data.room_id,
    roomName: data.room_name,
    roomCapacity: 0,
    meetingDate: data.meeting_date,
    startTime: data.start_time,
    endTime: data.end_time,
    durationMinutes: 60,
    purpose: data.purpose,
    attendees: data.attendees || 1,
    priority: data.priority || 'normal',
    notes: data.notes || '',
    equipmentNeeded: [],
    managerEmail: user.email || '',
  };
  return axios.post('https://n8n.internalautomation.io.vn/webhook/nhan-yeu-cau-dat-phong', payload);
};
export const cancelBooking = (bookingId, reason) => api.post('/meeting-room/cancel', { booking_id: bookingId, reason });
export const syncBookingStatus = (data) => api.post('/meeting-room/sync-status', data);

export const getManagerEmails = () => api.get('/settings/manager-emails');
export const updateManagerEmails = (data) => api.put('/settings/manager-emails', data);
export const lookupEmail = (department) => api.get('/settings/lookup', { params: { department } });

// Gmail OAuth2
export const getGmailAuthUrl = () => api.get('/gmail/auth-url');
export const getGmailStatus = () => api.get('/gmail/status');
export const disconnectGmail = () => api.post('/gmail/disconnect');

export default api;
