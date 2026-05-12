import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext.jsx';
import { ThemeProvider } from './context/ThemeContext.jsx';
import Login from './pages/Login.jsx';
import Dashboard from './pages/Dashboard.jsx';
import LeaveRequest from './pages/LeaveRequest.jsx';
import MyLeaves from './pages/MyLeaves.jsx';
import Approvals from './pages/Approvals.jsx';
import MeetingRoom from './pages/MeetingRoom.jsx';
import Settings from './pages/Settings.jsx';
import Users from './pages/Users.jsx';
import Profile from './pages/Profile.jsx';
import Layout from './components/Layout.jsx';

const ProtectedRoute = ({ children, roles }) => {
  const { user, loading } = useAuth();
  if (loading) return <div className="loading">Loading...</div>;
  if (!user) return <Navigate to="/login" replace />;
  if (roles && !roles.includes(user.role)) return <Navigate to="/" replace />;
  return children;
};

function AppRoutes() {
  const { user } = useAuth();
  return (
    <Routes>
      <Route path="/login" element={user ? <Navigate to="/" replace /> : <Login />} />
      <Route path="/" element={<ProtectedRoute><Layout /></ProtectedRoute>}>
        <Route index element={<Dashboard />} />
        <Route path="leave/new" element={<LeaveRequest />} />
        <Route path="leaves" element={<MyLeaves />} />
        <Route path="approvals" element={<Approvals />} />
        <Route path="meetings" element={<MeetingRoom />} />
        <Route path="settings" element={<ProtectedRoute roles={['hr']}><Settings /></ProtectedRoute>} />
        <Route path="users" element={<ProtectedRoute roles={['hr']}><Users /></ProtectedRoute>} />
        <Route path="profile" element={<Profile />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <ThemeProvider>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </ThemeProvider>
    </BrowserRouter>
  );
}
