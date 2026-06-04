import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuth } from './context/AuthContext'
import Login from './pages/Login'
import Register from './pages/Register'
import Dashboard from './pages/Dashboard'
import ScanDetails from './pages/ScanDetails'
import Reports from './pages/Reports'
import Navbar from './components/Navbar'

function PrivateRoute({ children }) {
  const { user } = useAuth()
  return user ? children : <Navigate to="/login" />
}

export default function App() {
  return (
    <div className="min-h-screen bg-gray-950 text-white">
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/" element={
          <PrivateRoute>
            <Navbar />
            <Dashboard />
          </PrivateRoute>
        } />
        <Route path="/scan/:id" element={
          <PrivateRoute>
            <Navbar />
            <ScanDetails />
          </PrivateRoute>
        } />
        <Route path="/reports" element={
          <PrivateRoute>
            <Navbar />
            <Reports />
          </PrivateRoute>
        } />
      </Routes>
    </div>
  )
}
