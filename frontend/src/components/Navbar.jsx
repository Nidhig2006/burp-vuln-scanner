import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

export default function Navbar() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  return (
    <nav className="bg-white border-b border-gray-200 px-6 py-4 sticky top-0 z-50 shadow-sm">
      <div className="max-w-7xl mx-auto flex items-center justify-between">

        <Link to="/" className="flex items-center gap-3">
          <div className="w-9 h-9 bg-blue-600 rounded-xl flex items-center justify-center shadow-sm">
            <span className="text-lg">🔍</span>
          </div>
          <span className="text-gray-900 font-bold text-lg tracking-tight">
            BurpVulnScanner
          </span>
        </Link>

        <div className="flex items-center gap-8">
          <Link to="/" className="text-gray-500 hover:text-gray-900 transition text-sm font-medium">
            Dashboard
          </Link>
          <Link to="/reports" className="text-gray-500 hover:text-gray-900 transition text-sm font-medium">
            Reports
          </Link>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 bg-gray-50 border border-gray-200 rounded-xl px-3 py-2">
            <div className="w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center">
              <span className="text-xs">👤</span>
            </div>
            <span className="text-gray-700 text-sm font-medium">{user?.username}</span>
            <span className="bg-blue-100 text-blue-700 text-xs px-2 py-0.5 rounded-full font-medium">
              {user?.role}
            </span>
          </div>
          <button
            onClick={handleLogout}
            className="bg-red-50 hover:bg-red-100 text-red-600 text-sm px-4 py-2 rounded-xl transition font-medium border border-red-200"
          >
            Logout
          </button>
        </div>

      </div>
    </nav>
  )
}