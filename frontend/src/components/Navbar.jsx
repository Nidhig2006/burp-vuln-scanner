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
    <nav className="bg-gray-900 border-b border-gray-800 px-6 py-4">
      <div className="max-w-7xl mx-auto flex items-center justify-between">

        <Link to="/" className="flex items-center gap-2">
          <span className="text-2xl">🔍</span>
          <span className="text-white font-bold text-lg">BurpVulnScanner</span>
        </Link>

        <div className="flex items-center gap-6">
          <Link to="/" className="text-gray-400 hover:text-white transition text-sm">
            Dashboard
          </Link>
          <Link to="/reports" className="text-gray-400 hover:text-white transition text-sm">
            Reports
          </Link>
          <div className="flex items-center gap-3">
            <span className="text-gray-400 text-sm">
              👤 {user?.username}
              <span className="ml-2 bg-blue-900 text-blue-300 text-xs px-2 py-0.5 rounded-full">
                {user?.role}
              </span>
            </span>
            <button
              onClick={handleLogout}
              className="bg-red-600 hover:bg-red-700 text-white text-sm px-4 py-2 rounded-lg transition"
            >
              Logout
            </button>
          </div>
        </div>

      </div>
    </nav>
  )
}