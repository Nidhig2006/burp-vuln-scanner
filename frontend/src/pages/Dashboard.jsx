import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import API from '../utils/api'

export default function Dashboard() {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [scanForm, setScanForm] = useState({ target_url: '', scan_name: '' })
  const [scanning, setScanning] = useState(false)
  const [error, setError] = useState('')
  const navigate = useNavigate()

  useEffect(() => {
    fetchScans()
  }, [])

  const fetchScans = async () => {
    try {
      const res = await API.get('/scans')
      setScans(res.data)
    } catch (err) {
      setError('Failed to load scans')
    } finally {
      setLoading(false)
    }
  }

  const handleStartScan = async (e) => {
    e.preventDefault()
    setScanning(true)
    setError('')
    try {
      const res = await API.post('/scans/start', scanForm)
      setScanForm({ target_url: '', scan_name: '' })
      fetchScans()
      navigate(`/scan/${res.data.scan_id}`)
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to start scan')
    } finally {
      setScanning(false)
    }
  }

  const statusColor = (status) => {
    if (status === 'running') return 'text-yellow-400'
    if (status === 'completed') return 'text-green-400'
    return 'text-red-400'
  }

  const statusDot = (status) => {
    if (status === 'running') return 'bg-yellow-400 animate-pulse'
    if (status === 'completed') return 'bg-green-400'
    return 'bg-red-400'
  }

  return (
    <div className="max-w-7xl mx-auto px-6 py-8">

      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white">Dashboard</h1>
        <p className="text-gray-400 mt-1">Manage and monitor your vulnerability scans</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <StatCard label="Total Scans" value={scans.length} icon="🔍" color="blue" />
        <StatCard label="Running" value={scans.filter(s => s.status === 'running').length} icon="⚡" color="yellow" />
        <StatCard label="Completed" value={scans.filter(s => s.status === 'completed').length} icon="✅" color="green" />
        <StatCard label="Total Findings" value={scans.reduce((a, b) => a + (b.total_findings || 0), 0)} icon="🚨" color="red" />
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 mb-8">
        <h2 className="text-white font-semibold text-lg mb-4">🚀 Start New Scan</h2>

        {error && (
          <div className="bg-red-900/50 border border-red-500 text-red-300 px-4 py-3 rounded-lg mb-4 text-sm">
            {error}
          </div>
        )}

        <form onSubmit={handleStartScan} className="flex flex-col md:flex-row gap-4">
          <input
            type="url"
            placeholder="https://target-website.com"
            value={scanForm.target_url}
            onChange={(e) => setScanForm({ ...scanForm, target_url: e.target.value })}
            className="flex-1 bg-gray-800 border border-gray-700 text-white rounded-lg px-4 py-3 focus:outline-none focus:border-blue-500 transition"
            required
          />
          <input
            type="text"
            placeholder="Scan name (optional)"
            value={scanForm.scan_name}
            onChange={(e) => setScanForm({ ...scanForm, scan_name: e.target.value })}
            className="flex-1 bg-gray-800 border border-gray-700 text-white rounded-lg px-4 py-3 focus:outline-none focus:border-blue-500 transition"
          />
          <button
            type="submit"
            disabled={scanning}
            className="bg-blue-600 hover:bg-blue-700 text-white font-semibold px-8 py-3 rounded-lg transition disabled:opacity-50 whitespace-nowrap"
          >
            {scanning ? '⏳ Starting...' : '▶ Start Scan'}
          </button>
        </form>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-2xl overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800">
          <h2 className="text-white font-semibold text-lg">📋 Recent Scans</h2>
        </div>

        {loading ? (
          <div className="text-center py-12 text-gray-400">Loading scans...</div>
        ) : scans.length === 0 ? (
          <div className="text-center py-12 text-gray-400">
            No scans yet. Start your first scan above!
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-800/50">
                <tr>
                  <th className="text-left text-gray-400 text-sm px-6 py-3">Scan Name</th>
                  <th className="text-left text-gray-400 text-sm px-6 py-3">Target URL</th>
                  <th className="text-left text-gray-400 text-sm px-6 py-3">Status</th>
                  <th className="text-left text-gray-400 text-sm px-6 py-3">Findings</th>
                  <th className="text-left text-gray-400 text-sm px-6 py-3">Started</th>
                  <th className="text-left text-gray-400 text-sm px-6 py-3">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {scans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-gray-800/30 transition">
                    <td className="px-6 py-4 text-white text-sm font-medium">
                      {scan.scan_name || 'Unnamed Scan'}
                    </td>
                    <td className="px-6 py-4 text-blue-400 text-sm truncate max-w-xs">
                      {scan.target_url}
                    </td>
                    <td className="px-6 py-4">
                      <span className={`flex items-center gap-2 text-sm ${statusColor(scan.status)}`}>
                        <span className={`w-2 h-2 rounded-full ${statusDot(scan.status)}`}></span>
                        {scan.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-white text-sm">
                      {scan.total_findings || 0}
                    </td>
                    <td className="px-6 py-4 text-gray-400 text-sm">
                      {new Date(scan.started_at).toLocaleString()}
                    </td>
                    <td className="px-6 py-4">
                      <button
                        onClick={() => navigate(`/scan/${scan.id}`)}
                        className="bg-blue-600/20 hover:bg-blue-600/40 text-blue-400 text-sm px-3 py-1.5 rounded-lg transition"
                      >
                        View →
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

function StatCard({ label, value, icon, color }) {
  const colors = {
    blue: 'border-blue-800 bg-blue-900/20',
    yellow: 'border-yellow-800 bg-yellow-900/20',
    green: 'border-green-800 bg-green-900/20',
    red: 'border-red-800 bg-red-900/20',
  }
  return (
    <div className={`border rounded-2xl p-5 ${colors[color]}`}>
      <div className="text-2xl mb-2">{icon}</div>
      <div className="text-3xl font-bold text-white">{value}</div>
      <div className="text-gray-400 text-sm mt-1">{label}</div>
    </div>
  )
}