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

  useEffect(() => { fetchScans() }, [])

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

  const statusConfig = {
    running:   { color: 'text-amber-600', bg: 'bg-amber-50 border-amber-200', dot: 'bg-amber-500 animate-pulse' },
    completed: { color: 'text-green-600', bg: 'bg-green-50 border-green-200', dot: 'bg-green-500' },
    stopped:   { color: 'text-red-600',   bg: 'bg-red-50 border-red-200',     dot: 'bg-red-500' },
  }

  const totalFindings = scans.reduce((a, b) => a + (b.total_findings || 0), 0)

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-6 py-8">

        {/* Header */}
        <div className="mb-8">
          <h1 className="text-2xl font-bold text-gray-900">Security Dashboard</h1>
          <p className="text-gray-500 mt-1">Monitor and manage your vulnerability scans</p>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
          <StatCard icon="🔍" label="Total Scans" value={scans.length} color="blue" />
          <StatCard icon="⚡" label="Running" value={scans.filter(s => s.status === 'running').length} color="amber" />
          <StatCard icon="✅" label="Completed" value={scans.filter(s => s.status === 'completed').length} color="green" />
          <StatCard icon="🚨" label="Total Findings" value={totalFindings} color="red" />
        </div>

        {/* New Scan */}
        <div className="bg-white rounded-2xl border border-gray-200 shadow-sm p-6 mb-8">
          <div className="flex items-center gap-3 mb-5">
            <div className="w-9 h-9 bg-blue-50 rounded-xl flex items-center justify-center">
              <span>🚀</span>
            </div>
            <div>
              <h2 className="text-gray-900 font-semibold">Start New Scan</h2>
              <p className="text-gray-400 text-xs">Enter a target URL to begin vulnerability scanning</p>
            </div>
          </div>

          {error && (
            <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-xl mb-4 text-sm">
              ⚠️ {error}
            </div>
          )}

          <form onSubmit={handleStartScan} className="flex flex-col md:flex-row gap-3">
            <input
              type="url"
              placeholder="https://target-website.com"
              value={scanForm.target_url}
              onChange={(e) => setScanForm({ ...scanForm, target_url: e.target.value })}
              className="flex-1 border border-gray-200 rounded-xl px-4 py-3 text-gray-800 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition text-sm"
              required
            />
            <input
              type="text"
              placeholder="Scan name (optional)"
              value={scanForm.scan_name}
              onChange={(e) => setScanForm({ ...scanForm, scan_name: e.target.value })}
              className="flex-1 border border-gray-200 rounded-xl px-4 py-3 text-gray-800 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition text-sm"
            />
            <button
              type="submit"
              disabled={scanning}
              className="bg-blue-600 hover:bg-blue-700 text-white font-semibold px-8 py-3 rounded-xl transition shadow-sm disabled:opacity-50 whitespace-nowrap text-sm"
            >
              {scanning ? '⏳ Starting...' : '▶ Start Scan'}
            </button>
          </form>
        </div>

        {/* Scans Table */}
        <div className="bg-white rounded-2xl border border-gray-200 shadow-sm overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-100 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 bg-gray-50 rounded-lg flex items-center justify-center">
                <span>📋</span>
              </div>
              <h2 className="text-gray-900 font-semibold">Recent Scans</h2>
            </div>
            <span className="text-gray-400 text-sm">{scans.length} total</span>
          </div>

          {loading ? (
            <div className="text-center py-16">
              <div className="text-4xl mb-3">⏳</div>
              <p className="text-gray-400">Loading scans...</p>
            </div>
          ) : scans.length === 0 ? (
            <div className="text-center py-16">
              <div className="text-4xl mb-3">🔍</div>
              <p className="text-gray-500 font-medium">No scans yet</p>
              <p className="text-gray-400 text-sm mt-1">Start your first scan above</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gray-50 border-b border-gray-100">
                  <tr>
                    {['Scan Name', 'Target URL', 'Status', 'Findings', 'Started', 'Action'].map(h => (
                      <th key={h} className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider px-6 py-3">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-50">
                  {scans.map((scan) => {
                    const sc = statusConfig[scan.status] || statusConfig.stopped
                    return (
                      <tr key={scan.id} className="hover:bg-gray-50 transition">
                        <td className="px-6 py-4 text-gray-900 text-sm font-medium">
                          {scan.scan_name || 'Unnamed Scan'}
                        </td>
                        <td className="px-6 py-4">
                          <span className="text-blue-600 text-sm truncate max-w-xs block">
                            {scan.target_url}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <span className={`inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full border ${sc.bg} ${sc.color}`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${sc.dot}`}></span>
                            {scan.status}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <span className={`text-sm font-semibold ${scan.total_findings > 0 ? 'text-red-600' : 'text-gray-400'}`}>
                            {scan.total_findings || 0}
                          </span>
                        </td>
                        <td className="px-6 py-4 text-gray-400 text-sm">
                          {new Date(scan.started_at).toLocaleString()}
                        </td>
                        <td className="px-6 py-4">
                          <button
                            onClick={() => navigate(`/scan/${scan.id}`)}
                            className="bg-blue-50 hover:bg-blue-100 text-blue-700 text-xs font-medium px-3 py-1.5 rounded-lg transition border border-blue-200"
                          >
                            View Details →
                          </button>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function StatCard({ icon, label, value, color }) {
  const colors = {
    blue:  'bg-blue-50 border-blue-100',
    amber: 'bg-amber-50 border-amber-100',
    green: 'bg-green-50 border-green-100',
    red:   'bg-red-50 border-red-100',
  }
  const textColors = {
    blue:  'text-blue-700',
    amber: 'text-amber-700',
    green: 'text-green-700',
    red:   'text-red-700',
  }
  return (
    <div className={`rounded-2xl border p-5 ${colors[color]}`}>
      <div className="text-2xl mb-3">{icon}</div>
      <div className={`text-3xl font-bold ${textColors[color]}`}>{value}</div>
      <div className="text-gray-500 text-sm mt-1 font-medium">{label}</div>
    </div>
  )
}