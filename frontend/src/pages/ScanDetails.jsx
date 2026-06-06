import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { io } from 'socket.io-client'
import {
  PieChart, Pie, Cell, Tooltip,
  BarChart, Bar, XAxis, YAxis,
  CartesianGrid, ResponsiveContainer, Legend
} from 'recharts'
import API from '../utils/api'
import SeverityBadge from '../components/SeverityBadge'
import jsPDF from 'jspdf'
import html2canvas from 'html2canvas'

const COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
  INFO: '#6b7280'
}

export default function ScanDetails() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [scan, setScan] = useState(null)
  const [findings, setFindings] = useState([])
  const [summary, setSummary] = useState([])
  const [liveFeed, setLiveFeed] = useState([])
  const [filter, setFilter] = useState('ALL')
  const [exporting, setExporting] = useState(false)

  useEffect(() => {
    fetchScan()
    fetchFindings()
    fetchSummary()
    setupSocket()
  }, [id])

  const fetchScan = async () => {
    const res = await API.get(`/scans/${id}`)
    setScan(res.data)
  }

  const fetchFindings = async () => {
    const res = await API.get(`/scans/${id}/findings`)
    setFindings(res.data)
  }

  const fetchSummary = async () => {
    const res = await API.get(`/scans/${id}/summary`)
    setSummary(res.data)
  }

  const setupSocket = () => {
    const socket = io('http://localhost:5000')
    socket.emit('join_scan', { scan_id: id })

    socket.on('new_finding', (data) => {
      if (data.scan_id == id) {
        setFindings(prev => [...prev, data.finding])
        setLiveFeed(prev => [`🚨 ${data.finding.vulnerability_type} found at ${data.finding.url}`, ...prev.slice(0, 9)])
      }
    })

    socket.on('scan_progress', (data) => {
      if (data.scan_id == id) {
        setLiveFeed(prev => [`⚡ Running: ${data.module}...`, ...prev.slice(0, 9)])
      }
    })

    socket.on('scan_complete', (data) => {
      if (data.scan_id == id) {
        setLiveFeed(prev => [`✅ Scan complete! ${data.total_findings} findings`, ...prev])
        fetchScan()
        fetchSummary()
      }
    })

    return () => socket.disconnect()
  }

  const exportPDF = async () => {
    setExporting(true)
    const element = document.getElementById('scan-report')
    const canvas = await html2canvas(element, { backgroundColor: '#030712' })
    const imgData = canvas.toDataURL('image/png')
    const pdf = new jsPDF('p', 'mm', 'a4')
    const width = pdf.internal.pageSize.getWidth()
    const height = (canvas.height * width) / canvas.width
    pdf.addImage(imgData, 'PNG', 0, 0, width, height)
    pdf.save(`scan-report-${id}.pdf`)
    setExporting(false)
  }

  const filteredFindings = filter === 'ALL'
    ? findings
    : findings.filter(f => f.severity === filter)

  const chartData = summary.map(s => ({
    name: s.severity,
    value: s.count,
    fill: COLORS[s.severity]
  }))

  if (!scan) return (
    <div className="text-center py-20 text-gray-400">Loading scan details...</div>
  )

  return (
    <div className="max-w-7xl mx-auto px-6 py-8" id="scan-report">

      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <button
            onClick={() => navigate('/')}
            className="text-gray-400 hover:text-white text-sm mb-2 block"
          >
            ← Back to Dashboard
          </button>
          <h1 className="text-2xl font-bold text-white">{scan.scan_name}</h1>
          <p className="text-blue-400 text-sm mt-1">{scan.target_url}</p>
        </div>
        <button
          onClick={exportPDF}
          disabled={exporting}
          className="bg-green-600 hover:bg-green-700 text-white px-6 py-3 rounded-lg font-semibold transition disabled:opacity-50"
        >
          {exporting ? '⏳ Exporting...' : '📄 Export PDF'}
        </button>
      </div>

      {/* Charts */}
      {chartData.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
            <h3 className="text-white font-semibold mb-4">Findings by Severity</h3>
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie data={chartData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label>
                  {chartData.map((entry, index) => (
                    <Cell key={index} fill={entry.fill} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151' }}
                  labelStyle={{ color: '#fff' }}
                />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
            <h3 className="text-white font-semibold mb-4">Severity Distribution</h3>
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="name" stroke="#9ca3af" />
                <YAxis stroke="#9ca3af" />
                <Tooltip
                  contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151' }}
                  labelStyle={{ color: '#fff' }}
                />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {chartData.map((entry, index) => (
                    <Cell key={index} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Findings Table */}
        <div className="lg:col-span-2 bg-gray-900 border border-gray-800 rounded-2xl overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
            <h2 className="text-white font-semibold">🚨 Findings ({findings.length})</h2>
            <div className="flex gap-2">
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(f => (
                <button
                  key={f}
                  onClick={() => setFilter(f)}
                  className={`text-xs px-3 py-1.5 rounded-lg transition ${
                    filter === f
                      ? 'bg-blue-600 text-white'
                      : 'bg-gray-800 text-gray-400 hover:text-white'
                  }`}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>

          <div className="divide-y divide-gray-800 max-h-96 overflow-y-auto">
            {filteredFindings.length === 0 ? (
              <div className="text-center py-8 text-gray-400">No findings yet</div>
            ) : (
              filteredFindings.map((finding, i) => (
                <div key={i} className="px-6 py-4 hover:bg-gray-800/30 transition">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <SeverityBadge severity={finding.severity} />
                        <span className="text-white text-sm font-medium">
                          {finding.vulnerability_type}
                        </span>
                      </div>
                      <p className="text-blue-400 text-xs truncate">{finding.url}</p>
                      <p className="text-gray-400 text-xs mt-1">{finding.evidence}</p>
                    </div>
                    <div className="text-right shrink-0">
                      <span className="text-gray-500 text-xs">CVSS</span>
                      <p className="text-white font-bold">{finding.cvss_score}</p>
                    </div>
                  </div>
                  <div className="mt-2 bg-gray-800/50 rounded-lg p-2">
                    <p className="text-green-400 text-xs">💡 {finding.recommendation}</p>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Live Feed */}
        <div className="bg-gray-900 border border-gray-800 rounded-2xl overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-800">
            <h2 className="text-white font-semibold">⚡ Live Feed</h2>
          </div>
          <div className="p-4 space-y-2 max-h-96 overflow-y-auto">
            {liveFeed.length === 0 ? (
              <p className="text-gray-500 text-sm text-center py-4">
                Waiting for scan activity...
              </p>
            ) : (
              liveFeed.map((msg, i) => (
                <div key={i} className="bg-gray-800/50 rounded-lg px-3 py-2">
                  <p className="text-gray-300 text-xs">{msg}</p>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  )
}