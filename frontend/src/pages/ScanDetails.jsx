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
  HIGH:     '#f97316',
  MEDIUM:   '#eab308',
  LOW:      '#3b82f6',
  INFO:     '#9ca3af'
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
        setLiveFeed(prev => [
          { type: 'finding', msg: `${data.finding.vulnerability_type} at ${data.finding.url}`, time: new Date().toLocaleTimeString() },
          ...prev.slice(0, 9)
        ])
      }
    })
    socket.on('scan_progress', (data) => {
      if (data.scan_id == id) {
        setLiveFeed(prev => [
          { type: 'progress', msg: `Running: ${data.module}`, time: new Date().toLocaleTimeString() },
          ...prev.slice(0, 9)
        ])
      }
    })
    socket.on('scan_complete', (data) => {
      if (data.scan_id == id) {
        setLiveFeed(prev => [
          { type: 'complete', msg: `Scan complete! ${data.total_findings} findings`, time: new Date().toLocaleTimeString() },
          ...prev
        ])
        fetchScan()
        fetchSummary()
      }
    })
    return () => socket.disconnect()
  }

  const exportPDF = async () => {
    setExporting(true)
    const element = document.getElementById('scan-report')
    const canvas = await html2canvas(element, { backgroundColor: '#ffffff' })
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

  const severityCount = (s) => findings.filter(f => f.severity === s).length

  if (!scan) return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center">
      <div className="text-center">
        <div className="text-4xl mb-3">⏳</div>
        <p className="text-gray-500">Loading scan details...</p>
      </div>
    </div>
  )

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-6 py-8" id="scan-report">

        {/* Header */}
        <div className="flex items-start justify-between mb-8">
          <div>
            <button
              onClick={() => navigate('/')}
              className="text-gray-400 hover:text-gray-600 text-sm mb-3 flex items-center gap-1 transition"
            >
              ← Back to Dashboard
            </button>
            <h1 className="text-2xl font-bold text-gray-900">{scan.scan_name}</h1>
            <div className="flex items-center gap-3 mt-2">
              <span className="text-blue-600 text-sm">{scan.target_url}</span>
              <span className={`inline-flex items-center gap-1 text-xs font-medium px-2 py-1 rounded-full ${
                scan.status === 'completed'
                  ? 'bg-green-50 text-green-700 border border-green-200'
                  : 'bg-amber-50 text-amber-700 border border-amber-200'
              }`}>
                <span className={`w-1.5 h-1.5 rounded-full ${scan.status === 'completed' ? 'bg-green-500' : 'bg-amber-500 animate-pulse'}`}></span>
                {scan.status}
              </span>
            </div>
          </div>
          <button
            onClick={exportPDF}
            disabled={exporting}
            className="bg-green-600 hover:bg-green-700 text-white px-6 py-3 rounded-xl font-semibold transition shadow-sm disabled:opacity-50 text-sm flex items-center gap-2"
          >
            {exporting ? '⏳ Exporting...' : '📄 Export PDF'}
          </button>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
          {[
            { label: 'Critical', count: severityCount('CRITICAL'), color: 'red' },
            { label: 'High',     count: severityCount('HIGH'),     color: 'orange' },
            { label: 'Medium',   count: severityCount('MEDIUM'),   color: 'yellow' },
            { label: 'Low',      count: severityCount('LOW'),      color: 'blue' },
          ].map(({ label, count, color }) => (
            <div key={label} className={`bg-white rounded-2xl border p-5 shadow-sm border-${color}-100`}>
              <div className={`text-3xl font-bold text-${color}-600`}>{count}</div>
              <div className="text-gray-500 text-sm font-medium mt-1">{label} Severity</div>
            </div>
          ))}
        </div>

        {/* Charts */}
        {chartData.length > 0 && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            <div className="bg-white rounded-2xl border border-gray-200 shadow-sm p-6">
              <h3 className="text-gray-900 font-semibold mb-4">Findings by Severity</h3>
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie data={chartData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label>
                    {chartData.map((entry, i) => (
                      <Cell key={i} fill={entry.fill} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ borderRadius: '12px', border: '1px solid #e5e7eb' }} />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </div>

            <div className="bg-white rounded-2xl border border-gray-200 shadow-sm p-6">
              <h3 className="text-gray-900 font-semibold mb-4">Severity Distribution</h3>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#f3f4f6" />
                  <XAxis dataKey="name" stroke="#9ca3af" tick={{ fontSize: 12 }} />
                  <YAxis stroke="#9ca3af" tick={{ fontSize: 12 }} />
                  <Tooltip contentStyle={{ borderRadius: '12px', border: '1px solid #e5e7eb' }} />
                  <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                    {chartData.map((entry, i) => (
                      <Cell key={i} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

          {/* Findings */}
          <div className="lg:col-span-2 bg-white rounded-2xl border border-gray-200 shadow-sm overflow-hidden">
            <div className="px-6 py-4 border-b border-gray-100 flex items-center justify-between">
              <h2 className="text-gray-900 font-semibold">
                🚨 Findings <span className="text-gray-400 font-normal text-sm">({findings.length})</span>
              </h2>
              <div className="flex gap-1.5">
                {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(f => (
                  <button
                    key={f}
                    onClick={() => setFilter(f)}
                    className={`text-xs px-3 py-1.5 rounded-lg transition font-medium ${
                      filter === f
                        ? 'bg-blue-600 text-white'
                        : 'bg-gray-100 text-gray-500 hover:bg-gray-200'
                    }`}
                  >
                    {f}
                  </button>
                ))}
              </div>
            </div>

            <div className="divide-y divide-gray-50 max-h-[500px] overflow-y-auto">
              {filteredFindings.length === 0 ? (
                <div className="text-center py-12">
                  <div className="text-3xl mb-2">🔍</div>
                  <p className="text-gray-400">No findings yet</p>
                </div>
              ) : (
                filteredFindings.map((finding, i) => (
                  <div key={i} className="px-6 py-4 hover:bg-gray-50 transition">
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1.5">
                          <SeverityBadge severity={finding.severity} />
                          <span className="text-gray-900 text-sm font-semibold">
                            {finding.vulnerability_type}
                          </span>
                        </div>
                        <p className="text-blue-500 text-xs truncate mb-1">{finding.url}</p>
                        <p className="text-gray-500 text-xs">{finding.evidence}</p>
                      </div>
                      <div className="text-right shrink-0">
                        <div className="text-xs text-gray-400">CVSS</div>
                        <div className="text-lg font-bold text-gray-900">{finding.cvss_score}</div>
                      </div>
                    </div>
                    <div className="mt-2.5 bg-green-50 border border-green-100 rounded-lg px-3 py-2">
                      <p className="text-green-700 text-xs">💡 {finding.recommendation}</p>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Live Feed */}
          <div className="bg-white rounded-2xl border border-gray-200 shadow-sm overflow-hidden">
            <div className="px-6 py-4 border-b border-gray-100">
              <h2 className="text-gray-900 font-semibold">⚡ Live Feed</h2>
            </div>
            <div className="p-4 space-y-2 max-h-[500px] overflow-y-auto">
              {liveFeed.length === 0 ? (
                <div className="text-center py-8">
                  <div className="text-2xl mb-2">📡</div>
                  <p className="text-gray-400 text-sm">Waiting for scan activity...</p>
                </div>
              ) : (
                liveFeed.map((item, i) => (
                  <div key={i} className={`rounded-xl px-3 py-2.5 border ${
                    item.type === 'finding'  ? 'bg-red-50 border-red-100' :
                    item.type === 'complete' ? 'bg-green-50 border-green-100' :
                    'bg-blue-50 border-blue-100'
                  }`}>
                    <p className={`text-xs font-medium ${
                      item.type === 'finding'  ? 'text-red-700' :
                      item.type === 'complete' ? 'text-green-700' :
                      'text-blue-700'
                    }`}>
                      {item.type === 'finding'  ? '🚨' :
                       item.type === 'complete' ? '✅' : '⚡'} {item.msg}
                    </p>
                    <p className="text-gray-400 text-xs mt-0.5">{item.time}</p>
                  </div>
                ))
              )}
            </div>
          </div>

        </div>
      </div>
    </div>
  )
}