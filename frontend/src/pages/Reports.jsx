import { useState, useEffect } from 'react'
import API from '../utils/api'

export default function Reports() {
  const [reports, setReports] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchReports()
  }, [])

  const fetchReports = async () => {
    try {
      const res = await API.get('/reports')
      setReports(res.data)
    } catch (err) {
      console.error('Failed to load reports')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="max-w-7xl mx-auto px-6 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white">Reports</h1>
        <p className="text-gray-400 mt-1">View and download your scan reports</p>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-2xl overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800">
          <h2 className="text-white font-semibold">📄 Generated Reports</h2>
        </div>

        {loading ? (
          <div className="text-center py-12 text-gray-400">Loading reports...</div>
        ) : reports.length === 0 ? (
          <div className="text-center py-12 text-gray-400">
            No reports yet. Complete a scan and export a PDF!
          </div>
        ) : (
          <div className="divide-y divide-gray-800">
            {reports.map((report) => (
              <div key={report.id} className="px-6 py-4 flex items-center justify-between hover:bg-gray-800/30 transition">
                <div>
                  <p className="text-white font-medium">{report.report_name}</p>
                  <p className="text-gray-400 text-sm mt-0.5">{report.target_url}</p>
                  <p className="text-gray-500 text-xs mt-1">
                    Generated: {new Date(report.generated_at).toLocaleString()}
                  </p>
                </div>
                <div className="flex items-center gap-3">
                  <span className="bg-green-900/50 text-green-300 border border-green-700 text-xs px-2.5 py-1 rounded-full">
                    {report.format}
                  </span>
                  <button className="bg-blue-600/20 hover:bg-blue-600/40 text-blue-400 text-sm px-4 py-2 rounded-lg transition">
                    Download
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}