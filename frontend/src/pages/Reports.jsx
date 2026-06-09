import { useState, useEffect } from 'react'
import API from '../utils/api'

export default function Reports() {
  const [reports, setReports] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => { fetchReports() }, [])

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
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-6 py-8">

        <div className="mb-8">
          <h1 className="text-2xl font-bold text-gray-900">Reports</h1>
          <p className="text-gray-500 mt-1">View and download your vulnerability assessment reports</p>
        </div>

        <div className="bg-white rounded-2xl border border-gray-200 shadow-sm overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-100 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 bg-gray-50 rounded-lg flex items-center justify-center">
                <span>📄</span>
              </div>
              <h2 className="text-gray-900 font-semibold">Generated Reports</h2>
            </div>
            <span className="text-gray-400 text-sm">{reports.length} reports</span>
          </div>

          {loading ? (
            <div className="text-center py-16">
              <div className="text-4xl mb-3">⏳</div>
              <p className="text-gray-400">Loading reports...</p>
            </div>
          ) : reports.length === 0 ? (
            <div className="text-center py-16">
              <div className="text-4xl mb-3">📄</div>
              <p className="text-gray-500 font-medium">No reports yet</p>
              <p className="text-gray-400 text-sm mt-1">Complete a scan and export a PDF to see it here</p>
            </div>
          ) : (
            <div className="divide-y divide-gray-50">
              {reports.map((report) => (
                <div key={report.id} className="px-6 py-5 flex items-center justify-between hover:bg-gray-50 transition">
                  <div className="flex items-center gap-4">
                    <div className="w-10 h-10 bg-red-50 rounded-xl flex items-center justify-center border border-red-100">
                      <span>📋</span>
                    </div>
                    <div>
                      <p className="text-gray-900 font-medium text-sm">{report.report_name}</p>
                      <p className="text-gray-400 text-xs mt-0.5">{report.target_url}</p>
                      <p className="text-gray-300 text-xs mt-0.5">
                        {new Date(report.generated_at).toLocaleString()}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="bg-green-50 text-green-700 border border-green-200 text-xs font-medium px-2.5 py-1 rounded-full">
                      {report.format}
                    </span>
                    <button className="bg-blue-50 hover:bg-blue-100 text-blue-700 text-xs font-medium px-4 py-2 rounded-lg transition border border-blue-200">
                      Download
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}