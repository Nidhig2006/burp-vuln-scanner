export default function SeverityBadge({ severity }) {
  const colors = {
    CRITICAL: 'bg-red-900/50 text-red-300 border border-red-700',
    HIGH:     'bg-orange-900/50 text-orange-300 border border-orange-700',
    MEDIUM:   'bg-yellow-900/50 text-yellow-300 border border-yellow-700',
    LOW:      'bg-blue-900/50 text-blue-300 border border-blue-700',
    INFO:     'bg-gray-800 text-gray-300 border border-gray-600',
  }
  return (
    <span className={`text-xs font-semibold px-2.5 py-1 rounded-full ${colors[severity] || colors.INFO}`}>
      {severity}
    </span>
  )
}