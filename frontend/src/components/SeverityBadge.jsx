export default function SeverityBadge({ severity }) {
  const styles = {
    CRITICAL: 'bg-red-100 text-red-700 border border-red-200',
    HIGH:     'bg-orange-100 text-orange-700 border border-orange-200',
    MEDIUM:   'bg-yellow-100 text-yellow-700 border border-yellow-200',
    LOW:      'bg-blue-100 text-blue-700 border border-blue-200',
    INFO:     'bg-gray-100 text-gray-600 border border-gray-200',
  }
  const icons = {
    CRITICAL: '🔴',
    HIGH:     '🟠',
    MEDIUM:   '🟡',
    LOW:      '🔵',
    INFO:     '⚪',
  }
  return (
    <span className={`inline-flex items-center gap-1 text-xs font-semibold px-2.5 py-1 rounded-full ${styles[severity] || styles.INFO}`}>
      {icons[severity]} {severity}
    </span>
  )
}