export function splitLinesOrComma(value) {
  return String(value || '').split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean)
}

export function splitLines(value) {
  return String(value || '').split(/\r?\n/).map((item) => item.trim()).filter(Boolean)
}

export function compactObject(object) {
  return Object.fromEntries(
    Object.entries(object).filter(([, value]) => value !== '' && value !== undefined && value !== null),
  )
}

export function normalizeBooleanValue(value, fallback = false) {
  if (value === undefined || value === null || value === '') return fallback
  if (value === true || value === false) return value
  const normalized = String(value).trim().toLowerCase()
  if (['true', '1', 'yes', 'on'].includes(normalized)) return true
  if (['false', '0', 'no', 'off'].includes(normalized)) return false
  return Boolean(value)
}

export function isPlainObject(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value))
}

export function valueOrEmpty(value) {
  return value ?? ''
}

export function normalizeProxyType(type) {
  return String(type || '').trim().toLowerCase()
}

export function normalizeClientProxyNode(proxy) {
  return {
    ...proxy,
    name: String(proxy.name || '').trim(),
    type: normalizeProxyType(proxy.type),
    'dialer-proxy': proxy['dialer-proxy'] === undefined ? undefined : String(proxy['dialer-proxy'] || '').trim(),
    network: proxy.network === undefined ? undefined : String(proxy.network || '').trim().toLowerCase(),
    enabled: normalizeBooleanValue(proxy.enabled, true),
  }
}

export function clone(value) {
  return JSON.parse(JSON.stringify(value))
}

export function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  })[char])
}

export function escapeAttr(value) {
  return escapeHtml(value)
}

export function downloadText(filename, text, type) {
  const blob = new Blob([text], { type })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}

export function normalizeFilename(value) {
  const cleaned = String(value || '').trim().replace(/[\\/:*?"<>|]+/g, '-')
  const fallback = cleaned || 'config.yaml'
  return /\.(ya?ml)$/i.test(fallback) ? fallback : `${fallback}.yaml`
}

export function splitRuleParts(rule) {
  const parts = []
  let current = ''
  let depth = 0
  for (const char of String(rule)) {
    if (char === '(') depth += 1
    else if (char === ')' && depth > 0) depth -= 1

    if (char === ',' && depth === 0) {
      parts.push(current.trim())
      current = ''
    } else {
      current += char
    }
  }
  parts.push(current.trim())
  return parts
}
