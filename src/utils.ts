export function splitLinesOrComma(value: unknown): string[] {
  return String(value || '').split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean)
}

export function splitLines(value: unknown): string[] {
  return String(value || '').split(/\r?\n/).map((item) => item.trim()).filter(Boolean)
}

export function compactObject(object: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(object).filter(([, value]) => value !== '' && value !== undefined && value !== null),
  )
}

export function normalizeBooleanValue(value: unknown, fallback = false): boolean {
  if (value === undefined || value === null || value === '') return fallback
  if (value === true || value === false) return value
  const normalized = String(value).trim().toLowerCase()
  if (['true', '1', 'yes', 'on'].includes(normalized)) return true
  if (['false', '0', 'no', 'off'].includes(normalized)) return false
  return Boolean(value)
}

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value))
}

export function valueOrEmpty(value: unknown): unknown {
  return value ?? ''
}

export function normalizeProxyType(type: unknown): string {
  return String(type || '').trim().toLowerCase()
}

export interface ProxyNode {
  name: string
  type: string
  'dialer-proxy'?: string
  network?: string
  enabled: boolean
  [key: string]: unknown
}

export function normalizeClientProxyNode(proxy: Record<string, unknown>): ProxyNode {
  return {
    ...proxy,
    name: String(proxy.name || '').trim(),
    type: normalizeProxyType(proxy.type),
    'dialer-proxy': proxy['dialer-proxy'] === undefined ? undefined : String(proxy['dialer-proxy'] || '').trim(),
    network: proxy.network === undefined ? undefined : String(proxy.network || '').trim().toLowerCase(),
    enabled: normalizeBooleanValue(proxy.enabled, true),
  }
}

export function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value))
}

export function escapeHtml(value: unknown): string {
  return String(value).replace(/[&<>"']/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  })[char] || char)
}

export function escapeAttr(value: unknown): string {
  return escapeHtml(value)
}

export function downloadText(filename: string, text: string, type: string): void {
  const blob = new Blob([text], { type })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}

export function normalizeFilename(value: unknown): string {
  const cleaned = String(value || '').trim().replace(/[\\/:*?"<>|]+/g, '-')
  const fallback = cleaned || 'config.yaml'
  return /\.(ya?ml)$/i.test(fallback) ? fallback : `${fallback}.yaml`
}

export function splitRuleParts(rule: string): string[] {
  const parts: string[] = []
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
