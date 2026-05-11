export const DEFAULT_BACKEND_ORIGIN = 'https://sub-elite-api.stroke.workers.dev'
export const PROXY_SECRET_HEADER = 'x-sub-elite-proxy-secret'

export function backendOrigin(env) {
  return String(env.SUB_ELITE_BACKEND_ORIGIN || DEFAULT_BACKEND_ORIGIN).replace(/\/+$/u, '')
}

export function cleanProxyHeaders(source, env, origin = '') {
  const headers = new Headers(source)
  headers.delete('host')
  headers.delete('content-length')
  headers.delete(PROXY_SECRET_HEADER)
  if (origin && !headers.has('origin')) headers.set('origin', origin)

  const proxySecret = String(env.SUB_ELITE_PROXY_SECRET || '').trim()
  if (proxySecret) headers.set(PROXY_SECRET_HEADER, proxySecret)

  return headers
}

export function withSecurityHeaders(response) {
  const headers = new Headers(response.headers)
  setSecurityHeaders(headers)
  headers.delete('content-length')
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  })
}

export function jsonHeaders(source) {
  const headers = new Headers(source)
  headers.set('content-type', 'application/json; charset=utf-8')
  headers.delete('content-length')
  setSecurityHeaders(headers)
  return headers
}

function setSecurityHeaders(headers) {
  headers.set('content-security-policy', [
    "default-src 'none'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    "form-action 'none'",
  ].join('; '))
  headers.set('permissions-policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=()')
  headers.set('referrer-policy', 'no-referrer')
  headers.set('strict-transport-security', 'max-age=31536000; includeSubDomains; preload')
  headers.set('x-content-type-options', 'nosniff')
  headers.set('x-frame-options', 'DENY')
}
