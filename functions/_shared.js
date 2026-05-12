export const PROXY_SECRET_HEADER = 'x-sub-elite-proxy-secret'

export function backendOrigin(env) {
  return String(env.SUB_ELITE_BACKEND_ORIGIN || '').trim().replace(/\/+$/u, '')
}

export function backendUrl(path, env) {
  const origin = backendOrigin(env)
  if (!origin) return null

  try {
    return new URL(path, origin)
  } catch {
    return null
  }
}

export function backendConfigErrorResponse(request, env, methods = 'GET,POST,OPTIONS', contentType = 'application/json') {
  const headers = new Headers(corsHeaders(methods, request, env))
  const message = 'SUB_ELITE_BACKEND_ORIGIN is not configured or is invalid.'

  if (contentType === 'text/yaml') {
    headers.set('content-type', 'text/yaml; charset=utf-8')
    headers.set('cache-control', 'no-store')
    return new Response(`${message}\n`, { status: 503, headers })
  }

  headers.set('content-type', 'application/json; charset=utf-8')
  return new Response(JSON.stringify({ error: message }), { status: 503, headers })
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

function corsHeaders(methods = 'GET,POST,OPTIONS', request) {
  const headers = new Headers()
  headers.set('access-control-allow-origin', request?.headers?.get('origin') || '*')
  headers.set('access-control-allow-methods', methods)
  headers.set('access-control-allow-headers', `content-type, ${PROXY_SECRET_HEADER}`)
  headers.set('vary', 'Origin')
  setSecurityHeaders(headers)
  return headers
}
