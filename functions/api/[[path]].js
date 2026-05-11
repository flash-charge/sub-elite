import {
  backendOrigin,
  cleanProxyHeaders,
  jsonHeaders,
  withSecurityHeaders,
} from '../_shared.js'

export async function onRequest(context) {
  const response = await proxyToBackend(context)
  const requestUrl = new URL(context.request.url)

  if (requestUrl.pathname === '/api/subscriptions' && isJsonResponse(response)) {
    const payload = await response.json()
    if (typeof payload.url === 'string') {
      payload.url = sameOriginSubscriptionUrl(payload.url, requestUrl.origin)
    }
    delete payload.secret

    return new Response(JSON.stringify(payload), {
      status: response.status,
      headers: jsonHeaders(response.headers),
    })
  }

  return withSecurityHeaders(response)
}

async function proxyToBackend(context) {
  const requestUrl = new URL(context.request.url)
  const backendUrl = new URL(`${requestUrl.pathname}${requestUrl.search}`, backendOrigin(context.env))
  const headers = cleanProxyHeaders(context.request.headers, context.env, requestUrl.origin)
  const init = {
    method: context.request.method,
    headers,
    body: ['GET', 'HEAD'].includes(context.request.method) ? undefined : context.request.body,
    redirect: 'manual',
  }

  return fetch(backendUrl, init)
}

function isJsonResponse(response) {
  return (response.headers.get('content-type') || '').toLowerCase().includes('application/json')
}

function sameOriginSubscriptionUrl(value, origin) {
  try {
    const url = new URL(value)
    return `${origin}${url.pathname}${url.search}`
  } catch {
    return value
  }
}
