import {
  backendConfigErrorResponse,
  backendUrl,
  cleanProxyHeaders,
  withSecurityHeaders,
} from './_shared.js'

export async function onRequest(context) {
  const requestUrl = new URL(context.request.url)
  const targetUrl = backendUrl('/healthz', context.env)
  if (!targetUrl) return backendConfigErrorResponse(context.request, context.env, 'GET,OPTIONS')

  const response = await fetch(targetUrl, {
    method: 'GET',
    headers: cleanProxyHeaders(context.request.headers, context.env, requestUrl.origin),
    redirect: 'manual',
  })
  return withSecurityHeaders(response)
}
