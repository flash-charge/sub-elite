import {
  backendConfigErrorResponse,
  backendUrl,
  cleanProxyHeaders,
  withSecurityHeaders,
} from '../_shared.js'

export async function onRequest(context) {
  const requestUrl = new URL(context.request.url)
  const targetUrl = backendUrl(`${requestUrl.pathname}${requestUrl.search}`, context.env)
  if (!targetUrl) return backendConfigErrorResponse(context.request, context.env, 'GET,OPTIONS', 'text/yaml')

  const response = await fetch(targetUrl, {
    method: context.request.method,
    headers: cleanProxyHeaders(context.request.headers, context.env, requestUrl.origin),
    body: ['GET', 'HEAD'].includes(context.request.method) ? undefined : context.request.body,
    redirect: 'manual',
  })
  return withSecurityHeaders(response)
}
