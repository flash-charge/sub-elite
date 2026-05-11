import {
  backendOrigin,
  cleanProxyHeaders,
  withSecurityHeaders,
} from '../_shared.js'

export async function onRequest(context) {
  const requestUrl = new URL(context.request.url)
  const backendUrl = new URL(`${requestUrl.pathname}${requestUrl.search}`, backendOrigin(context.env))
  const response = await fetch(backendUrl, {
    method: context.request.method,
    headers: cleanProxyHeaders(context.request.headers, context.env, requestUrl.origin),
    body: ['GET', 'HEAD'].includes(context.request.method) ? undefined : context.request.body,
    redirect: 'manual',
  })
  return withSecurityHeaders(response)
}
