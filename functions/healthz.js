import {
  backendOrigin,
  cleanProxyHeaders,
  withSecurityHeaders,
} from './_shared.js'

export async function onRequest(context) {
  const requestUrl = new URL(context.request.url)
  const backendUrl = new URL('/healthz', backendOrigin(context.env))
  const response = await fetch(backendUrl, {
    method: 'GET',
    headers: cleanProxyHeaders(context.request.headers, context.env, requestUrl.origin),
    redirect: 'manual',
  })
  return withSecurityHeaders(response)
}
