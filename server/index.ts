import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { extname, join, normalize, sep, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { randomBytes } from 'node:crypto'
import { convertToClashMeta } from '../lib/converter.ts'

const PORT = Number(process.env.PORT || 8787)
const MAX_INPUT_BYTES = 1024 * 1024
const MAX_SUBSCRIPTION_BYTES = 256 * 1024
const SUBSCRIPTION_EXPIRY = {
  '7d': 7 * 24 * 60 * 60,
  '30d': 30 * 24 * 60 * 60,
  never: undefined,
}
const SECRET_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
const localSubscriptions = new Map()
const __dirname = fileURLToPath(new URL('.', import.meta.url))
const rootDir = normalize(join(__dirname, '..'))
const distDir = join(rootDir, 'dist')

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url || '/', 'http://localhost')
    const pathname = url.pathname

    if (request.method === 'GET' && pathname === '/healthz') {
      return sendJson(response, 200, { ok: true })
    }

    if (request.method === 'POST' && pathname === '/api/convert') {
      return handleConvert(request, response)
    }

    if (request.method === 'POST' && pathname === '/api/subscriptions') {
      return handleCreateSubscription(request, response)
    }

    if (request.method === 'GET' && /^\/sub\/[A-Za-z0-9_-]+\/config\.yaml$/.test(pathname)) {
      return handleSubscription(request, response)
    }

    if (request.method === 'OPTIONS') {
      response.writeHead(204, corsHeaders())
      return response.end()
    }

    return serveStatic(request, response)
  } catch (error) {
    return sendJson(response, error.statusCode || 500, { error: error.message || 'Server error' })
  }
})

server.listen(PORT, '0.0.0.0', () => {
  console.log(`API server ready on http://127.0.0.1:${PORT}`)
})

async function handleConvert(request, response) {
  const body = await readBody(request)
  let payload

  try {
    payload = JSON.parse(body)
  } catch {
    return sendJson(response, 400, { error: 'Body must be valid JSON.' })
  }

  const input = String(payload.input || '').trim()
  if (!input) return sendJson(response, 400, { error: 'Input cannot be empty.' })
  if (hasHttpUrl(input)) {
    return sendJson(response, 400, { error: 'Paste config links directly, not http/https subscription URLs.' })
  }

  const result = convertToClashMeta(input, readConvertOptions(payload))
  return sendJson(response, 200, result)
}

async function handleCreateSubscription(request, response) {
  const contentType = request.headers['content-type'] || ''
  if (!String(contentType).toLowerCase().includes('application/json')) {
    return sendJson(response, 415, { error: 'Content-Type must be application/json.' })
  }

  const body = await readBody(request, MAX_SUBSCRIPTION_BYTES + 4096)
  let payload

  try {
    payload = JSON.parse(body)
  } catch {
    return sendJson(response, 400, { error: 'Body must be valid JSON.' })
  }

  const yaml = String(payload.yaml || '').trim()
  if (!yaml) return sendJson(response, 400, { error: 'YAML cannot be empty.' })
  if (Buffer.byteLength(yaml, 'utf8') > MAX_SUBSCRIPTION_BYTES) {
    return sendJson(response, 413, { error: 'YAML is too large. Maximum size is 256 KB.' })
  }

  const expiresIn = Object.hasOwn(SUBSCRIPTION_EXPIRY, payload.expiresIn) ? payload.expiresIn : '30d'
  const secret = randomSecret(32)
  const ttl = SUBSCRIPTION_EXPIRY[expiresIn]
  localSubscriptions.set(secret, {
    yaml,
    expiresAt: ttl ? Date.now() + ttl * 1000 : 0,
  })

  const url = new URL(`/sub/${secret}/config.yaml`, `http://${request.headers.host || `127.0.0.1:${PORT}`}`)
  return sendJson(response, 200, {
    ok: true,
    url: url.toString(),
    secret,
    expiresIn,
  })
}

function handleSubscription(request, response) {
  const url = new URL(request.url || '/', 'http://localhost')
  const secret = url.pathname.split('/')[2]
  const record = localSubscriptions.get(secret)
  if (!record || (record.expiresAt && record.expiresAt <= Date.now())) {
    if (record) localSubscriptions.delete(secret)
    response.writeHead(404, subscriptionHeaders())
    return response.end('Subscription not found.')
  }

  response.writeHead(200, subscriptionHeaders())
  return response.end(record.yaml.endsWith('\n') ? record.yaml : `${record.yaml}\n`)
}

async function readBody(request, maxBytes = MAX_INPUT_BYTES) {
  const chunks = []
  let size = 0

  for await (const chunk of request) {
    size += chunk.length
    if (size > maxBytes) throw httpError(413, maxBytes === MAX_INPUT_BYTES ? 'Input is too large.' : 'YAML is too large. Maximum size is 256 KB.')
    chunks.push(chunk)
  }

  return Buffer.concat(chunks).toString('utf8')
}

async function serveStatic(request, response) {
  if (!['GET', 'HEAD'].includes(request.method || '')) return sendJson(response, 404, { error: 'Not found' })
  const headOnly = request.method === 'HEAD'

  const url = new URL(request.url || '/', 'http://localhost')
  const requested = url.pathname === '/' ? '/index.html' : url.pathname
  const baseDir = await hasDistBuild()
  const basePath = resolve(baseDir)
  const filePath = resolve(basePath, requested.replace(/^\/+/u, ''))
  if (filePath !== basePath && !filePath.startsWith(`${basePath}${sep}`)) {
    return sendJson(response, 403, { error: 'Forbidden' })
  }

  try {
    const content = await readFile(filePath)
    response.writeHead(200, {
      'content-type': contentType(filePath),
    })
    return response.end(headOnly ? undefined : content)
  } catch {
    if (!extname(requested)) {
      try {
        const content = await readFile(join(baseDir, 'index.html'))
        response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
        return response.end(headOnly ? undefined : content)
      } catch {
        return sendJson(response, 404, { error: 'Frontend build is not available yet. Run npm run build.' })
      }
    }
    return sendJson(response, 404, { error: 'Not found' })
  }
}

function sendJson(response, status, payload) {
  const body = JSON.stringify(payload)
  response.writeHead(status, {
    ...corsHeaders(),
    'content-type': 'application/json; charset=utf-8',
  })
  response.end(body)
}

function corsHeaders() {
  return {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET,POST,OPTIONS',
    'access-control-allow-headers': 'content-type',
  }
}

function contentType(filePath) {
  const ext = extname(filePath)
  if (ext === '.html') return 'text/html; charset=utf-8'
  if (ext === '.js') return 'text/javascript; charset=utf-8'
  if (ext === '.css') return 'text/css; charset=utf-8'
  if (ext === '.svg') return 'image/svg+xml'
  if (ext === '.png') return 'image/png'
  if (ext === '.webmanifest') return 'application/manifest+json; charset=utf-8'
  return 'application/octet-stream'
}

function subscriptionHeaders() {
  return {
    'content-type': 'text/yaml; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  }
}

function randomSecret(length) {
  const bytes = randomBytes(length)
  let output = ''
  for (const byte of bytes) output += SECRET_ALPHABET[byte % SECRET_ALPHABET.length]
  return output
}

async function hasDistBuild() {
  try {
    await readFile(join(distDir, 'index.html'))
    return distDir
  } catch {
    return rootDir
  }
}

function httpError(statusCode, message) {
  const error = new Error(message)
  error.statusCode = statusCode
  return error
}

function hasHttpUrl(input) {
  return input
    .split(/\s+/)
    .some((item) => /^https?:\/\//i.test(item.trim()))
}

function readConvertOptions(payload) {
  return {
    template: payload.template,
    rulesPreset: payload.rulesPreset,
    namePattern: payload.namePattern,
    namePrefix: payload.namePrefix,
  }
}
