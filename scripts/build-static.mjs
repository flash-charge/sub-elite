import ts from 'typescript'
import webpack from 'webpack'
import { createHash } from 'node:crypto'
import { cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { deflateSync } from 'node:zlib'

const root = fileURLToPath(new URL('..', import.meta.url))
const dist = join(root, 'dist')
const buildTemp = join(root, '.sub-elite-build')
const CRC_TABLE = Array.from({ length: 256 }, (_, index) => {
  let value = index
  for (let bit = 0; bit < 8; bit += 1) {
    value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1
  }
  return value >>> 0
})

await rm(dist, { recursive: true, force: true })
await rm(buildTemp, { recursive: true, force: true })
await mkdir(join(dist, 'assets'), { recursive: true })
await mkdir(buildTemp, { recursive: true })

const apiBaseUrl = normalizeApiBaseUrl(process.env.SUB_ELITE_API_BASE_URL || process.env.API_BASE_URL || '')
await cp(join(root, 'public'), dist, { recursive: true })
await updateSecurityHeaders(apiBaseUrl)
await writePwaIconPng(join(dist, 'pwa-icon-192.png'), 192)
await writePwaIconPng(join(dist, 'pwa-icon-512.png'), 512)

const converterTsOptions = {
  compilerOptions: {
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.ESNext,
    removeComments: true,
  },
}
for (const libMod of ['helpers.ts', 'parsers.ts', 'converter.ts']) {
  const source = await readFile(join(root, 'lib', libMod), 'utf8')
  const result = ts.transpileModule(source, converterTsOptions)
  await writeFile(join(buildTemp, libMod.replace('.ts', '.js')), result.outputText.replace(/from '\.\/(\w+)\.ts'/g, "from './$1.js'"))
}

const appSource = await readFile(join(root, 'src', 'app.js'), 'utf8')
const appPrepared = appSource
  .replace("from '../lib/converter.ts'", "from './converter.js'")
  .replace(/from '\.\/(\w+)\.ts'/g, "from './$1.js'")
await writeFile(join(buildTemp, 'app.js'), appPrepared)

for (const mod of ['constants.ts', 'utils.ts', 'model.ts', 'state.js', 'manual-node.js', 'proxy-fields.js', 'yaml-tools.js', 'editors.js', 'providers.js', 'rules.js']) {
  const modSource = await readFile(join(root, 'src', mod), 'utf8')
  const modResult = ts.transpileModule(modSource, {
    compilerOptions: {
      target: ts.ScriptTarget.ES2022,
      module: ts.ModuleKind.ESNext,
      removeComments: true,
    },
  })
  const outName = mod.replace(/\.ts$/, '.js')
  await writeFile(join(buildTemp, outName), modResult.outputText.replace(/from '\.\/(\w+)\.ts'/g, "from './$1.js'").replace("from '../lib/converter.ts'", "from './converter.js'"))
}

const appPath = await bundleApp()

const cssSource = await readFile(join(root, 'src', 'styles.css'), 'utf8')
const cssPath = await writeAsset('styles', 'css', minifyCss(cssSource))

const indexHtml = await readFile(join(root, 'index.html'), 'utf8')
const builtHtml = indexHtml
  .replaceAll('%SUB_ELITE_API_BASE_URL%', escapeHtmlAttr(apiBaseUrl))
  .replace(/<link rel="stylesheet" href="\/src\/styles\.css[^"]*" \/>/u, `<link rel="stylesheet" href="/assets/${cssPath.name}" />`)
  .replace(/<script type="module" src="\/src\/app\.js[^"]*"><\/script>/u, `<script type="module" src="/assets/${appPath.name}"></script>`)
await writeFile(join(dist, 'index.html'), builtHtml)
await writeFile(join(dist, 'service-worker.js'), createServiceWorkerSource({
  appAsset: appPath.name,
  cssAsset: cssPath.name,
}))
await rm(buildTemp, { recursive: true, force: true })

console.log('Static build written to dist')

async function bundleApp() {
  const stats = await new Promise((resolve, reject) => {
    webpack({
      mode: 'production',
      entry: join(buildTemp, 'app.js'),
      output: {
        path: join(dist, 'assets'),
        filename: 'app.[contenthash:12].js',
        clean: false,
      },
      devtool: false,
      target: ['web', 'es2022'],
      resolve: {
        mainFields: ['browser', 'module', 'main'],
        extensions: ['.js', '.json'],
      },
      optimization: {
        concatenateModules: true,
        minimize: true,
        mangleExports: true,
      },
      performance: false,
    }, (error, stats) => {
      if (error) {
        reject(error)
        return
      }

      if (stats?.hasErrors()) {
        reject(new Error(stats.toString({ all: false, errors: true })))
        return
      }

      resolve(stats)
    })
  })

  const output = stats.toJson({ all: false, assets: true })
  const asset = output.assets?.find((asset) => /^app\.[a-f0-9]{12}\.js$/u.test(asset.name))
  if (!asset) throw new Error('Bundled app asset was not generated.')
  return { name: asset.name }
}

async function writeAsset(name, extension, content) {
  const hash = createHash('sha256').update(content).digest('hex').slice(0, 12)
  const filename = `${name}.${hash}.${extension}`
  await writeFile(join(dist, 'assets', filename), content)
  return { name: filename }
}

function minifyCss(css) {
  return css
    .replace(/\/\*[\s\S]*?\*\//gu, '')
    .replace(/\s+/gu, ' ')
    .replace(/\s*([{}:;,>])\s*/gu, '$1')
    .replace(/;\}/gu, '}')
    .trim()
}

function normalizeApiBaseUrl(value) {
  return String(value || '').trim().replace(/\/+$/u, '')
}

async function updateSecurityHeaders(apiBaseUrl) {
  if (!apiBaseUrl) return

  let apiOrigin = ''
  try {
    apiOrigin = new URL(apiBaseUrl).origin
  } catch {
    throw new Error('SUB_ELITE_API_BASE_URL must be a valid absolute URL.')
  }

  const headersPath = join(dist, '_headers')
  const headers = await readFile(headersPath, 'utf8')
  const updated = headers.replace(
    /connect-src 'self'([^;]*);/u,
    (match, extra = '') => match.includes(apiOrigin) ? match : `connect-src 'self'${extra} ${apiOrigin};`,
  )
  await writeFile(headersPath, updated)
}

function escapeHtmlAttr(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('"', '&quot;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
}

function createServiceWorkerSource({ appAsset, cssAsset }) {
  const version = createHash('sha256').update(`${appAsset}:${cssAsset}`).digest('hex').slice(0, 12)
  const precacheUrls = [
    '/',
    '/index.html',
    `/assets/${appAsset}`,
    `/assets/${cssAsset}`,
    '/favicon.svg',
    '/icons.svg',
    '/manifest.webmanifest',
    '/pwa-icon.svg',
    '/pwa-icon-192.png',
    '/pwa-icon-512.png',
  ]

  return `const CACHE_NAME = ${JSON.stringify(`sub-elite-${version}`)}
const PRECACHE_URLS = ${JSON.stringify(precacheUrls, null, 2)}
const BYPASS_PREFIXES = ['/api/', '/sub/', '/healthz']

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(PRECACHE_URLS))
      .then(() => self.skipWaiting())
  )
})

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((names) => Promise.all(names
        .filter((name) => name.startsWith('sub-elite-') && name !== CACHE_NAME)
        .map((name) => caches.delete(name))))
      .then(() => self.clients.claim())
  )
})

self.addEventListener('fetch', (event) => {
  const request = event.request
  if (request.method !== 'GET') return

  const url = new URL(request.url)
  if (url.origin !== self.location.origin) return
  if (BYPASS_PREFIXES.some((prefix) => url.pathname === prefix.slice(0, -1) || url.pathname.startsWith(prefix))) return

  if (request.mode === 'navigate') {
    event.respondWith(networkFirst(request, '/index.html'))
    return
  }

  if (url.pathname.startsWith('/assets/') || PRECACHE_URLS.includes(url.pathname)) {
    event.respondWith(cacheFirst(request))
  }
})

async function cacheFirst(request) {
  const cached = await caches.match(request)
  if (cached) return cached

  const response = await fetch(request)
  if (response.ok) {
    const cache = await caches.open(CACHE_NAME)
    await cache.put(request, response.clone())
  }
  return response
}

async function networkFirst(request, fallbackUrl) {
  try {
    const response = await fetch(request)
    if (response.ok) {
      const cache = await caches.open(CACHE_NAME)
      await cache.put(request, response.clone())
    }
    return response
  } catch {
    return await caches.match(request) || await caches.match(fallbackUrl)
  }
}
`
}

async function writePwaIconPng(filePath, size) {
  const image = createPngBuffer(size)
  await writeFile(filePath, image)
}

function createPngBuffer(size) {
  const raw = Buffer.alloc((size * 4 + 1) * size)
  const scale = (value) => Math.round((value / 512) * size)

  for (let y = 0; y < size; y += 1) {
    const row = y * (size * 4 + 1)
    raw[row] = 0
    for (let x = 0; x < size; x += 1) {
      setRgba(raw, row + 1 + x * 4, 10, 15, 14, 255)
    }
  }

  paintRoundedRect(raw, size, scale(52), scale(52), scale(408), scale(408), scale(96), [38, 53, 50, 255])
  paintRoundedRect(raw, size, scale(68), scale(68), scale(376), scale(376), scale(80), [18, 25, 24, 255])
  paintRoundedRect(raw, size, scale(162), scale(156), scale(188), scale(44), scale(22), [20, 184, 154, 255])
  paintRoundedRect(raw, size, scale(162), scale(234), scale(188), scale(44), scale(22), [20, 184, 154, 255])
  paintRoundedRect(raw, size, scale(162), scale(312), scale(188), scale(44), scale(22), [20, 184, 154, 255])
  paintCircle(raw, size, scale(162), scale(178), scale(34), [215, 255, 246, 255])
  paintCircle(raw, size, scale(350), scale(256), scale(34), [20, 184, 154, 255])
  paintCircle(raw, size, scale(350), scale(334), scale(34), [126, 231, 214, 255])

  return encodePng(size, size, raw)
}

function setRgba(buffer, offset, red, green, blue, alpha) {
  buffer[offset] = red
  buffer[offset + 1] = green
  buffer[offset + 2] = blue
  buffer[offset + 3] = alpha
}

function paintRoundedRect(buffer, size, x, y, width, height, radius, color) {
  const right = x + width
  const bottom = y + height
  const centerX = x + width / 2
  const centerY = y + height / 2
  const innerX = width / 2 - radius
  const innerY = height / 2 - radius

  for (let py = Math.max(0, y); py < Math.min(size, bottom); py += 1) {
    const row = py * (size * 4 + 1)
    for (let px = Math.max(0, x); px < Math.min(size, right); px += 1) {
      const dx = Math.max(Math.abs(px + 0.5 - centerX) - innerX, 0)
      const dy = Math.max(Math.abs(py + 0.5 - centerY) - innerY, 0)
      if (dx * dx + dy * dy <= radius * radius) {
        setRgba(buffer, row + 1 + px * 4, color[0], color[1], color[2], color[3])
      }
    }
  }
}

function paintCircle(buffer, size, centerX, centerY, radius, color) {
  const radiusSquared = radius * radius
  for (let py = Math.max(0, centerY - radius); py < Math.min(size, centerY + radius); py += 1) {
    const row = py * (size * 4 + 1)
    for (let px = Math.max(0, centerX - radius); px < Math.min(size, centerX + radius); px += 1) {
      const dx = px + 0.5 - centerX
      const dy = py + 0.5 - centerY
      if (dx * dx + dy * dy <= radiusSquared) {
        setRgba(buffer, row + 1 + px * 4, color[0], color[1], color[2], color[3])
      }
    }
  }
}

function encodePng(width, height, raw) {
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])
  const ihdr = Buffer.alloc(13)
  ihdr.writeUInt32BE(width, 0)
  ihdr.writeUInt32BE(height, 4)
  ihdr[8] = 8
  ihdr[9] = 6
  ihdr[10] = 0
  ihdr[11] = 0
  ihdr[12] = 0

  return Buffer.concat([
    signature,
    pngChunk('IHDR', ihdr),
    pngChunk('IDAT', deflateSync(raw)),
    pngChunk('IEND', Buffer.alloc(0)),
  ])
}

function pngChunk(type, data) {
  const typeBuffer = Buffer.from(type)
  const length = Buffer.alloc(4)
  length.writeUInt32BE(data.length, 0)
  const crc = Buffer.alloc(4)
  crc.writeUInt32BE(crc32(Buffer.concat([typeBuffer, data])), 0)
  return Buffer.concat([length, typeBuffer, data, crc])
}

function crc32(buffer) {
  let crc = 0xffffffff
  for (const byte of buffer) {
    crc = (crc >>> 8) ^ CRC_TABLE[(crc ^ byte) & 0xff]
  }
  return (crc ^ 0xffffffff) >>> 0
}
