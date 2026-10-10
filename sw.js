// Service worker for the password-protected site.
// Everything under app.html, assets/ and media/ is published encrypted
// (as <file>.enc). This worker fetches the encrypted file, decrypts it
// with the key saved after the password was entered, and hands the
// browser the real file — so the app itself needs no changes.
const BUILD = 'mv2dbcax' // changes every deploy so browsers pick up a new worker
const SCOPE = new URL(self.registration.scope).pathname
const PROTECTED = /^(app\.html$|assets\/|media\/)/

const TYPES = {
  html: 'text/html; charset=utf-8', js: 'text/javascript', css: 'text/css', json: 'application/json',
  svg: 'image/svg+xml', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', webp: 'image/webp',
  gif: 'image/gif', avif: 'image/avif', ico: 'image/x-icon', mp4: 'video/mp4', webm: 'video/webm',
  mov: 'video/quicktime', m4v: 'video/mp4', mp3: 'audio/mpeg', m4a: 'audio/mp4', wav: 'audio/wav',
  woff2: 'font/woff2', txt: 'text/plain; charset=utf-8',
}

self.addEventListener('install', () => self.skipWaiting())
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()))

function keyStore(mode, fn) {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open('vault', 1)
    open.onupgradeneeded = () => open.result.createObjectStore('keys')
    open.onerror = () => reject(open.error)
    open.onsuccess = () => {
      const req = fn(open.result.transaction('keys', mode).objectStore('keys'))
      req.onsuccess = () => resolve(req.result)
      req.onerror = () => reject(req.error)
    }
  })
}
// The key is stored as raw bytes, not a CryptoKey object: Safari can't read
// CryptoKey objects saved by a page back inside a service worker.
const KEY = 'site-raw'
async function getKey() {
  const raw = await keyStore('readonly', (s) => s.get(KEY))
  return raw ? crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']) : null
}
const forgetKey = () => keyStore('readwrite', (s) => s.delete(KEY))

// small memory cache so video seeking doesn't re-download/decrypt each range
const cache = new Map()
async function decrypt(path, key) {
  if (cache.has(path)) return cache.get(path)
  const res = await fetch(path + '.enc', { cache: 'no-cache' })
  if (!res.ok) return null
  const data = new Uint8Array(await res.arrayBuffer())
  const plain = new Uint8Array(
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv: data.subarray(0, 12) }, key, data.subarray(12)),
  )
  cache.set(path, plain)
  if (cache.size > 8) cache.delete(cache.keys().next().value)
  return plain
}

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url)
  if (url.origin !== location.origin || !url.pathname.startsWith(SCOPE)) return
  if (!PROTECTED.test(url.pathname.slice(SCOPE.length))) return
  event.respondWith(serve(event.request, url))
})

async function serve(request, url) {
  const locked = () =>
    request.mode === 'navigate' ? Response.redirect(SCOPE + '?locked', 302) : new Response('Locked', { status: 401 })

  const key = await getKey().catch(() => null)
  if (!key) return locked()

  let body
  try {
    body = await decrypt(url.pathname, key)
  } catch {
    // wrong/old key (e.g. the password was changed) → ask again
    await forgetKey().catch(() => {})
    return locked()
  }
  if (!body) return new Response('Not found', { status: 404 })

  const ext = url.pathname.split('.').pop().toLowerCase()
  const headers = { 'Content-Type': TYPES[ext] || 'application/octet-stream', 'Accept-Ranges': 'bytes' }

  // videos ask for byte ranges (Safari requires this to play at all)
  const range = /bytes=(\d*)-(\d*)/.exec(request.headers.get('range') || '')
  if (range) {
    const total = body.length
    let start = range[1] ? Number(range[1]) : total - Number(range[2])
    let end = range[1] && range[2] ? Number(range[2]) : total - 1
    start = Math.max(0, start)
    end = Math.min(end, total - 1)
    if (start > end) return new Response(null, { status: 416, headers: { 'Content-Range': `bytes */${total}` } })
    return new Response(body.slice(start, end + 1), {
      status: 206,
      headers: { ...headers, 'Content-Range': `bytes ${start}-${end}/${total}`, 'Content-Length': String(end - start + 1) },
    })
  }
  return new Response(body, { headers: { ...headers, 'Content-Length': String(body.length) } })
}
