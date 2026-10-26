/* Hotel Copahue — service worker (Tanda 380)
   - La pantalla principal (el HTML) se pide primero a la red y, si no hay conexión o tarda mucho, se abre la última copia guardada.
   - Librerías y tipografías externas (Firebase, Google Fonts, iconos): se guardan y se refrescan en segundo plano.
   - NO toca Firestore, las funciones de Netlify (/.netlify/*) ni ninguna llamada que no sea GET: los datos siempre salen directo a la red.
   Para forzar que todos descarguen una versión nueva de este archivo, cambiar VERSION. */
const VERSION = "copahue-v2";
const SHELL_KEY = "/__app-shell";
const STATIC_HOSTS = ["www.gstatic.com", "fonts.googleapis.com", "fonts.gstatic.com", "cdn.jsdelivr.net"];
const PRECACHE = [
  "/manifest.webmanifest",
  "/icons/icon-192.png",
  "/icons/icon-512.png",
  "https://www.gstatic.com/firebasejs/10.13.2/firebase-app-compat.js",
  "https://www.gstatic.com/firebasejs/10.13.2/firebase-firestore-compat.js",
  "https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@latest/tabler-icons.min.css"
];

self.addEventListener("install", (e) => {
  e.waitUntil((async () => {
    const c = await caches.open(VERSION);
    // Cada archivo por separado: si uno falla (ej. sin internet al instalar) no se cae la instalación.
    await Promise.all(PRECACHE.map((u) => c.add(new Request(u, u.startsWith("http") ? { mode: "no-cors" } : {})).catch(() => {})));
    try { const r = await fetch("/", { cache: "reload" }); if (r.ok) await c.put(SHELL_KEY, r); } catch (_) {}
    await self.skipWaiting();
  })());
});

self.addEventListener("activate", (e) => {
  e.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter((k) => k !== VERSION).map((k) => caches.delete(k)));
    await self.clients.claim();
  })());
});

const withTimeout = (p, ms) => new Promise((res, rej) => { const t = setTimeout(() => rej(new Error("timeout")), ms); p.then((v) => { clearTimeout(t); res(v); }, (e) => { clearTimeout(t); rej(e); }); });

async function networkFirstShell(req) {
  const c = await caches.open(VERSION);
  try {
    const r = await withTimeout(fetch(req), 8000);
    if (r && r.ok && r.type === "basic") { c.put(SHELL_KEY, r.clone()); return r; }
    // El sistema cambia la direccion (/inicio, /roomings...) sin recargar; si el servidor no conoce esa ruta, se abre igual la app guardada.
    if (r && r.status === 404) { const hit404 = await c.match(SHELL_KEY); if (hit404) return hit404; }
    return r;
  } catch (_) {
    const hit = await c.match(SHELL_KEY);
    if (hit) return hit;
    return new Response("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><body style='font-family:sans-serif;padding:32px;text-align:center'><h2>Sin conexión</h2><p>Todavía no hay una copia guardada. Conectate a internet una vez para poder usar la app sin conexión.</p>", { status: 503, headers: { "Content-Type": "text/html; charset=utf-8" } });
  }
}

async function staleWhileRevalidate(req) {
  const c = await caches.open(VERSION);
  const hit = await c.match(req);
  const net = fetch(req).then((r) => { if (r && (r.ok || r.type === "opaque")) c.put(req, r.clone()); return r; }).catch(() => null);
  return hit || (await net) || Response.error();
}

self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin === self.location.origin) {
    if (url.pathname.startsWith("/.netlify/")) return;
    if (req.mode === "navigate") { e.respondWith(networkFirstShell(req)); return; }
    e.respondWith((async () => {
      const c = await caches.open(VERSION);
      try { const r = await fetch(req); if (r && r.ok) c.put(req, r.clone()); return r; }
      catch (_) { const hit = await c.match(req); return hit || Response.error(); }
    })());
    return;
  }
  if (STATIC_HOSTS.includes(url.hostname)) e.respondWith(staleWhileRevalidate(req));
});

self.addEventListener("message", (e) => { if (e.data === "SKIP_WAITING") self.skipWaiting(); });

self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  e.waitUntil((async () => {
    const all = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    for (const c of all) { if ("focus" in c) { try { await c.focus(); return; } catch (_) {} } }
    if (self.clients.openWindow) await self.clients.openWindow("/");
  })());
});
