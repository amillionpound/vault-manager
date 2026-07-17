// vault-manager PWA service worker — app-shell cache, network for API.
const CACHE = 'vlt-pwa-v8';
const SHELL = [
  './',
  './index.html',
  './manifest.webmanifest',
  './static/jsqr.js',
  './static/qrcode.min.js',
  './icons/icon-192.png',
  './icons/icon-512.png',
  './icons/icon-maskable-512.png'
];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  // API calls are dynamic & zero-knowledge: never cache, always network.
  if (url.pathname.includes('/api/') || url.hostname.includes('tencentscf.com')) {
    return; // fall through to default network fetch
  }
  if (url.origin === self.location.origin) {
    // 导航(打开首页)：网络优先，失败回退缓存 —— 保证每次部署都能拿到最新文件
    if (req.mode === 'navigate') {
      e.respondWith(
        fetch(req).then((res) => {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(req, copy));
          return res;
        }).catch(() => caches.match('./index.html'))
      );
      return;
    }
    // 其他静态资源：cache-first，然后网络并更新缓存
    e.respondWith(
      caches.match(req).then((hit) => {
        if (hit) return hit;
        return fetch(req).then((res) => {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(req, copy));
          return res;
        }).catch(() => {
          if (req.mode === 'navigate') return caches.match('./index.html');
        });
      })
    );
  }
});
