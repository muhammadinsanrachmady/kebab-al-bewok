const CACHE_NAME = 'kebab-bewok-v2';
const ASSETS_TO_CACHE = [
  '/',
  '/customer.html',
  '/admin.html',
  '/driver.html',
  '/owner.html',
  '/manifest.json',
  '/manifest-admin.json',
  '/manifest-driver.json',
  '/manifest-owner.json',
  'https://cdn.tailwindcss.com',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      console.log('🍢 [Service Worker] Memasang aset offline Kebab AL Bewok...');
      return cache.addAll(ASSETS_TO_CACHE).catch(err => console.log('SW cache skip:', err));
    })
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            console.log('🍢 [Service Worker] Menghapus cache lama:', key);
            return caches.delete(key);
          }
        })
      );
    })
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  if (event.request.method === 'GET' && !event.request.url.includes('/api/')) {
    event.respondWith(
      fetch(event.request).catch(() => caches.match(event.request))
    );
  }
});
