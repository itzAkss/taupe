const CACHE_NAME = 'taupe-v1';

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll([
      '/',
      '/style.css',
      '/client.js',
      '/crypto.js',
      '/manifest.json'
    ]))
  );
});

self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;

  return caches.match(event.request).then(cached => {
    const networked = fetch(event.request).then(response => {
      if (response.ok) {
        const url = new URL(event.request.url);
        if (!url.pathname.startsWith('/api/') && 
            !url.pathname.startsWith('/socket.io/') && 
            !url.pathname.startsWith('/uploads/')) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
        }
      }
      return response;
    }).catch(() => cached);
    
    return networked || cached;
  });
});