const CACHE_NAME = "open-eidas-v1";
const STATIC_ASSETS = [
  "./",
  "index.html",
  "style.css",
  "app.js",
  "manifest.json",
  "icon.svg",
];

self.addEventListener("install", (e) => {
  e.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(STATIC_ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys.map((k) => {
          if (k !== CACHE_NAME) return caches.delete(k);
        })
      )
    ).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);

  // Ne pas mettre en cache les requêtes vers l'API Open eIDAS
  if (url.origin.includes("open-eidas.eu") && url.pathname.includes("/api/")) {
    return;
  }

  // Stratégie pour les assets locaux et CDN : Cache first avec repli réseau
  e.respondWith(
    caches.match(e.request).then((cached) => {
      if (cached) return cached;
      return fetch(e.request).then((res) => {
        if (
          res.status === 200 &&
          (e.request.url.startsWith("http") || e.request.url.includes("jsdelivr"))
        ) {
          const clone = res.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(e.request, clone));
        }
        return res;
      });
    })
  );
});
