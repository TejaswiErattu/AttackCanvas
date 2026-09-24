# static-spa

Trimmed, offline copy of files from the public repository TejaswiErattu/tejaswisummer:
a static single-page app (index.html + browser JS), a Cloudflare Worker proxy
(proxy/worker.js), Firebase (firebase-config.js, firebase-sync.js, firestore.rules) and a
GitHub Pages workflow. There is a package-lock.json but no package.json.

Used by tests/detect.staticSpa.test.ts. Large files were cut to the parts the detectors
read; the Firebase web API key in firebase-config.js is replaced with a placeholder.
