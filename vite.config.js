import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { request as httpsRequest } from 'node:https'
import tls from 'node:tls'

// Self-signed PVE-Zertifikate global akzeptieren (nur dev-server Prozess)
tls.DEFAULT_REJECT_UNAUTHORIZED = 0

function pveProxy() {
  return {
    name: 'pve-proxy',
    configureServer(server) {
      // Muss VOR Vite-internen Middlewares registriert werden
      server.middlewares.use((req, res, next) => {
        if (!req.url.startsWith('/pve-api')) return next()

        if (req.method === 'OPTIONS') {
          res.writeHead(204, {
            'access-control-allow-origin': '*',
            'access-control-allow-headers': '*',
            'access-control-allow-methods': '*',
            'access-control-max-age': '86400',
          })
          return res.end()
        }

        const target = req.headers['x-pve-target']
        if (!target) {
          res.writeHead(400, { 'content-type': 'application/json' })
          return res.end('{"error":"X-PVE-Target header missing"}')
        }

        const [host, port = '8006'] = target.split(':')
        const apiPath = req.url.replace(/^\/pve-api/, '/api2/json')

        // Body sammeln
        const chunks = []
        req.on('data', c => chunks.push(c))
        req.on('end', () => {
          const body = Buffer.concat(chunks)

          // Nur PVE-relevante Headers weiterleiten
          const fwdHeaders = { accept: 'application/json' }
          for (const h of ['authorization', 'content-type', 'cookie', 'csrfpreventiontoken']) {
            if (req.headers[h]) fwdHeaders[h] = req.headers[h]
          }
          if (body.length) fwdHeaders['content-length'] = String(body.length)

          const proxyReq = httpsRequest({
            hostname: host,
            port: Number(port),
            path: apiPath,
            method: req.method,
            headers: fwdHeaders,
            rejectUnauthorized: false,   // <<< self-signed cert
            requestCert: false,
            agent: false,                // kein Connection-Pooling → jede Req neuer Socket
          }, proxyRes => {
            const rh = {
              'access-control-allow-origin': '*',
              'access-control-allow-headers': '*',
              'access-control-allow-methods': '*',
            }
            if (proxyRes.headers['content-type']) rh['content-type'] = proxyRes.headers['content-type']
            if (proxyRes.headers['set-cookie'])   rh['set-cookie']   = proxyRes.headers['set-cookie']

            res.writeHead(proxyRes.statusCode, rh)
            proxyRes.pipe(res)
          })

          proxyReq.on('error', err => {
            if (!res.headersSent) {
              res.writeHead(502, { 'content-type': 'application/json' })
              res.end(JSON.stringify({ error: err.message }))
            }
          })

          if (body.length) proxyReq.write(body)
          proxyReq.end()
        })
      })
    },
  }
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [pveProxy(), react()],
  server: {
    cors: false,  // Vite's eigenen CORS-Handler deaktivieren – wir machen das selbst
  },
})
