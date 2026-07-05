// src/middleware/originCheck.js
// Defense-in-depth: reject API requests from unexpected origins.
// Mount AFTER CORS but BEFORE routes.
//
// This catches request smuggling, DNS rebinding, and cases where
// CORS preflight passes but the actual request should be blocked.
// It's safe because legitimate browsers always send Origin or Referer.

const logger = require('../lib/logger');

function originCheck(req, res, next) {
  // Skip for server-to-server calls (no origin) and health checks
  if (!req.headers.origin && !req.headers.referer) return next();
  if (req.path === '/health') return next();

  const origin = req.headers.origin || req.headers.referer;
  if (!origin) return next();

  try {
    const url = new URL(origin);
    const hostname = url.hostname;

    // Allow localhost in development
    if (hostname === 'localhost' || hostname === '127.0.0.1') return next();

    // Allow known frontend domains
    const allowedHosts = [
      ...(process.env.FRONTEND_URL ? [new URL(process.env.FRONTEND_URL).hostname] : []),
      ...(process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',').map(function(o) {
        try { return new URL(o.trim()).hostname; } catch { return null; }
      }).filter(Boolean) : []),
    ];

    if (allowedHosts.includes(hostname)) return next();

    // Allow all Vercel preview/production deployments
    if (hostname.endsWith('.vercel.app')) return next();

    logger.warn({ origin: origin, hostname: hostname, path: req.path }, 'Origin check failed');
    return res.status(403).json({ error: 'Forbidden' });
  } catch {
    // Invalid URL in origin/referer — just log and deny
    logger.warn({ origin: origin, path: req.path }, 'Invalid origin header');
    return res.status(400).json({ error: 'Invalid request' });
  }
}

module.exports = { originCheck };
