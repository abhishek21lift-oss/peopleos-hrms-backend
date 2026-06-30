// src/server.js
// 619 ERP API — consolidated v2 + v3 entry point
// ───────────────────────────────────────────────────
// STARTUP ENV CHECKS — fail fast with clear messages
// ───────────────────────────────────────────────────
require('dotenv').config();

const logger = require('./lib/logger');

const REQUIRED_ENV = ['DATABASE_URL', 'JWT_SECRET', 'FRONTEND_URL'];
const missing = REQUIRED_ENV.filter(function(k) { return !process.env[k]; });
if (missing.length) {
  logger.fatal({ missing }, 'Missing required environment variables');
  console.error('  Set them in your .env file or your Render dashboard.');
  process.exit(1);
}

if (process.env.JWT_SECRET.length < 32) {
  logger.fatal('JWT_SECRET is too short (minimum 32 characters). Use a strong random secret (96 hex chars recommended).');
  process.exit(1);
}

const express   = require('express');
const cors      = require('cors');
const helmet    = require('helmet');
const rateLimit     = require('express-rate-limit');
const cookieParser  = require('cookie-parser');
const path = require('path');

const { errorHandler, notFound } = require('./middleware/errorHandler');
const { auth, adminOnly }        = require('./middleware/auth');

const app  = express();
const PORT = Number(process.env.PORT) || 5000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const isProd = NODE_ENV === 'production';

// Behind Render / Vercel / Cloudflare — trust the first proxy so
// req.ip is real and rate-limit keys aren’t bucketed to one IP.
app.set('trust proxy', 1);
app.disable('x-powered-by');

// ────────────────────────
// SECURITY
// ────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'none'"],
      scriptSrc: ["'none'"],
      styleSrc: ["'none'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      fontSrc: ["'none'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'none'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: false },
}));

// ────────────────────────
// CORS
// ────────────────────────
function validOrigin(origin) {
  if (!origin) return null;
  const trimmed = origin.trim();
  try {
    const url = new URL(trimmed);
    if (!['http:', 'https:'].includes(url.protocol)) throw new Error('invalid protocol');
    return url.origin;
  } catch {
    logger.warn({ origin: trimmed }, 'Ignoring invalid CORS origin');
    return null;
  }
}

const allowedOrigins = [
  ...(process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',').map(validOrigin) : []),
  validOrigin(process.env.FRONTEND_URL),
  'http://localhost:3000',
  'http://127.0.0.1:3000',
].filter(Boolean);

app.use(cors({
  origin: function(origin, cb) {
    if (!origin) return cb(null, true);
    if (allowedOrigins.includes(origin)) return cb(null, true);
    logger.warn({ origin }, 'CORS blocked origin');
    return cb(new Error('CORS: origin not allowed'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// ────────────────────────
// BODY PARSING
// ────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use('/uploads', express.static(path.join(__dirname, '..', 'uploads'), {
  maxAge: isProd ? '7d' : 0,
  fallthrough: false,
}));

// ────────────────────────
// ORIGIN / REFERER CHECK (defense-in-depth)
// ────────────────────────
const { originCheck } = require('./middleware/originCheck');
app.use('/api/', originCheck);

// ────────────────────────
// INPUT SANITIZATION
// ────────────────────────
const { sanitizeBody, sanitizeQuery } = require('./middleware/sanitize');
app.use(sanitizeBody);
app.use(sanitizeQuery);

// ────────────────────────
// REQUEST ID
// ────────────────────────
const requestId = require('./middleware/requestId');
app.use(requestId);

// ────────────────────────
// STRUCTURED REQUEST LOGGER
// ────────────────────────
app.use(function(req, res, next) {
  const start = Date.now();
  res.on('finish', function() {
    const ms = Date.now() - start;
    if (req.path.startsWith('/api/')) {
      logger.info({
        method: req.method,
        url: req.originalUrl,
        status: res.statusCode,
        ms: ms,
        req_id: req.id,
        query: Object.keys(req.query).length ? req.query : undefined,
      }, '%s %s %d %dms', req.method, req.originalUrl, res.statusCode, ms);
    }
  });
  next();
});

// ────────────────────────
// HEALTH CHECK
// ────────────────────────
app.get('/', function(req, res) {
  res.json({ status: 'ok', app: '619 ERP API', version: '3.0.0' });
});

app.get('/api/health', function(req, res) {
  res.json({
    status: 'ok',
    version: 'v3',
    time: new Date().toISOString(),
    env: {
      mode: NODE_ENV,
      database: !!process.env.DATABASE_URL,
      jwt: !!process.env.JWT_SECRET,
      frontend: allowedOrigins.filter(function(o) { return !o.includes('localhost') && !o.includes('127.0.0.1'); }),
    },
  });
});



// ────────────────────────
// RATE LIMITING
// ────────────────────────
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: isProd ? 2000 : 5000,
  standardHeaders: true,
  legacyHeaders: false,
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Please wait 15 minutes.' },
});

const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many account creation attempts. Please wait 15 minutes.' },
});

app.use('/api/', apiLimiter);
app.use('/api/auth/login',        loginLimiter);
app.use('/api/v1/auth/login',     loginLimiter);
app.use('/api/v1/auth/forgot-password', registerLimiter);
app.use('/api/v1/auth/reset-password',  registerLimiter);
app.use('/api/auth/create-user', registerLimiter);
app.use('/api/auth/users',      registerLimiter);
app.use('/api/auth/forgot-password', registerLimiter);
app.use('/api/auth/reset-password',  registerLimiter);

// ────────────────────────
// v2 ROUTES (production)
// ────────────────────────

// ROUTE INTEGRITY NOTE (R-01):
// /api/auth and /api/v1/auth both mount the same router intentionally.
// /api/v1/auth exists for legacy mobile app callers. Any changes to auth
// behaviour must be tested against both URL prefixes.
app.use('/api/auth',              require('./routes/auth'));
app.use('/api/v1/auth',           require('./routes/auth'));
app.use('/api/profile',           require('./routes/profile'));

// ROUTE INTEGRITY NOTE (R-02):
// /api/clients mounts two separate routers. Express resolves in registration
// order — if both files define the same METHOD+PATH, client-actions.js will
// be shadowed. Audit both files for overlapping routes before adding new ones.
app.use('/api/clients',           require('./routes/clients'));
app.use('/api/clients',           require('./routes/client-actions'));

app.use('/api/trainers',          require('./routes/trainers'));
app.use('/api/payments',          require('./routes/payments'));
app.use('/api/attendance',        require('./routes/attendance'));
app.use('/api/checkin',           require('./routes/checkin'));

// ROUTE INTEGRITY NOTE (R-03):
// Legacy /api/reports (routes/reports.js) and v3 /api/v1/reports
// (modules/reports) coexist. Frontend pages must call the correct version.
// New pages should use /api/v1/reports. Do not add endpoints to the legacy
// router — it will be removed once all consumers are migrated.
app.use('/api/reports',           require('./routes/reports'));

app.use('/api/plans',             require('./routes/plans'));
app.use('/api/staff',             require('./routes/staff'));
app.use('/api/leave',             require('./routes/leave'));
app.use('/api/expenses',          require('./routes/expenses'));
app.use('/api/import',            require('./routes/import'));  // FIX: was never mounted

// ROUTE INTEGRITY NOTE (R-03 / bookings):
// /api/bookings and /api/v1/bookings both mount the same router.
// Same policy as auth: legacy callers use /api/bookings, new callers use /api/v1/bookings.
app.use('/api/v1/bookings',       require('./modules/bookings/bookings.routes'));
app.use('/api/bookings',          require('./modules/bookings/bookings.routes'));

// FIX (Route Integrity R-10):
// /api/admin previously relied solely on individual route handlers to apply
// auth + adminOnly middleware. This left the mount unguarded — any handler
// that forgot to include the middleware chain would be publicly accessible.
// We now enforce auth + adminOnly at the mount level as defense-in-depth.
// Individual handlers may still include the middleware; it is a no-op.
app.use('/api/admin',             auth, adminOnly, require('./routes/admin-reset'));

app.use('/api/modules',           require('./modules/operations/operations.routes'));

// ────────────────────────
// PREMIUM FEATURE ROUTES (v4)
// ────────────────────────
app.use('/api/settings',          require('./routes/settings'));
app.use('/api/invoices',          require('./routes/invoices'));
app.use('/api/workouts',          require('./routes/workouts'));
app.use('/api/diet',              require('./routes/diet'));

// ────────────────────────
// MEMBER PORTAL ROUTES
// ────────────────────────
app.use('/api/classes',           require('./routes/classes'));

// ────────────────────────
// PT OS — Personal Training Operating System
// ────────────────────────
app.use('/api/pt-os',            require('./modules/pt-os/pt-os.routes'));

// ────────────────────────
// BUSINESS FLOW ROUTES (v4 — Progress, Automation)
// ────────────────────────
app.use('/api/progress',         require('./modules/progress/progress.routes'));
app.use('/api/automation',       require('./modules/automation/automation.routes'));

// ────────────────────────
// v3 MODULE ROUTES
// ────────────────────────
app.use('/api/v1/members',        require('./modules/members/members.routes'));
app.use('/api/v1/pt-sessions',    require('./modules/sessions/sessions.routes'));
app.use('/api/v1/notifications',  require('./modules/notifications/notifications.routes'));
app.use('/api/v1/reports',        require('./modules/reports/reports.routes'));

// ────────────────────────
// 404 + GLOBAL ERROR HANDLER
// ────────────────────────
app.use(notFound);
app.use(errorHandler);

// ────────────────────────
// START — run migrations first, then listen
// ────────────────────────
const { runMigrations } = require('./db/migrate');
const profileRoute = require('./routes/profile');

logger.info('Running database migrations…');
runMigrations()
  .then(function() {
    return profileRoute.ensureSchema();
  })
  .then(function() {
    const server = app.listen(PORT, '0.0.0.0', function() {
      logger.info({
        port: PORT,
        env: NODE_ENV,
        corsOrigins: allowedOrigins.length ? allowedOrigins : '(server-to-server only)',
      }, '619 ERP API listening on port %d (%s)', PORT, NODE_ENV);
    });

    const pool = require('./db/pool');
    function shutdown(sig) {
      return function() {
        logger.info({ signal: sig }, 'Received signal — shutting down');
        server.close(function() {
          pool.end(function() { process.exit(0); });
        });
        setTimeout(function() { process.exit(1); }, 10_000).unref();
      };
    }
    process.on('SIGTERM', shutdown('SIGTERM'));
    process.on('SIGINT',  shutdown('SIGINT'));
  })
  .catch(function(err) {
    logger.fatal({ err: err.message }, 'Startup migration failed');
    process.exit(1);
  });

process.on('unhandledRejection', (reason) => {
  logger.error({ reason }, 'unhandledRejection');
});
process.on('uncaughtException', (err) => {
  logger.fatal({ err }, 'uncaughtException — exiting');
  process.exit(1);
});

module.exports = app;
