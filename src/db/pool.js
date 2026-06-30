// src/db/pool.js
require('dotenv').config();
const fs = require('fs');
const { Pool } = require('pg');
const logger = require('../lib/logger');

if (!process.env.DATABASE_URL) {
  logger.fatal('DATABASE_URL is not set. Check your .env file.');
  process.exit(1);
}

// Build SSL config:
//   - If DATABASE_SSL_CA is set, use that CA file with full cert verification.
//     This is the most secure option — download the Supabase CA bundle from your
//     project settings and set DATABASE_SSL_CA to its file path.
//   - Otherwise fall back to rejectUnauthorized: false.
//     Supabase's connection pooler (port 6543 / Supavisor) uses a custom CA
//     that is not in the default Node.js trust store, so standard verification
//     fails without the CA bundle. Until DATABASE_SSL_CA is set, the connection
//     is encrypted in transit but the server certificate is not verified.
function buildSslConfig() {
  const caPath = process.env.DATABASE_SSL_CA;
  if (caPath) {
    try {
      return { ca: fs.readFileSync(caPath, 'utf8'), rejectUnauthorized: true };
    } catch (err) {
      logger.fatal({ caPath, err: err.message }, 'DATABASE_SSL_CA file could not be read');
      process.exit(1);
    }
  }
  logger.warn('DATABASE_SSL_CA not set — SSL cert verification disabled. Set DATABASE_SSL_CA to the Supabase CA bundle path to enable full verification.');
  return { rejectUnauthorized: false };
}

const POOL_MAX = (() => {
  const n = parseInt(process.env.DATABASE_POOL_SIZE || '', 10);
  return Number.isFinite(n) && n > 0 ? n : 20;
})();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: buildSslConfig(),
  max: POOL_MAX,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
  // FIX: statement_timeout prevents any single query from hanging the API.
  // 15s is generous for all current queries; adjust down if needed.
  // query_timeout is the node-postgres client-side hard stop.
  statement_timeout: 15000,
  query_timeout: 20000,
});

pool.on('error', (err) => {
  logger.error({ err: err.message }, 'Unexpected DB pool error');
});

// Test connection on startup. Don't crash here — Render's healthcheck will
// surface a 5xx and you can read the log. Crashing prevents redeploys from
// recovering when Supabase has a brief connectivity blip.
pool.connect()
  .then(client => {
    logger.info('Connected to Supabase PostgreSQL');
    client.release();
  })
  .catch(err => {
    logger.error({ err: err.message }, 'Database connection failed on startup');
    logger.error('  1. Check DATABASE_URL is set in your .env / Render env');
    logger.error('  2. Check the Supabase project is not paused');
    logger.error('  3. Check the password in the URI matches your DB password');
  });

module.exports = pool;
