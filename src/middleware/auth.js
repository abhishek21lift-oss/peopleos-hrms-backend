// src/middleware/auth.js
const jwt = require('jsonwebtoken');
const pool = require('../db/pool');
const logger = require('../lib/logger');

// In-memory user cache. The token only carries `id`; we re-load the row
// on every request so role / trainer_id / is_active changes propagate
// instantly. To avoid hitting Postgres on every API call, cache the
// resolved user for a short TTL.
const USER_CACHE_TTL_MS = 30000;
const userCache = new Map(); // id -> { user, expiresAt }
function _cacheGet(id) {
  const hit = userCache.get(id);
  if (!hit) return null;
  if (hit.expiresAt < Date.now()) { userCache.delete(id); return null; }
  return hit.user;
}
function _cacheSet(id, user) {
  userCache.set(id, { user, expiresAt: Date.now() + USER_CACHE_TTL_MS });
  if (userCache.size > 500) {
    const oldest = userCache.keys().next().value;
    if (oldest !== undefined) userCache.delete(oldest);
  }
}
function invalidateUserCache(userId) {
  if (userId == null) userCache.clear();
  else userCache.delete(userId);
}

// Periodic cleanup of expired entries (runs every 60s, never prevents exit)
setInterval(() => {
  const now = Date.now();
  for (const [id, entry] of userCache) {
    if (entry.expiresAt < now) userCache.delete(id);
  }
}, 60_000).unref();

async function auth(req, res, next) {
  let token = null;
  const header = req.headers.authorization;
  if (header && header.startsWith('Bearer ')) {
    token = header.slice(7);
  } else if (req.cookies && req.cookies.token) {
    token = req.cookies.token;
  }

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    let user = _cacheGet(decoded.id);
    if (!user) {
      let rows;
      try {
        const result = await pool.query(
          // FIX: token_version is now selected so revocation check below works.
          // member_id is needed by requireSelfOrRole (v3 RBAC).
          // SECURITY: filter out soft-deleted users (deleted_at IS NOT NULL).
          `SELECT id, name, email, role, trainer_id, member_id, branch_id,
                  is_active, token_version
             FROM users
            WHERE id = $1
              AND (deleted_at IS NULL)`,
          [decoded.id]
        );
        rows = result.rows;
      } catch {
        // Fallback if deleted_at column doesn't exist (pre-migration)
        const result = await pool.query(
          `SELECT id, name, email, role, trainer_id, member_id, branch_id,
                  is_active, token_version
             FROM users WHERE id = $1`,
          [decoded.id]
        );
        rows = result.rows;
      }
      user = rows[0];
      if (!user || !user.is_active) {
        return res.status(401).json({ error: 'Account not found or disabled' });
      }
      // Token revocation: if the DB user has a token_version set, the JWT must
      // include a matching token_version. Missing or mismatched versions mean
      // the token was issued before a password change or forced logout.
      if (user.token_version !== null && user.token_version !== undefined) {
        if (decoded.token_version === undefined || decoded.token_version !== user.token_version) {
          return res.status(401).json({ error: 'Token has been revoked. Please log in again.' });
        }
      }
      _cacheSet(user.id, user);
    }

    req.user = user;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Session expired, please log in again' });
    }
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function adminOnly(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

/**
 * Allows admin OR manager roles.
 * Use for operations that managers should be able to perform
 * (e.g. delete trainer, edit plans) but regular staff cannot.
 */
function adminOrManager(req, res, next) {
  const role = req.user?.role;
  if (role !== 'admin' && role !== 'manager') {
    return res.status(403).json({ error: 'Admin or manager access required' });
  }
  next();
}

// FIX (Route Integrity R-09):
// requireRole and requireSelfOrRole were previously duplicated between
// auth.js and rbac.js with different signatures and error response shapes:
//   auth.js   — requireRole(roles: string[])  → { error: 'string' }
//   rbac.js   — requireRole(...roles)          → { error: { code, message } }
//
// The canonical implementations now live in rbac.js. We re-export them
// from auth.js for backward compatibility so existing route files that
// import from './middleware/auth' continue to work without changes.
// Do not re-implement these functions here — import from rbac.js.
const { requireRole, requireSelfOrRole } = require('./rbac');

module.exports = {
  auth,
  adminOnly,
  adminOrManager,
  requireRole,
  requireSelfOrRole,
  invalidateUserCache,
};
