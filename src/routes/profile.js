const router = require('express').Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const { authenticator } = require('otplib');
const pool = require('../db/pool');
const logger = require('../lib/logger');
const { auth, invalidateUserCache } = require('../middleware/auth');

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter(_req, file, cb) {
    if (!/^image\/(png|jpe?g|webp|gif)$/i.test(file.mimetype || '')) {
      return cb(new Error('Only PNG, JPG, WEBP, or GIF images are allowed'));
    }
    cb(null, true);
  },
});

const defaultNotifications = {
  email_logins: true,
  email_payments: true,
  email_reports: true,
  email_marketing: false,
  push_logins: true,
  push_tasks: true,
  push_mentions: true,
  whatsapp_alerts: false,
  frequency: 'instant',
};

const defaultPreferences = {
  theme: 'system',
  language: 'en',
  timezone: 'Asia/Calcutta',
  dateFormat: 'DD/MM/YYYY',
  timeFormat: '12h',
  compactMode: false,
};

let schemaInitialized = false;

function jsonOrDefault(value, fallback) {
  if (!value) return { ...fallback };
  if (typeof value === 'object') return { ...fallback, ...value };
  try {
    return { ...fallback, ...JSON.parse(value) };
  } catch {
    return { ...fallback };
  }
}

function clientInfo(req) {
  const ua = String(req.headers['user-agent'] || '');
  const browser = /Chrome/i.test(ua) ? 'Chrome'
    : /Firefox/i.test(ua) ? 'Firefox'
    : /Safari/i.test(ua) ? 'Safari'
    : /Edge/i.test(ua) ? 'Edge'
    : 'Browser';
  const os = /Windows/i.test(ua) ? 'Windows'
    : /Mac OS|Macintosh/i.test(ua) ? 'macOS'
    : /Android/i.test(ua) ? 'Android'
    : /iPhone|iPad/i.test(ua) ? 'iOS'
    : /Linux/i.test(ua) ? 'Linux'
    : 'Unknown OS';
  const type = /Mobile|Android|iPhone/i.test(ua) ? 'mobile' : /iPad|Tablet/i.test(ua) ? 'tablet' : 'desktop';
  return { browser, os, type, ip: req.ip || '' };
}

async function ensureSchema() {
  if (!schemaInitialized) {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_profiles (
        user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        phone TEXT,
        location TEXT,
        bio TEXT,
        avatar_url TEXT,
        notification_preferences JSONB NOT NULL DEFAULT '{}'::jsonb,
        preferences JSONB NOT NULL DEFAULT '{}'::jsonb,
        mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
        mfa_secret TEXT,
        mfa_recovery_codes TEXT[],
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    schemaInitialized = true;
  }
}


async function profileFor(userId) {
  await ensureSchema();
  await pool.query('INSERT INTO user_profiles (user_id) VALUES ($1) ON CONFLICT DO NOTHING', [userId]);
  const { rows } = await pool.query(
    `SELECT u.id, u.name, u.email, u.role, u.created_at, u.last_login,
            p.phone, p.location, p.bio, p.avatar_url,
            p.notification_preferences, p.preferences, p.mfa_enabled
       FROM users u
  LEFT JOIN user_profiles p ON p.user_id = u.id
      WHERE u.id = $1`,
    [userId]
  );
  return rows[0];
}

function shapeProfile(row) {
  return {
    id: row.id,
    name: row.name || '',
    email: row.email || '',
    phone: row.phone || '',
    role: row.role || '',
    location: row.location || '',
    bio: row.bio || '',
    avatarUrl: row.avatar_url || null,
    createdAt: row.created_at,
    lastLoginAt: row.last_login,
    mfaEnabled: Boolean(row.mfa_enabled),
  };
}

async function logActivity(req, action, entityType, entityId, data) {
  try {
    await pool.query(
      `INSERT INTO activity_log
        (user_id, user_name, action, entity_type, entity_id, new_data, ip_address, user_agent)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        req.user.id,
        req.user.name || null,
        action,
        entityType || 'profile',
        entityId || req.user.id,
        data ? JSON.stringify(data) : null,
        req.ip || null,
        req.headers['user-agent'] || null,
      ]
    );
  } catch (err) {
    logger.warn({ err: err.message }, 'profile activity log failed');
  }
}

router.use(auth);

router.get('/me', async (req, res, next) => {
  try {
    const row = await profileFor(req.user.id);
    res.json(shapeProfile(row));
  } catch (err) {
    next(err);
  }
});

router.put('/me', async (req, res, next) => {
  try {
    await ensureSchema();
    const name = String(req.body.name || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const phone = String(req.body.phone || '').trim();
    const location = String(req.body.location || '').trim();
    const bio = String(req.body.bio || '').trim();

    if (!name) return res.status(400).json({ error: 'Name is required' });
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      return res.status(400).json({ error: 'Valid email is required' });
    }

    const existing = await pool.query(
      'SELECT id FROM users WHERE LOWER(email) = LOWER($1) AND id <> $2 AND deleted_at IS NULL',
      [email, req.user.id]
    );
    if (existing.rows.length) return res.status(409).json({ error: 'Email already registered' });

    await pool.query('UPDATE users SET name = $1, email = $2, updated_at = NOW() WHERE id = $3', [name, email, req.user.id]);
    await pool.query(
      `INSERT INTO user_profiles (user_id, phone, location, bio, updated_at)
       VALUES ($1,$2,$3,$4,NOW())
       ON CONFLICT (user_id) DO UPDATE
       SET phone = EXCLUDED.phone,
           location = EXCLUDED.location,
           bio = EXCLUDED.bio,
           updated_at = NOW()`,
      [req.user.id, phone, location, bio]
    );
    invalidateUserCache(req.user.id);
    await logActivity(req, 'profile.update', 'user', req.user.id, { name, email });
    const row = await profileFor(req.user.id);
    res.json(shapeProfile(row));
  } catch (err) {
    next(err);
  }
});

router.post('/avatar', upload.single('avatar'), async (req, res, next) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'Avatar file is required' });
    await ensureSchema();

    const ext = ({ 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp', 'image/gif': 'gif' })[req.file.mimetype] || 'bin';
    const dir = path.join(__dirname, '..', '..', 'uploads', 'profile');
    fs.mkdirSync(dir, { recursive: true });
    const filename = `${req.user.id}-${Date.now()}.${ext}`;
    fs.writeFileSync(path.join(dir, filename), req.file.buffer);
    const avatarUrl = `/uploads/profile/${filename}`;

    await pool.query(
      `INSERT INTO user_profiles (user_id, avatar_url, updated_at)
       VALUES ($1,$2,NOW())
       ON CONFLICT (user_id) DO UPDATE
       SET avatar_url = EXCLUDED.avatar_url, updated_at = NOW()`,
      [req.user.id, avatarUrl]
    );
    await logActivity(req, 'profile.avatar.update', 'user', req.user.id);
    res.json({ avatarUrl });
  } catch (err) {
    next(err);
  }
});

router.put('/password', async (req, res, next) => {
  try {
    const currentPassword = String(req.body.currentPassword || req.body.current || '');
    const newPassword = String(req.body.newPassword || req.body.password || '');
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Both current and new password are required' });
    if (newPassword.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters' });

    const { rows } = await pool.query('SELECT password FROM users WHERE id = $1', [req.user.id]);
    if (!rows[0]) return res.status(404).json({ error: 'User not found' });
    const valid = await bcrypt.compare(currentPassword, rows[0].password);
    if (!valid) return res.status(401).json({ error: 'Current password is incorrect' });

    const hashed = await bcrypt.hash(newPassword, 12);
    await pool.query(
      'UPDATE users SET password = $1, token_version = token_version + 1, updated_at = NOW() WHERE id = $2',
      [hashed, req.user.id]
    );
    invalidateUserCache(req.user.id);
    await logActivity(req, 'profile.password.update', 'user', req.user.id);
    res.json({ message: 'Password updated' });
  } catch (err) {
    next(err);
  }
});

router.post('/mfa/setup', async (req, res, next) => {
  try {
    await ensureSchema();
    const secret = authenticator.generateSecret();
    await pool.query(
      `INSERT INTO user_profiles (user_id, mfa_secret, updated_at)
       VALUES ($1,$2,NOW())
       ON CONFLICT (user_id) DO UPDATE
       SET mfa_secret = EXCLUDED.mfa_secret, updated_at = NOW()`,
      [req.user.id, secret]
    );
    res.json({
      secret,
      qrUrl: `otpauth://totp/619-ERP:${encodeURIComponent(req.user.email)}?secret=${secret}&issuer=619-ERP`,
    });
  } catch (err) {
    next(err);
  }
});

router.post('/mfa/verify', async (req, res, next) => {
  try {
    const code = String(req.body.code || '').trim();
    if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: 'Valid MFA code is required' });
    await ensureSchema();
    const { rows } = await pool.query('SELECT mfa_secret FROM user_profiles WHERE user_id = $1', [req.user.id]);
    const storedSecret = rows[0] && rows[0].mfa_secret;
    if (!storedSecret) return res.status(400).json({ error: 'MFA setup required before verification' });
    const valid = authenticator.check(code, storedSecret, { window: 1 });
    if (!valid) return res.status(400).json({ error: 'Invalid MFA code' });

    // Generate recovery codes (plaintext, returned once to user), store hashed
    const recoveryCodes = Array.from({ length: 8 }, () => crypto.randomBytes(4).toString('hex').toUpperCase());
    const hashedCodes = await Promise.all(recoveryCodes.map(c => bcrypt.hash(c, 10)));

    await pool.query(
      `UPDATE user_profiles
          SET mfa_enabled = TRUE, mfa_recovery_codes = $2, updated_at = NOW()
        WHERE user_id = $1`,
      [req.user.id, hashedCodes]
    );
    await logActivity(req, 'profile.mfa.enable', 'user', req.user.id);
    res.json({ recoveryCodes });
  } catch (err) {
    next(err);
  }
});

router.delete('/mfa', async (req, res, next) => {
  try {
    await ensureSchema();
    await pool.query('UPDATE user_profiles SET mfa_enabled = FALSE, mfa_secret = NULL, updated_at = NOW() WHERE user_id = $1', [req.user.id]);
    await logActivity(req, 'profile.mfa.disable', 'user', req.user.id);
    res.json({ message: 'MFA disabled' });
  } catch (err) {
    next(err);
  }
});

router.get('/notifications', async (req, res, next) => {
  try {
    const row = await profileFor(req.user.id);
    res.json(jsonOrDefault(row.notification_preferences, defaultNotifications));
  } catch (err) {
    next(err);
  }
});

router.put('/notifications', async (req, res, next) => {
  try {
    await ensureSchema();
    const preferences = jsonOrDefault(req.body, defaultNotifications);
    await pool.query(
      `INSERT INTO user_profiles (user_id, notification_preferences, updated_at)
       VALUES ($1,$2::jsonb,NOW())
       ON CONFLICT (user_id) DO UPDATE
       SET notification_preferences = EXCLUDED.notification_preferences, updated_at = NOW()`,
      [req.user.id, JSON.stringify(preferences)]
    );
    res.json(preferences);
  } catch (err) {
    next(err);
  }
});

router.get('/preferences', async (req, res, next) => {
  try {
    const row = await profileFor(req.user.id);
    res.json(jsonOrDefault(row.preferences, defaultPreferences));
  } catch (err) {
    next(err);
  }
});

router.put('/preferences', async (req, res, next) => {
  try {
    await ensureSchema();
    const preferences = jsonOrDefault(req.body, defaultPreferences);
    await pool.query(
      `INSERT INTO user_profiles (user_id, preferences, updated_at)
       VALUES ($1,$2::jsonb,NOW())
       ON CONFLICT (user_id) DO UPDATE
       SET preferences = EXCLUDED.preferences, updated_at = NOW()`,
      [req.user.id, JSON.stringify(preferences)]
    );
    res.json(preferences);
  } catch (err) {
    next(err);
  }
});

router.get('/devices', (req, res) => {
  const info = clientInfo(req);
  res.json([{
    id: 'current',
    name: `${info.browser} on ${info.os}`,
    type: info.type,
    browser: info.browser,
    os: info.os,
    ip: info.ip,
    location: 'Current network',
    lastSeen: new Date().toISOString(),
    isCurrent: true,
  }]);
});

router.delete('/devices/:id', (req, res) => {
  if (req.params.id === 'current') return res.status(400).json({ error: 'Cannot revoke the current device here' });
  res.json({ message: 'Device revoked' });
});

router.get('/sessions', (req, res) => {
  const info = clientInfo(req);
  res.json([{
    id: 'current',
    ip: info.ip,
    location: 'Current network',
    device: `${info.type} device`,
    browser: info.browser,
    createdAt: req.user.last_login || new Date().toISOString(),
    lastActive: new Date().toISOString(),
    isCurrent: true,
  }]);
});

router.delete('/sessions/:id', (req, res) => {
  if (req.params.id === 'current') return res.status(400).json({ error: 'Cannot revoke the current session here' });
  res.json({ message: 'Session revoked' });
});

router.post('/sessions/revoke-all', async (req, res, next) => {
  try {
    await pool.query('UPDATE users SET token_version = token_version + 1, updated_at = NOW() WHERE id = $1', [req.user.id]);
    invalidateUserCache(req.user.id);
    await logActivity(req, 'profile.sessions.revoke_all', 'user', req.user.id);
    res.clearCookie('token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      path: '/',
    });
    res.json({ message: 'All sessions revoked' });
  } catch (err) {
    next(err);
  }
});

router.get('/activity', async (req, res, next) => {
  try {
    const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 20, 1), 100);
    const offset = (page - 1) * limit;
    const category = String(req.query.category || '').trim();
    const params = [req.user.id];
    const conds = ['user_id = $1'];
    if (category && category !== 'all') {
      params.push(`${category}.%`);
      conds.push(`action LIKE $${params.length}`);
    }
    const where = conds.join(' AND ');
    const count = await pool.query(`SELECT COUNT(*)::int AS total FROM activity_log WHERE ${where}`, params);
    params.push(limit, offset);
    const { rows } = await pool.query(
      `SELECT id, action, entity_type, ip_address, created_at
         FROM activity_log
        WHERE ${where}
        ORDER BY created_at DESC
        LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );
    const total = count.rows[0]?.total || 0;
    res.json({
      events: rows.map((row) => ({
        id: row.id,
        type: row.action,
        description: row.action.replace(/\./g, ' '),
        ip: row.ip_address || '',
        location: 'Current network',
        createdAt: row.created_at,
        category: row.action.split('.')[0] || 'system',
      })),
      hasMore: offset + rows.length < total,
      total,
    });
  } catch (err) {
    next(err);
  }
});

router.ensureSchema = ensureSchema;
module.exports = router;
