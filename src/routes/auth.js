// src/routes/auth.js
const router = require('express').Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt    = require('jsonwebtoken');
const pool   = require('../db/pool');
const logger = require('../lib/logger');
const { auth, adminOnly, invalidateUserCache } = require('../middleware/auth');
const { validate } = require('../middleware/validate');
const { authSchemas } = require('../lib/validation');
const { sendPasswordReset } = require('../lib/email');

const isProd = process.env.NODE_ENV === 'production';

function setTokenCookie(res, token) {
  res.cookie('token', token, {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: '/',
  });
}

// POST /api/auth/login
router.post('/login', validate(authSchemas.login), async (req, res) => {
  try {
    const { email, password } = req.body;

    // ── Fetch user from DB ─────────────────────────────
    let rows;
    try {
      const result = await pool.query(
        'SELECT id, email, password, role, mfa_enabled, mfa_secret, token_version, is_active, trainer_id, member_id, name FROM users WHERE LOWER(email) = LOWER($1) AND is_active = true',
        [email]
      );
      rows = result.rows;
    } catch (dbErr) {
      logger.error({ err: dbErr.message }, 'Login DB error');
      return res.status(500).json({ error: 'Database connection error. Please try again.' });
    }

    const user = rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });

    // ── Verify password ────────────────────────────────
    let valid = false;
    try {
      valid = await bcrypt.compare(password, user.password);
    } catch (bcryptErr) {
      logger.error({ err: bcryptErr.message }, 'bcrypt error');
      return res.status(500).json({ error: 'Authentication error. Please try again.' });
    }

    if (!valid) return res.status(401).json({ error: 'Invalid email or password' });

    // ── MFA check — issue pre-auth token if MFA is enabled ────────
    if (user.mfa_enabled) {
      const preAuthToken = jwt.sign(
        { sub: user.id, type: 'mfa_required' },
        process.env.JWT_SECRET,
        { expiresIn: '5m' }
      );
      return res.status(200).json({ mfa_required: true, pre_auth_token: preAuthToken });
    }

    // ── Update last login (non-critical, don't block on failure) ──
    pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id])
      .catch(function(err) { logger.warn({ err: err.message }, 'last_login update failed (non-critical)'); });

    // ── Sign JWT ───────────────────────────────────────
    let token;
    try {
      token = jwt.sign(
        { id: user.id, token_version: user.token_version },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
      );
    } catch (jwtErr) {
      logger.error({ err: jwtErr.message }, 'JWT sign error');
      return res.status(500).json({ error: 'Token generation failed. Contact administrator.' });
    }

    setTokenCookie(res, token);

    res.json({
      user: {
        id:         user.id,
        name:       user.name,
        email:      user.email,
        role:       user.role,
        trainer_id: user.trainer_id,
        member_id:  user.member_id,
      },
    });

  } catch (err) {
    logger.error({ err: err.message, stack: err.stack }, 'Unexpected login error');
    res.status(500).json({ error: 'Unexpected server error. Please try again.' });
  }
});

// POST /api/auth/mfa/verify — verify TOTP code after pre-auth token step
router.post('/mfa/verify', async (req, res) => {
  try {
    const { code, pre_auth_token } = req.body;
    if (!code || !pre_auth_token) {
      return res.status(400).json({ error: 'code and pre_auth_token are required' });
    }

    let decoded;
    try {
      decoded = jwt.verify(pre_auth_token, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ error: 'Invalid or expired pre-auth token' });
    }

    if (decoded.type !== 'mfa_required') {
      return res.status(401).json({ error: 'Invalid token type' });
    }

    const userId = decoded.sub;
    const { rows } = await pool.query(
      'SELECT id, name, email, role, trainer_id, member_id, token_version, is_active FROM users WHERE id = $1 AND is_active = true',
      [userId]
    );
    if (!rows[0]) return res.status(401).json({ error: 'User not found or disabled' });
    const user = rows[0];

    // Fetch MFA secret from user_profiles
    const { rows: profileRows } = await pool.query(
      'SELECT mfa_secret FROM user_profiles WHERE user_id = $1',
      [userId]
    );
    const mfaSecret = profileRows[0] && profileRows[0].mfa_secret;
    if (!mfaSecret) return res.status(400).json({ error: 'MFA not configured' });

    const { authenticator } = require('otplib');
    const valid = authenticator.check(code, mfaSecret, { window: 1 });
    if (!valid) return res.status(401).json({ error: 'Invalid MFA code' });

    pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [userId])
      .catch(function(err) { logger.warn({ err: err.message }, 'last_login update failed (non-critical)'); });

    const token = jwt.sign(
      { id: user.id, token_version: user.token_version },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );

    setTokenCookie(res, token);
    res.json({
      user: {
        id:         user.id,
        name:       user.name,
        email:      user.email,
        role:       user.role,
        trainer_id: user.trainer_id,
        member_id:  user.member_id,
      },
    });
  } catch (err) {
    logger.error({ err: err.message }, 'MFA verify error');
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/auth/logout
router.post('/logout', function(req, res) {
  res.clearCookie('token', {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    path: '/',
  });
  res.json({ message: 'Logged out' });
});

// POST /api/auth/forgot-password
router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });

    const rawToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(rawToken).digest('hex');

    const { rows } = await pool.query(
      'SELECT id FROM users WHERE LOWER(email) = LOWER($1)',
      [email]
    );

    if (rows.length) {
      await pool.query(
        'UPDATE users SET password_reset_token = $1, password_reset_expires = NOW() + INTERVAL \'1 hour\' WHERE id = $2',
        [hashedToken, rows[0].id]
      );
      // FIX: await + .catch so email failures are logged instead of silently swallowed
      sendPasswordReset(email, rawToken)
        .catch(function(err) { logger.warn({ err: err.message }, 'Password reset email failed (non-critical)'); });
    }

    // Always return success — don't reveal if email exists
    res.json({ message: 'If the email exists, a reset link has been sent.' });
  } catch (err) {
    logger.error({ err: err.message }, 'Forgot password error');
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/auth/reset-password
router.post('/reset-password', async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token || !password) return res.status(400).json({ error: 'Token and password are required' });
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    const { rows } = await pool.query(
      'SELECT id FROM users WHERE password_reset_token = $1 AND password_reset_expires > NOW()',
      [hashedToken]
    );

    if (!rows.length) return res.status(400).json({ error: 'Invalid or expired reset token' });

    const hashed = await bcrypt.hash(password, 12);
    await pool.query(
      'UPDATE users SET password = $1, token_version = token_version + 1, password_reset_token = NULL, password_reset_expires = NULL, updated_at = NOW() WHERE id = $2',
      [hashed, rows[0].id]
    );
    invalidateUserCache(rows[0].id);

    res.json({ message: 'Password reset successfully. Please log in with your new password.' });
  } catch (err) {
    logger.error({ err: err.message }, 'Reset password error');
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/auth/me
router.get('/me', auth, (req, res) => {
  res.json({ user: req.user });
});

// PUT /api/auth/change-password
// Also accepts POST for backwards compatibility with older frontend builds
async function changePasswordHandler(req, res) {
  try {
    // Accept both new and legacy field names so a stale frontend still works
    const currentPassword = (
      req.body.currentPassword ?? req.body.current ?? req.body.oldPassword ?? ''
    ).trim();
    const newPassword = (
      req.body.newPassword ?? req.body.newPw ?? req.body.password ?? ''
    ).trim();

    if (!currentPassword || !newPassword)
      return res.status(400).json({ error: 'Both current and new password are required' });
    if (typeof newPassword !== 'string' || newPassword.length < 8)
      return res.status(400).json({ error: 'New password must be at least 8 characters' });

    const { rows } = await pool.query(
      'SELECT password FROM users WHERE id = $1', [req.user.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'User not found' });

    const valid = await bcrypt.compare(currentPassword, rows[0].password);
    if (!valid) return res.status(401).json({ error: 'Current password is incorrect' });

    const hashed = await bcrypt.hash(newPassword, 12);
    await pool.query(
      'UPDATE users SET password = $1, token_version = token_version + 1, updated_at = NOW() WHERE id = $2',
      [hashed, req.user.id]
    );
    invalidateUserCache(req.user.id);
    const { rows: updated } = await pool.query(
      'SELECT token_version FROM users WHERE id = $1', [req.user.id]
    );
    const newToken = jwt.sign(
      { id: req.user.id, token_version: updated[0].token_version },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );
    setTokenCookie(res, newToken);
    res.json({ message: 'Password changed successfully' });
  } catch (err) {
    logger.error({ err: err.message }, 'Change password error');
    res.status(500).json({ error: 'Server error' });
  }
}
router.put('/change-password', auth, validate(authSchemas.changePassword), changePasswordHandler);
router.post('/change-password', auth, validate(authSchemas.changePassword), changePasswordHandler);

// POST /api/auth/create-user  (admin only)
// Also accepts /users for compatibility with older frontend builds
const ALLOWED_ROLES = ['admin', 'manager', 'trainer', 'reception', 'member'];

async function createUserHandler(req, res) {
  try {
    const { name, email, password, role = 'trainer', trainer_id, member_id } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ error: 'Name, email and password required' });
    if (password.length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    if (!ALLOWED_ROLES.includes(role))
      return res.status(400).json({ error: `Role must be one of: ${ALLOWED_ROLES.join(', ')}` });

    // If a trainer_id is supplied, make sure it actually exists. Otherwise
    // we'd happily create an orphaned link that breaks the dashboard later.
    if (trainer_id) {
      const { rows: t } = await pool.query('SELECT 1 FROM trainers WHERE id = $1', [trainer_id]);
      if (!t.length) return res.status(400).json({ error: 'trainer_id does not match an existing trainer' });
    }

    const { rows: exists } = await pool.query(
      'SELECT id FROM users WHERE LOWER(email) = LOWER($1)', [email.trim()]
    );
    if (exists.length) return res.status(409).json({ error: 'Email already registered' });

    const hashed = await bcrypt.hash(password, 12);
    const id = crypto.randomUUID();
    await pool.query(
      'INSERT INTO users (id, name, email, password, role, trainer_id, member_id) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [id, name.trim(), email.toLowerCase().trim(), hashed, role, trainer_id || null, member_id || null]
    );
    res.status(201).json({ message: 'User created', user: { id, name, email: email.toLowerCase(), role } });
  } catch (err) {
    logger.error({ err: err.message }, 'Create user error');
    res.status(500).json({ error: 'Server error' });
  }
}
router.post('/create-user', auth, adminOnly, validate(authSchemas.createUser), createUserHandler);
// Compatibility alias — the frontend at one point posted here
router.post('/users', auth, adminOnly, validate(authSchemas.createUser), createUserHandler);

// GET /api/auth/users  (admin only)
router.get('/users', auth, adminOnly, async (req, res) => {
  try {
    const limit  = Math.min(parseInt(req.query.limit, 10) || 100, 500);
    const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
    const { rows } = await pool.query(
      'SELECT id, name, email, role, trainer_id, is_active, last_login, created_at FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2',
      [limit, offset]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// PUT /api/auth/users/:id/toggle  (admin only)
router.put('/users/:id/toggle', auth, adminOnly, async (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'Cannot disable yourself' });
  try {
    const { rows } = await pool.query(
      'UPDATE users SET is_active = NOT is_active, token_version = token_version + 1, updated_at = NOW() WHERE id = $1 RETURNING id, is_active',
      [req.params.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'User not found' });
    invalidateUserCache(req.params.id);
    res.json({ message: 'Updated', is_active: rows[0].is_active });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /api/auth/users/:id (admin only)
// FIX: soft delete — sets deleted_at and bumps token_version so existing tokens are immediately revoked.
// Hard delete left a dangling reference risk and bypassed the deleted_at guard in auth middleware.
router.delete('/users/:id', auth, adminOnly, async (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'Cannot delete yourself' });
  try {
    const { rows } = await pool.query(
      `UPDATE users
          SET deleted_at = NOW(),
              is_active = false,
              token_version = token_version + 1,
              updated_at = NOW()
        WHERE id = $1
          AND deleted_at IS NULL
        RETURNING id`,
      [req.params.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'User not found or already deleted' });
    invalidateUserCache(req.params.id);
    res.json({ message: 'User deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
