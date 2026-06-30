// src/routes/checkin.js
//
// Face check-in API
//   POST /api/checkin/face           — match descriptor & log attendance
//   POST /api/checkin/enroll         — store a member's face descriptor
//   GET  /api/checkin/descriptors    — list all active descriptors (for kiosk-side matching)
//   GET  /api/checkin/logs           — recent check-in events
//   DELETE /api/checkin/enroll/:id   — revoke a member's face enrollment
//
// Storage:
//   * Face descriptors live in `face_descriptors` table (normalized, multi-version)
//   * `clients.face_descriptor` is kept in sync for backwards compat
//   * Each check-in attempt is appended to `face_checkin_logs`
//
// Recognition:
//   * Euclidean distance between query and stored 128-D descriptors
//   * Threshold of 0.50 — lower = stricter (face-api.js default 0.6)
//
// All routes require auth except where noted.

const router = require('express').Router();
const { randomUUID } = require('crypto');
const rateLimit = require('express-rate-limit');
const pool = require('../db/pool');
const { auth } = require('../middleware/auth');
const logger = require('../lib/logger');
const { kioskTokenMiddleware } = require('../middleware/kiosk-token');

// Separate rate limiters so a burst of enrollment attempts doesn't block
// the check-in kiosk and vice versa.
const enrollLimiter = rateLimit({ windowMs: 60 * 1000, max: 15, standardHeaders: true, legacyHeaders: false });
const faceLimiter   = rateLimit({ windowMs: 60 * 1000, max: 15, standardHeaders: true, legacyHeaders: false });

function kioskOrAuth(req, res, next) {
  if (req.user && req.user.role === 'kiosk') return next();
  return auth(req, res, next);
}

function authOrKioskForEnroll(req, res, next) {
  // Enrollment with kiosk token is allowed for self-enrollment flows.
  if (req.user && req.user.role === 'kiosk') return next();
  return auth(req, res, next);
}


// ──────────────────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────────────────
const RECOGNITION_THRESHOLD = 0.50;
const DESCRIPTOR_LENGTH     = 128;

// ──────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────
function euclideanDistance(a, b) {
  if (!a || !b || a.length !== b.length) return Infinity;
  let sum = 0;
  for (let i = 0; i < a.length; i++) {
    const d = a[i] - b[i];
    sum += d * d;
  }
  return Math.sqrt(sum);
}

function isValidDescriptor(d) {
  return Array.isArray(d)
    && d.length === DESCRIPTOR_LENGTH
    && d.every((v) => typeof v === 'number' && Number.isFinite(v));
}

function membershipStatusFor(client) {
  if (client.status === 'frozen') return 'frozen';
  const today = new Date().toISOString().slice(0, 10);
  const expiry = client.expiry_date || client.subscription_end_date || client.pt_end_date;
  if (expiry && expiry < today) return 'expired';
  if (client.status && client.status !== 'active') return client.status;
  return 'active';
}

async function logCheckIn({ clientId, status, distance, ip, userAgent, attendanceId }) {
  const id = randomUUID();
  await pool.query(
    `INSERT INTO face_checkin_logs
       (id, client_id, status, distance, ip, user_agent, attendance_id)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [id, clientId || null, status, distance || null, ip || null, userAgent || null, attendanceId || null]
  );
  return id;
}

function formatDescriptorToJson(arr) {
  // The descriptor column is JSONB, so we need a JSON array with
  // fixed-precision values (not PostgreSQL array literal syntax).
  return JSON.stringify(arr.map(v => +v.toFixed(8)));
}

// ──────────────────────────────────────────────────────────────────
// POST /api/checkin/face
// Body: { descriptor: number[128] }
// ──────────────────────────────────────────────────────────────────
router.post('/face', kioskTokenMiddleware, faceLimiter, kioskOrAuth, async (req, res, next) => {
  try {
    const descriptor = req.body?.descriptor;
    if (!isValidDescriptor(descriptor)) {
      return res.status(400).json({
        success: false,
        error: `descriptor must be a length-${DESCRIPTOR_LENGTH} array of finite numbers`,
      });
    }

    // OOM guard: refuse to load descriptors into memory if count exceeds limit.
    const { rows: [{ count }] } = await pool.query('SELECT COUNT(*) FROM face_descriptors WHERE is_active = TRUE');
    if (parseInt(count) > 1000) {
      return res.status(503).json({ error: 'Face recognition unavailable: member count exceeds in-memory limit. Enable pgvector for scalable matching.' });
    }

    // Pull active descriptors from the normalized face_descriptors table,
    // joined with client info for membership checks.
    // This is the canonical source — clients.face_descriptor is kept for
    // backwards compat only.
    const { rows: clients } = await pool.query(
      `SELECT c.id, c.name, c.status, c.photo_url, c.member_code, c.client_id,
              c.package_type, c.pt_end_date, c.expiry_date, c.subscription_end_date, c.trainer_id,
              d.descriptor AS face_descriptor, d.id AS descriptor_id
         FROM face_descriptors d
         JOIN clients c ON c.id = d.client_id
        WHERE d.is_active = TRUE
        LIMIT 2000`
    );

    if (clients.length === 0) {
      const logId = await logCheckIn({
        clientId: null, status: 'unknown', distance: null,
        ip: req.ip, userAgent: req.headers['user-agent'],
      });
      return res.status(404).json({
        success: false,
        error: 'No enrolled members. Ask reception to enroll faces first.',
        log_id: logId,
      });
    }

    // Find the closest match.
    // PERF: early-exit when we already have a confident match (< 0.30).
    // For real scale install pgvector and switch to ORDER BY descriptor <-> $1 LIMIT 1.
    const CONFIDENT_THRESHOLD = 0.30;
    let best = { distance: Infinity, client: null };
    for (const c of clients) {
      const stored = c.face_descriptor;
      if (!isValidDescriptor(stored)) continue;
      const d = euclideanDistance(descriptor, stored);
      if (d < best.distance) {
        best = { distance: d, client: c };
        if (d < CONFIDENT_THRESHOLD) break;
      }
    }

    if (best.distance > RECOGNITION_THRESHOLD || !best.client) {
      const logId = await logCheckIn({
        clientId: null,
        status: 'unknown',
        distance: best.distance === Infinity ? null : best.distance,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });
      return res.status(404).json({
        success: false,
        error: 'Face not recognized',
        distance: best.distance === Infinity ? null : Number(best.distance.toFixed(4)),
        log_id: logId,
      });
    }

    const member = best.client;
    const memberStatus = membershipStatusFor(member);

    // Trainer RBAC: only allow trainers to check in their own clients.
    if (req.user && req.user.role === 'trainer' && member.trainer_id !== req.user.trainer_id) {
      const logId = await logCheckIn({
        clientId: member.id, status: 'denied',
        distance: best.distance,
        ip: req.ip, userAgent: req.headers['user-agent'],
      });
      return res.status(403).json({
        success: false,
        error: 'Member is not assigned to you',
        log_id: logId,
      });
    }

    // Expired / frozen → log + tell client (but don't mark attendance).
    if (memberStatus !== 'active') {
      const logId = await logCheckIn({
        clientId: member.id,
        status: memberStatus === 'expired' ? 'expired' : 'denied',
        distance: best.distance,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });
      return res.status(200).json({
        success: true,
        message: `Membership ${memberStatus}`,
        member: {
          id: member.id,
          name: member.name,
          status: memberStatus,
          photo_url: member.photo_url,
          member_code: member.member_code || member.client_id,
          package_type: member.package_type,
        },
        distance: Number(best.distance.toFixed(4)),
        log_id: logId,
      });
    }

    // Active member → mark attendance.
    const date = new Date().toISOString().slice(0, 10);

    const { rows: attendanceRows } = await pool.query(
      `INSERT INTO attendance_logs
         (ref_id, ref_type, ref_name, date, check_in_time, method, status, notes)
       VALUES ($1, 'client', $2, $3::date, NOW(), 'face', 'present', 'Face check-in')
       ON CONFLICT (ref_id, ref_type, date) DO UPDATE
         SET status       = 'present',
             check_in_time = COALESCE(attendance_logs.check_in_time, EXCLUDED.check_in_time),
             method        = 'face',
             notes         = 'Face check-in'
       RETURNING id`,
      [member.id, member.name, date]
    );
    const attendanceId = attendanceRows?.[0]?.id || null;

    const logId = await logCheckIn({
      clientId: member.id,
      status: 'success',
      distance: best.distance,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      attendanceId,
    });

    return res.status(200).json({
      success: true,
      message: `Welcome ${member.name}`,
      member: {
        id: member.id,
        name: member.name,
        status: 'active',
        photo_url: member.photo_url,
        member_code: member.member_code || member.client_id,
        package_type: member.package_type,
      },
      distance: Number(best.distance.toFixed(4)),
      log_id: logId,
    });
  } catch (err) {
    logger.error({ err: err.message }, '[checkin/face] error');
    return next(err);
  }
});

// ──────────────────────────────────────────────────────────────────
// POST /api/checkin/enroll
// Body: { client_id, descriptor }
// ──────────────────────────────────────────────────────────────────
router.post('/enroll', kioskTokenMiddleware, authOrKioskForEnroll, enrollLimiter, async (req, res, next) => {
  try {
    // Skip role check for kiosk tokens (self-enrollment at kiosk).
    if (!req.user || req.user.role !== 'kiosk') {
      const allowedRoles = new Set(['admin', 'owner', 'manager', 'reception', 'trainer']);
      if (!allowedRoles.has(req.user.role)) {
        return res.status(403).json({ error: 'Not allowed to enroll faces' });
      }
    }

    const { client_id, descriptor } = req.body || {};
    if (!client_id) return res.status(400).json({ error: 'client_id required' });
    if (!isValidDescriptor(descriptor)) {
      return res.status(400).json({
        error: `descriptor must be a length-${DESCRIPTOR_LENGTH} array of finite numbers`,
      });
    }

    // Trainers can only enroll their own assigned clients.
    if (req.user && req.user.role === 'trainer') {
      const { rows: own } = await pool.query(
        'SELECT 1 FROM clients WHERE id = $1 AND trainer_id = $2 LIMIT 1',
        [client_id, req.user.trainer_id]
      );
      if (own.length === 0) {
        return res.status(403).json({ error: 'Member is not assigned to you' });
      }
    }

    // Update clients table for backwards compat.
    const clientResult = await pool.query(
      `UPDATE clients
          SET face_descriptor  = $1::float8[],
              face_enrolled    = TRUE,
              face_enrolled_at = NOW()
        WHERE id = $2
      RETURNING id`,
      [descriptor, client_id]
    );

    if (clientResult.rowCount === 0) return res.status(404).json({ error: 'Client not found' });

    // Deactivate old descriptors for this client, then insert new one.
    await pool.query(
      `UPDATE face_descriptors SET is_active = FALSE, updated_at = NOW()
        WHERE client_id = $1 AND is_active = TRUE`,
      [client_id]
    );

    const descriptorId = randomUUID();
    const enrolledBy = req.user && req.user.role !== 'kiosk' ? req.user.id : null;
    await pool.query(
      `INSERT INTO face_descriptors (id, client_id, angle, descriptor, is_active, enrolled_by, updated_at)
       VALUES ($1, $2, 'front', $3::float8[], TRUE, $4, NOW())`,
      [descriptorId, client_id, descriptor, enrolledBy]
    );

    // Log the enrollment event.
    await logCheckIn({
      clientId: client_id,
      status: 'enrolled',
      distance: null,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    return res.status(200).json({ message: 'Face enrolled', client_id, descriptor_id: descriptorId });
  } catch (err) {
    logger.error({ err: err.message }, '[checkin/enroll] error');
    return next(err);
  }
});

// ──────────────────────────────────────────────────────────────────
// GET /api/checkin/descriptors
// Returns all active face descriptors (for kiosk-side matching).
// ──────────────────────────────────────────────────────────────────
router.get('/descriptors', auth, async (req, res, next) => {
  try {
    if (!['admin', 'manager', 'kiosk'].includes(req.user.role)) {
      return res.status(403).json({ error: 'Access denied: admin, manager, or kiosk role required' });
    }
    const { rows } = await pool.query(
      `SELECT d.client_id, c.name, d.descriptor
         FROM face_descriptors d
         JOIN clients c ON c.id = d.client_id
        WHERE d.is_active = TRUE
        ORDER BY c.name`
    );
    return res.json(rows);
  } catch (err) {
    logger.error({ err: err.message }, '[checkin/descriptors] error');
    return next(err);
  }
});

// ──────────────────────────────────────────────────────────────────
// DELETE /api/checkin/enroll/:clientId
// Revokes a member's face enrollment.
// ──────────────────────────────────────────────────────────────────
router.delete('/enroll/:clientId', auth, async (req, res, next) => {
  try {
    const { clientId } = req.params;

    const allowedRoles = new Set(['admin', 'owner', 'manager', 'reception']);
    if (!allowedRoles.has(req.user.role)) {
      return res.status(403).json({ error: 'Not allowed to revoke face enrollment' });
    }

    // Deactivate all active descriptors.
    await pool.query(
      `UPDATE face_descriptors SET is_active = FALSE, updated_at = NOW()
        WHERE client_id = $1 AND is_active = TRUE`,
      [clientId]
    );

    // Clear clients table.
    await pool.query(
      `UPDATE clients
          SET face_descriptor  = NULL::float8[],
              face_enrolled    = FALSE,
              face_enrolled_at = NULL
        WHERE id = $1`,
      [clientId]
    );

    // Log the revocation.
    await logCheckIn({
      clientId,
      status: 'revoked',
      distance: null,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    return res.json({ message: 'Face enrollment revoked', client_id: clientId });
  } catch (err) {
    logger.error({ err: err.message }, '[checkin/enroll/delete] error');
    return next(err);
  }
});

// ──────────────────────────────────────────────────────────────────
// GET /api/checkin/logs?date=YYYY-MM-DD&limit=N&status=STATUS
// ──────────────────────────────────────────────────────────────────
router.get('/logs', auth, async (req, res, next) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 100, 500);
    const date = req.query.date;
    const status = req.query.status;
    const params = [];
    const conds = ['1=1'];

    if (date) {
      params.push(date);
      conds.push(`l.created_at::date = $${params.length}`);
    }

    if (status) {
      params.push(status);
      conds.push(`l.status = $${params.length}`);
    }

    if (req.user.role === 'trainer' && req.user.trainer_id) {
      params.push(req.user.trainer_id);
      conds.push(`(c.trainer_id = $${params.length} OR l.client_id IS NULL)`);
    }

    const { rows } = await pool.query(
      `SELECT l.id, l.client_id, l.status, l.distance, l.created_at,
              c.name AS client_name, c.photo_url, c.member_code
         FROM face_checkin_logs l
    LEFT JOIN clients c ON c.id = l.client_id
        WHERE ${conds.join(' AND ')}
        ORDER BY l.created_at DESC
        LIMIT ${limit}`,
      params
    );
    return res.json(rows);
  } catch (err) {
    logger.error({ err: err.message }, '[checkin/logs] error');
    return next(err);
  }
});

// ──────────────────────────────────────────────────────────────────
// POST /api/checkin/qr-mark
// Body: { client_id }
// Quick QR-based attendance — no face matching needed.
// ──────────────────────────────────────────────────────────────────
router.post('/qr-mark', auth, async (req, res, next) => {
  try {
    const { client_id } = req.body || {};
    if (!client_id) return res.status(400).json({ error: 'client_id required' });

    const { rows: member } = await pool.query(
      `SELECT id, name, status, pt_end_date, expiry_date, subscription_end_date
         FROM clients WHERE id = $1 LIMIT 1`,
      [client_id]
    );
    if (!member[0]) return res.status(404).json({ error: 'Member not found' });

    const memberStatus = membershipStatusFor(member[0]);
    const date = new Date().toISOString().slice(0, 10);

    if (memberStatus !== 'active') {
      return res.status(200).json({
        success: false,
        message: `Membership ${memberStatus}`,
        member: { id: member[0].id, name: member[0].name, status: memberStatus },
      });
    }

    const { rows: att } = await pool.query(
      `INSERT INTO attendance_logs
         (ref_id, ref_type, ref_name, date, check_in_time, method, status, notes)
       VALUES ($1, 'client', $2, $3::date, NOW(), 'qr', 'present', 'QR check-in')
       ON CONFLICT (ref_id, ref_type, date) DO UPDATE
         SET check_in_time = COALESCE(attendance_logs.check_in_time, EXCLUDED.check_in_time),
             method = CASE WHEN attendance_logs.method = 'manual' THEN EXCLUDED.method
                           ELSE attendance_logs.method END,
             status = 'present',
             notes = 'QR check-in'
       RETURNING id`,
      [member[0].id, member[0].name, date]
    );

    return res.status(200).json({
      success: true,
      message: `Welcome ${member[0].name}`,
      member: { id: member[0].id, name: member[0].name, status: 'active' },
      attendance_id: att[0]?.id,
    });
  } catch (err) {
    logger.error({ err: err.message }, '[checkin/qr-mark] error');
    return next(err);
  }
});

// ──────────────────────────────────────────────────────────────────
// POST /api/checkin/mobile-mark
// Body: { mobile }
// Mark attendance by mobile number lookup.
// ──────────────────────────────────────────────────────────────────
router.post('/mobile-mark', auth, async (req, res, next) => {
  try {
    const { mobile } = req.body || {};
    if (!mobile) return res.status(400).json({ error: 'mobile required' });

    const { rows: members } = await pool.query(
      `SELECT id, name, status, pt_end_date, expiry_date, subscription_end_date
         FROM clients
        WHERE mobile = $1
           OR REPLACE(mobile, '-', '') = REPLACE($1, '-', '')
           OR REPLACE(mobile, ' ', '') = REPLACE($1, ' ', '')
        LIMIT 1`,
      [mobile]
    );

    if (!members[0]) return res.status(404).json({ error: 'No member found with that mobile number' });

    const member = members[0];
    const memberStatus = membershipStatusFor(member);
    const date = new Date().toISOString().slice(0, 10);

    if (memberStatus !== 'active') {
      return res.status(200).json({
        success: false,
        message: `Membership ${memberStatus}`,
        member: { id: member.id, name: member.name, status: memberStatus },
      });
    }

    const { rows: att } = await pool.query(
      `INSERT INTO attendance_logs
         (ref_id, ref_type, ref_name, date, check_in_time, method, status, notes)
       VALUES ($1, 'client', $2, $3::date, NOW(), 'manual', 'present', 'Mobile check-in')
       ON CONFLICT (ref_id, ref_type, date) DO UPDATE
         SET check_in_time = COALESCE(attendance_logs.check_in_time, EXCLUDED.check_in_time),
             status = 'present',
             notes = 'Mobile check-in'
       RETURNING id`,
      [member.id, member.name, date]
    );

    return res.status(200).json({
      success: true,
      message: `Welcome ${member.name}`,
      member: { id: member.id, name: member.name, status: 'active' },
      attendance_id: att[0]?.id,
    });
  } catch (err) {
    logger.error({ err: err.message }, '[checkin/mobile-mark] error');
    return next(err);
  }
});

module.exports = router;
