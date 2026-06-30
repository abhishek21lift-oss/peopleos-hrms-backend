// src/routes/attendance.js
// Uses the canonical attendance_logs table (v4 schema).
// Column mapping from old attendance table:
//   attendance.type       → attendance_logs.ref_type
//   attendance.check_in   → attendance_logs.check_in_time (TIMESTAMPTZ)
//   attendance.check_out  → attendance_logs.check_out_time (TIMESTAMPTZ)
//   attendance.check_in_method → attendance_logs.method
//   trainer_id/name       → marked_by (references users.id)
// Removed: updated_at, branch_id, member_id, booking_id, pt_session_id, device_id
// Unique constraint: (ref_id, ref_type, date)

const router = require('express').Router();
const { randomUUID } = require('crypto');
const rateLimit = require('express-rate-limit');
const pool = require('../db/pool');
const { auth } = require('../middleware/auth');
const { validate } = require('../middleware/validate');
const { bulkAttendanceSchema } = require('../lib/validation');

const biometricLimiter = rateLimit({ windowMs: 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false });

// GET /api/attendance?date=YYYY-MM-DD&type=client
router.get('/', auth, async (req, res, next) => {
  try {
    const { date, from, to, type = 'client', ref_id } = req.query;
    const conditions = ['1=1'];
    const params = [];
    let p = 1;

    if (req.user.role === 'trainer' && req.user.trainer_id) {
      conditions.push(`a.ref_type = 'client'`);
    }
    if (date)   { conditions.push(`a.date = $${p++}`);     params.push(date); }
    if (from)   { conditions.push(`a.date >= $${p++}`);    params.push(from); }
    if (to)     { conditions.push(`a.date <= $${p++}`);    params.push(to); }
    if (type)   { conditions.push(`a.ref_type = $${p++}`); params.push(type); }
    if (ref_id) { conditions.push(`a.ref_id = $${p++}`);   params.push(ref_id); }

    const limit = (from || to) ? 5000 : 200;

    const { rows } = await pool.query(
      `SELECT a.id, a.ref_id, a.ref_type AS type, a.ref_name,
              a.date, a.check_in_time AS check_in, a.check_out_time AS check_out,
              a.status, a.notes, a.method AS check_in_method, a.created_at
         FROM attendance_logs a
       WHERE ${conditions.join(' AND ')}
       ORDER BY a.date DESC, a.check_in_time DESC NULLS LAST
       LIMIT $${p}`,
      params.concat(limit)
    );
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

// POST /api/attendance — mark attendance
router.post('/', auth, async (req, res, next) => {
  try {
    const d = req.body;
    if (!d.ref_id || !d.date)
      return res.status(400).json({ error: 'ref_id and date required' });

    const type = d.type || 'client';

    // RBAC: trainers can only mark attendance for their own clients
    if (req.user.role === 'trainer') {
      if (type === 'client') {
        const { rows: own } = await pool.query(
          'SELECT trainer_id FROM clients WHERE id=$1', [d.ref_id]
        );
        if (!own[0]) return res.status(404).json({ error: 'Client not found' });
        if (own[0].trainer_id !== req.user.trainer_id)
          return res.status(403).json({ error: 'Access denied: client is not assigned to you' });
      } else if (type === 'trainer') {
        if (d.ref_id !== req.user.trainer_id)
          return res.status(403).json({ error: 'Access denied' });
      }
      d.trainer_id = req.user.trainer_id;
    }

    const id = randomUUID();
    const checkIn = d.check_in ? new Date(d.date + 'T' + d.check_in).toISOString() : null;
    const checkOut = d.check_out ? new Date(d.date + 'T' + d.check_out).toISOString() : null;
    await pool.query(`
      INSERT INTO attendance_logs
        (id, ref_id, ref_type, ref_name, date, check_in_time, check_out_time,
         status, notes, method, marked_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      ON CONFLICT (ref_id, ref_type, date) DO UPDATE
        SET status=$8,
            check_in_time=COALESCE(attendance_logs.check_in_time, $6),
            check_out_time=$7,
            notes=$9,
            method=$10`,
      [id, d.ref_id, type, d.ref_name || null,
       d.date, checkIn, checkOut,
       d.status || 'present', d.notes || null,
       'manual', req.user.id]
    );
    res.status(201).json({ message: 'Attendance marked' });
  } catch (err) {
    next(err);
  }
});

// POST /api/attendance/biometric
router.post('/biometric', auth, biometricLimiter, async (req, res, next) => {
  try {
    const code = String(req.body?.biometric_code || '').trim();
    const requestedType = req.body?.type;
    if (!code) return res.status(400).json({ error: 'biometric_code required' });
    if (requestedType && !['client', 'trainer'].includes(requestedType)) {
      return res.status(400).json({ error: 'type must be client or trainer' });
    }

    const lookups = requestedType ? [requestedType] : ['client', 'trainer'];
    let person = null;
    let type = null;

    for (const t of lookups) {
      if (t === 'client') {
        const { rows } = await pool.query(
          `SELECT id, name, client_id, trainer_id, trainer_name
             FROM clients
            WHERE biometric_code = $1 OR client_id = $1 OR member_code = $1
            LIMIT 1`, [code]
        );
        if (rows[0]) { person = rows[0]; type = 'client'; break; }
      } else {
        const { rows } = await pool.query(
          `SELECT id, name, biometric_code FROM trainers WHERE biometric_code = $1 LIMIT 1`,
          [code]
        );
        if (rows[0]) { person = rows[0]; type = 'trainer'; break; }
      }
    }

    if (!person || !type) return res.status(404).json({ error: 'Biometric code not found' });

    if (req.user.role === 'trainer') {
      if (type === 'client' && person.trainer_id !== req.user.trainer_id)
        return res.status(403).json({ error: 'Access denied: member is not assigned to you' });
      if (type === 'trainer' && person.id !== req.user.trainer_id)
        return res.status(403).json({ error: 'Access denied' });
    }

    const now = new Date();
    const date = now.toISOString().split('T')[0];
    const id = randomUUID();

    await pool.query(`
      INSERT INTO attendance_logs
        (id, ref_id, ref_type, ref_name, date, check_in_time, status, notes, method, marked_by)
      VALUES ($1,$2,$3,$4,$5,NOW(),'present','biometric','biometric',$6)
      ON CONFLICT (ref_id, ref_type, date) DO UPDATE
        SET status='present',
            check_in_time=COALESCE(attendance_logs.check_in_time, NOW()),
            notes='biometric',
            method='biometric'`,
      [id, person.id, type, person.name, date, req.user.id]
    );

    const { rows } = await pool.query(
      'SELECT id, ref_id, ref_type AS type, ref_name, date, check_in_time AS check_in, check_out_time AS check_out, status, notes, method AS check_in_method, created_at FROM attendance_logs WHERE ref_type=$1 AND ref_id=$2 AND date=$3',
      [type, person.id, date]
    );
    res.status(201).json({
      message: `${person.name} checked in by biometric`,
      attendance: rows[0],
      person: { id: person.id, name: person.name, type },
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/attendance/today-summary
router.get('/today-summary', auth, async (req, res, next) => {
  try {
    const params = [];
    let trainerFilter = '';
    if (req.user.role === 'trainer' && req.user.trainer_id) {
      params.push(req.user.trainer_id);
      trainerFilter = 'AND a.marked_by = $' + params.length + ' ';
    }

    const { rows } = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE a.status='present') AS present,
        COUNT(*) FILTER (WHERE a.status='absent')  AS absent,
        COUNT(*) FILTER (WHERE a.status='late')    AS late,
        COUNT(*)                                    AS total
      FROM attendance_logs a
      WHERE a.date = CURRENT_DATE AND a.ref_type = 'client' ${trainerFilter}`,
      params
    );
    res.json(rows[0]);
  } catch (err) {
    next(err);
  }
});

// PUT /api/attendance/:id — update a specific attendance record
router.put('/:id', auth, async function(req, res, next) {
  try {
    const { rows: existing } = await pool.query(
      'SELECT id, marked_by, ref_type FROM attendance_logs WHERE id = $1', [req.params.id]
    );
    if (!existing[0]) return res.status(404).json({ error: 'Attendance record not found' });

    // RBAC: trainers can only edit their own clients' records
    if (req.user.role === 'trainer' && existing[0].marked_by !== req.user.id) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const fields = [];
    const params = [req.params.id];
    let idx = 2;
    const d = req.body;

    if (d.status !== undefined) { fields.push('status = $' + idx++); params.push(d.status); }
    if (d.check_in !== undefined) { fields.push('check_in_time = $' + idx++); params.push(d.check_in); }
    if (d.check_out !== undefined) { fields.push('check_out_time = $' + idx++); params.push(d.check_out); }
    if (d.notes !== undefined) { fields.push('notes = $' + idx++); params.push(d.notes); }

    if (fields.length === 0) return res.status(400).json({ error: 'No fields to update' });

    const { rows } = await pool.query(
      'UPDATE attendance_logs SET ' + fields.join(', ') + ' WHERE id = $1 RETURNING id, ref_id, ref_type AS type, ref_name, date, check_in_time AS check_in, check_out_time AS check_out, status, notes, method AS check_in_method, created_at',
      params
    );
    res.json({ message: 'Attendance updated', attendance: rows[0] });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/attendance/:id — delete a specific attendance record
router.delete('/:id', auth, async function(req, res, next) {
  try {
    const { rows: existing } = await pool.query(
      'SELECT id, marked_by FROM attendance_logs WHERE id = $1', [req.params.id]
    );
    if (!existing[0]) return res.status(404).json({ error: 'Attendance record not found' });

    if (req.user.role === 'trainer' && existing[0].marked_by !== req.user.id) {
      return res.status(403).json({ error: 'Access denied' });
    }

    await pool.query('DELETE FROM attendance_logs WHERE id = $1', [req.params.id]);
    res.json({ message: 'Attendance record deleted' });
  } catch (err) {
    next(err);
  }
});

// POST /api/attendance/bulk — mark attendance for multiple members
router.post('/bulk', auth, validate(bulkAttendanceSchema), async function(req, res, next) {
  try {
    const records = req.body.records;
    if (!Array.isArray(records) || records.length === 0) {
      return res.status(400).json({ error: 'records array is required' });
    }

    if (records.length > 200) {
      return res.status(400).json({ error: 'Maximum 200 records per bulk operation' });
    }

    const results = [];
    const errors = [];

    // Batch-fetch trainer_id for all client records to avoid N+1 queries
    const clientIds = [...new Set(records.map(r => r.ref_id).filter(Boolean))];
    const trainerRes = clientIds.length > 0
      ? await pool.query('SELECT id, trainer_id FROM clients WHERE id = ANY($1)', [clientIds])
      : { rows: [] };
    const trainerMap = Object.fromEntries(trainerRes.rows.map(r => [r.id, r.trainer_id]));

    for (let i = 0; i < records.length; i++) {
      const d = records[i];
      if (!d.ref_id || !d.date || !d.status) {
        errors.push({ index: i, error: 'ref_id, date, and status required' });
        continue;
      }

      try {
        const type = d.type || 'client';
        const id = randomUUID();

        // RBAC: trainers scoped to own clients
        if (req.user.role === 'trainer') {
          const clientTrainerId = trainerMap[d.ref_id];
          if (clientTrainerId === undefined || clientTrainerId !== req.user.trainer_id) {
            errors.push({ index: i, ref_id: d.ref_id, error: 'Access denied' });
            continue;
          }
        }

        const bulkCheckIn = d.check_in ? new Date(d.date + 'T' + d.check_in).toISOString() : null;
        const bulkCheckOut = d.check_out ? new Date(d.date + 'T' + d.check_out).toISOString() : null;
        await pool.query(`
          INSERT INTO attendance_logs
            (id, ref_id, ref_type, ref_name, date,
             check_in_time, check_out_time, status, notes, method, marked_by)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
          ON CONFLICT (ref_id, ref_type, date) DO UPDATE
            SET status=$8, notes=$9`,
          [id, d.ref_id, type, d.ref_name || null,
           d.date, bulkCheckIn, bulkCheckOut,
           d.status || 'present', d.notes || null,
           'manual', req.user.id]
        );
        results.push({ index: i, ref_id: d.ref_id, status: d.status });
      } catch (err) {
        errors.push({ index: i, ref_id: d.ref_id, error: err.message });
      }
    }

    res.status(201).json({
      message: results.length + ' records processed',
      processed: results.length,
      failed: errors.length,
      errors: errors.length > 0 ? errors : undefined,
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/attendance/stats — attendance statistics for charts
// Query params: from, to, granularity (day|week|month)
router.get('/stats', auth, async function(req, res, next) {
  try {
    const from = req.query.from || new Date(Date.now() - 30 * 86400000).toISOString().split('T')[0];
    const to = req.query.to || new Date().toISOString().split('T')[0];
    const granularity = req.query.granularity || 'day';

    const VALID_GRANULARITIES = { day: 'day', week: 'week', month: 'month' };
    const granularityVal = VALID_GRANULARITIES[granularity];
    if (!granularityVal) return res.status(400).json({ error: 'Invalid granularity' });
    const dateTrunc = granularityVal === 'day' ? 'a.date' : `DATE_TRUNC('${granularityVal}', a.date)`;

    const params = [from, to];
    let trainerFilter = '';
    if (req.user.role === 'trainer' && req.user.trainer_id) {
      params.push(req.user.trainer_id);
      trainerFilter = 'AND c.trainer_id = $' + params.length + ' ';
    }

    const { rows } = await pool.query(
      'SELECT ' + dateTrunc + ' AS period, ' +
      'a.status, COUNT(*) AS count ' +
      'FROM attendance_logs a ' +
      'JOIN clients c ON c.id = a.ref_id ' +
      'WHERE a.date >= $1 AND a.date <= $2 ' + trainerFilter +
      'AND a.ref_type = \'client\' ' +
      'GROUP BY period, a.status ' +
      'ORDER BY period ASC',
      params
    );

    // Pivot: group by period, spread statuses
    const series = {};
    for (const r of rows) {
      const key = r.period instanceof Date ? r.period.toISOString().split('T')[0] : String(r.period);
      if (!series[key]) series[key] = { date: key, present: 0, absent: 0, late: 0, total: 0 };
      series[key][r.status] = parseInt(r.count) || 0;
      series[key].total += parseInt(r.count) || 0;
    }

    res.json(Object.values(series));
  } catch (err) {
    next(err);
  }
});

// GET /api/attendance/gaps — members with attendance gaps (absent streaks)
// Query params: min_streak_days (default 3), from, to
router.get('/gaps', auth, async function(req, res, next) {
  try {
    const minStreak = parseInt(req.query.min_streak_days) || 3;
    const from = req.query.from || new Date(Date.now() - 30 * 86400000).toISOString().split('T')[0];
    const to = req.query.to || new Date().toISOString().split('T')[0];

    const params = [from, to, minStreak];
    let trainerFilter = '';
    if (req.user.role === 'trainer' && req.user.trainer_id) {
      params.push(req.user.trainer_id);
      trainerFilter = 'AND c.trainer_id = $' + params.length + ' ';
    }

    // Find members with consecutive absent days >= minStreak
    const { rows } = await pool.query(
      'SELECT c.id, c.name, c.mobile, c.primary_trainer_id, ' +
      'COALESCE(t.name, \'—\') AS trainer_name, ' +
      'COUNT(a.id) FILTER (WHERE a.date >= $1::DATE) AS absent_days, ' +
      'MAX(a.date) AS last_absent_date, ' +
      '(SELECT COUNT(*) FROM attendance_logs a2 ' +
      '  WHERE a2.ref_id = c.id AND a2.ref_type = \'client\' ' +
      '  AND a2.date >= $1::DATE AND a2.date <= $2::DATE) AS total_entries ' +
      'FROM clients c ' +
      'LEFT JOIN attendance_logs a ON a.ref_id = c.id AND a.ref_type = \'client\' AND a.status = \'absent\' ' +
      'LEFT JOIN trainers t ON t.id = c.primary_trainer_id ' +
      'WHERE c.deleted_at IS NULL ' +
      'AND c.status = \'active\' ' + trainerFilter +
      'GROUP BY c.id, c.name, c.mobile, c.primary_trainer_id, t.name ' +
      'HAVING COUNT(a.id) >= $3 ' +
      'ORDER BY absent_days DESC',
      params
    );

    res.json(rows);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
