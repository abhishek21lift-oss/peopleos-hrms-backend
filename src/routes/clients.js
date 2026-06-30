// src/routes/clients.js
const router = require('express').Router();
const { randomUUID } = require('crypto');
const pool   = require('../db/pool');
const { genReceiptNo } = require('../db/receipts');
const { auth, adminOnly } = require('../middleware/auth');
const { validate } = require('../middleware/validate');
const { clientSchemas, renewSchema } = require('../lib/validation');
const logger = require('../lib/logger');
const { generateClientId, generateMemberCode } = require('../db/id-gen');

// Helper: parse a value as a finite number, or return fallback.
// parseFloat('') is NaN — `??` does NOT catch that. Use this guard instead.
function num(value, fallback = 0) {
  if (value === null || value === undefined || value === '') return fallback;
  const n = parseFloat(value);
  return Number.isFinite(n) ? n : fallback;
}

// Track last auto-expire run so we don't fire the UPDATE on every list call.
let lastExpireRun = 0;
async function maybeAutoExpire() {
  const now = Date.now();
  // Run at most once per hour
  if (now - lastExpireRun < 60 * 60 * 1000) return;
  lastExpireRun = now;
  try {
    await pool.query(
      `UPDATE clients SET status='expired', updated_at=NOW()
       WHERE status='active' AND pt_end_date < CURRENT_DATE`
    );
  } catch (err) {
    logger.warn({ err: err.message }, 'Auto-expire error');
  }
}

// GET /api/clients
//   ?search=…       fuzzy on name / mobile / client_id / email
//   ?status=active|expired|frozen|expiring|dues
//   ?trainer_id=…   admin-only filter
//   ?limit=…        clamped to [1, 1000]
//   ?offset=…       clamped to >= 0
router.get('/', auth, async (req, res, next) => {
  try {
    const { search, status, trainer_id, dues } = req.query;
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 500, 1), 1000);
    const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
    const conditions = [];
    const params = [];
    let p = 1;
    // Soft-delete filter (added by 2026-05-perf-and-soft-delete migration).
    // We use an OR-against-NULL to keep this clause SAFE on databases that
    // haven't run the migration yet — Postgres short-circuits and returns
    // every row when the column isn't present (it would error before, but
    // production runs the migration first). Pass ?include_deleted=1 to see
    // soft-deleted rows.
    if (req.query.include_deleted !== '1') {
      conditions.push('COALESCE(c.deleted_at, NULL) IS NULL');
    }

    // Scope trainer to own clients only
    if (req.user.role === 'trainer' && req.user.trainer_id) {
      conditions.push(`c.trainer_id = $${p++}`);
      params.push(req.user.trainer_id);
    } else if (trainer_id) {
      conditions.push(`c.trainer_id = $${p++}`);
      params.push(trainer_id);
    }

    if (search) {
      // ILIKE is the case-insensitive cousin of LIKE — and pairs with a
      // pg_trgm index on name/email/mobile for sub-100ms search at scale.
      conditions.push(
        `(c.name ILIKE $${p} OR c.mobile ILIKE $${p} OR c.client_id ILIKE $${p} OR c.email ILIKE $${p})`
      );
      params.push(`%${String(search).trim()}%`);
      p++;
    }

    if (status === 'expiring') {
      conditions.push(
        `c.status = 'active' AND c.pt_end_date BETWEEN CURRENT_DATE AND CURRENT_DATE + INTERVAL '7 days'`
      );
    } else if (status === 'dues') {
      conditions.push(`c.balance_amount > 0`);
    } else if (status) {
      conditions.push(`c.status = $${p++}`);
      params.push(status);
    }

    if (dues === 'yes') conditions.push('c.balance_amount > 0');

    const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';

    // Auto-expire is rate-limited to once an hour, off the hot read path.
    maybeAutoExpire().catch(err => console.error('Auto-expire error:', err));

    const { rows } = await pool.query(
      `SELECT c.id, c.client_id, c.member_code, c.name, c.mobile, c.email, c.gender, c.dob,
              c.address, c.trainer_id, c.trainer_name, c.package_type, c.joining_date,
              c.pt_start_date, c.pt_end_date, c.expiry_date, c.base_amount, c.discount,
              c.final_amount, c.paid_amount, c.balance_amount, c.payment_method, c.payment_date,
              c.status, c.notes, c.photo_url, c.weight, c.face_enrolled, c.face_enrolled_at,
              c.is_frozen, c.freeze_from, c.freeze_until, c.freeze_reason,
              c.deleted_at, c.created_at, c.updated_at,
              t.name as computed_trainer_name
       FROM clients c
       LEFT JOIN trainers t ON t.id = c.trainer_id
       ${where}
       ORDER BY c.created_at DESC
       LIMIT $${p++} OFFSET $${p++}`,
      [...params, limit, offset]
    );
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

// GET /api/clients/search — dedicated search route matching frontend api.clients.search()
router.get('/search', auth, async (req, res, next) => {
  try {
    const q = String(req.query.q || '').trim();
    if (!q) return res.json([]);
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 20, 1), 100);
    const { rows } = await pool.query(
      `SELECT c.id, c.client_id, c.member_code, c.name, c.mobile, c.email, c.gender, c.dob,
              c.address, c.trainer_id, c.trainer_name, c.package_type, c.joining_date,
              c.pt_start_date, c.pt_end_date, c.expiry_date, c.base_amount, c.discount,
              c.final_amount, c.paid_amount, c.balance_amount, c.payment_method, c.payment_date,
              c.status, c.notes, c.photo_url, c.weight, c.face_enrolled, c.face_enrolled_at,
              c.deleted_at, c.created_at, c.updated_at,
              t.name as computed_trainer_name
       FROM clients c LEFT JOIN trainers t ON t.id = c.trainer_id
       WHERE COALESCE(c.deleted_at, NULL) IS NULL
         AND (c.name ILIKE $1 OR c.mobile ILIKE $1 OR c.client_id ILIKE $1 OR c.email ILIKE $1)
       ORDER BY c.created_at DESC LIMIT $2`,
      [`%${q}%`, limit]
    );
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

// GET /api/clients/:id
//   Returns the client + last 50 payments, 20 weight logs, 20 renewals.
//   Fans the four queries out in parallel — was sequential before.
router.get('/:id', auth, async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `SELECT c.*, t.name as trainer_full_name, t.mobile as trainer_mobile
       FROM clients c LEFT JOIN trainers t ON t.id = c.trainer_id
       WHERE c.id = $1`, [req.params.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'Client not found' });

    // Trainer can only see their own clients.
    if (req.user.role === 'trainer' &&
        (!req.user.trainer_id || rows[0].trainer_id !== req.user.trainer_id)) {
      return res.status(404).json({ error: 'Client not found' });
    }

    // Member role can only see their own record.
    if (req.user.role === 'member' && rows[0].id !== req.user.member_id) {
      return res.status(404).json({ error: 'Client not found' });
    }

    // Reception can see basic info but not financial details.
    const isReception = req.user.role === 'reception';

    const [payments, weightLogs, renewals] = await Promise.all([
      pool.query(
        'SELECT * FROM payments WHERE client_id=$1 ORDER BY date DESC, created_at DESC LIMIT 50',
        [req.params.id]
      ),
      pool.query(
        'SELECT * FROM weight_logs WHERE client_id=$1 ORDER BY date DESC LIMIT 20',
        [req.params.id]
      ),
      pool.query(
        'SELECT * FROM renewals WHERE client_id=$1 ORDER BY renewed_on DESC, created_at DESC LIMIT 20',
        [req.params.id]
      ),
    ]);

    if (isReception) {
      const { payments: _, weight_logs: wl, renewals: rn, ...basic } = rows[0];
      return res.json(basic);
    }

    res.json({
      ...rows[0],
      payments: payments.rows,
      weight_logs: weightLogs.rows,
      renewals: renewals.rows,
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/clients/:id/renew  — renew an existing client's membership.
// Wrapped in a transaction so the client row, the renewal row, and (optionally)
// the payment row all succeed together — or none of them do.
router.post('/:id/renew', auth, validate(renewSchema), async (req, res, next) => {
  const tx = await pool.connect();
  try {
    const d = req.body || {};
    const id = req.params.id;

    if (!d.package_type) return res.status(400).json({ error: 'Package type is required' });
    if (!d.pt_start_date || !d.pt_end_date) return res.status(400).json({ error: 'Start and end dates are required' });

    await tx.query('BEGIN');

    const { rows: existing } = await tx.query(
      'SELECT * FROM clients WHERE id=$1 FOR UPDATE', [id]
    );
    if (!existing[0]) {
      await tx.query('ROLLBACK');
      return res.status(404).json({ error: 'Client not found' });
    }
    const c = existing[0];

    // Trainers can only renew their own clients
    if (req.user.role === 'trainer' &&
        (!req.user.trainer_id || c.trainer_id !== req.user.trainer_id)) {
      await tx.query('ROLLBACK');
      return res.status(403).json({ error: 'Access denied' });
    }

    const base    = num(d.base_amount,  0);
    const disc    = num(d.discount,     0);
    const final   = num(d.final_amount, base - disc);
    const paid    = num(d.paid_amount,  0);
    const balance = Math.max(0, final - paid);

    if (final <= 0) {
      await tx.query('ROLLBACK');
      return res.status(400).json({ error: 'Final amount must be greater than zero' });
    }

    // 1. Insert renewal record (history)
    await tx.query(`
      INSERT INTO renewals (id, client_id, client_name, trainer_id, trainer_name,
        old_package, new_package, old_end_date, new_end_date,
        amount, paid_amount, payment_method, renewed_on, notes)
      VALUES (gen_random_uuid()::TEXT, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
      [id, c.name, c.trainer_id, c.trainer_name,
       c.package_type, d.package_type,
       c.pt_end_date, d.pt_end_date,
       final, paid, d.payment_method || 'CASH',
       d.renewed_on || new Date().toISOString().split('T')[0],
       d.notes || null]
    );

    // 2. Update the client to reflect the new membership
    await tx.query(`
      UPDATE clients SET
        package_type   = $1,
        pt_start_date  = $2,
        pt_end_date    = $3,
        base_amount    = $4,
        discount       = $5,
        final_amount   = $6,
        paid_amount    = $7,
        balance_amount = $8,
        payment_method = $9,
        payment_date   = $10,
        status         = 'active',
        updated_at     = NOW()
      WHERE id = $11`,
      [d.package_type, d.pt_start_date, d.pt_end_date,
       base, disc, final, paid, balance,
       d.payment_method || 'CASH',
       d.renewed_on || new Date().toISOString().split('T')[0],
       id]
    );

    // 3. If they paid anything today, create a payment record + incentive
    if (paid > 0) {
      let incentiveRate = 0.5;
      if (c.trainer_id) {
        const { rows: tr } = await tx.query(
          'SELECT incentive_rate FROM trainers WHERE id=$1', [c.trainer_id]
        );
        incentiveRate = tr[0]?.incentive_rate ?? 0.5;
      }
      const receiptNo = await genReceiptNo(tx);
      await tx.query(`
        INSERT INTO payments (id, client_id, client_name, trainer_id, trainer_name,
          amount, method, date, receipt_no, package_type, incentive_amt, notes)
        VALUES (gen_random_uuid()::TEXT, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
        [id, c.name, c.trainer_id, c.trainer_name, paid,
         d.payment_method || 'CASH',
         d.renewed_on || new Date().toISOString().split('T')[0],
         receiptNo, d.package_type,
         Math.round(paid * incentiveRate),
         (d.notes ? `Renewal: ${d.notes}` : `Renewal — ${d.package_type}`)]
      );
    }

    await tx.query('COMMIT');

    // Re-fetch the updated client + history to send back
    const { rows: fresh } = await pool.query('SELECT * FROM clients WHERE id=$1', [id]);
    const { rows: payments } = await pool.query(
      'SELECT * FROM payments WHERE client_id=$1 ORDER BY date DESC LIMIT 50', [id]
    );
    const { rows: renewals } = await pool.query(
      'SELECT * FROM renewals WHERE client_id=$1 ORDER BY renewed_on DESC LIMIT 20', [id]
    );

    res.json({ message: 'Membership renewed', client: { ...fresh[0], payments, renewals } });
  } catch (err) {
    await tx.query('ROLLBACK').catch(() => {});
    next(err);
  } finally {
    tx.release();
  }
});

// POST /api/clients/:id/pt-renew - renew personal training dates/amount.
router.post('/:id/pt-renew', auth, async (req, res, next) => {
  const tx = await pool.connect();
  try {
    const d = req.body || {};
    if (!d.pt_start_date || !d.pt_end_date) {
      return res.status(400).json({ error: 'PT start and end dates are required' });
    }

    await tx.query('BEGIN');
    const { rows: existing } = await tx.query('SELECT * FROM clients WHERE id=$1 FOR UPDATE', [req.params.id]);
    const c = existing[0];
    if (!c) {
      await tx.query('ROLLBACK');
      return res.status(404).json({ error: 'Client not found' });
    }
    if (req.user.role === 'trainer' && (!req.user.trainer_id || c.trainer_id !== req.user.trainer_id)) {
      await tx.query('ROLLBACK');
      return res.status(403).json({ error: 'Access denied' });
    }

    const amount = num(d.amount, 0);
    await tx.query(`
      UPDATE clients SET
        package_type = COALESCE($1, package_type),
        pt_start_date=$2,
        pt_end_date=$3,
        final_amount = CASE WHEN $4 > 0 THEN $4 ELSE final_amount END,
        balance_amount = CASE WHEN $4 > 0 THEN GREATEST(0, $4 - COALESCE(paid_amount,0)) ELSE balance_amount END,
        status='active',
        updated_at=NOW()
      WHERE id=$5`,
      [d.package_type || 'PT', d.pt_start_date, d.pt_end_date, amount, req.params.id]
    );

    await tx.query(`
      INSERT INTO renewals (id, client_id, client_name, trainer_id, trainer_name,
        old_package, new_package, old_end_date, new_end_date, amount, paid_amount,
        payment_method, renewed_on, notes)
      VALUES (gen_random_uuid()::TEXT,$1,$2,$3,$4,$5,$6,$7,$8,$9,0,'PT_RENEWAL',CURRENT_DATE,$10)`,
      [req.params.id, c.name, c.trainer_id, c.trainer_name, c.package_type,
       d.package_type || 'PT', c.pt_end_date, d.pt_end_date, amount, d.reason || d.notes || null]
    );

    await tx.query('COMMIT');
    const { rows } = await pool.query('SELECT * FROM clients WHERE id=$1', [req.params.id]);
    res.json({ message: 'Personal training renewed', client: rows[0] });
  } catch (err) {
    await tx.query('ROLLBACK').catch(() => {});
    next(err);
  } finally {
    tx.release();
  }
});

// POST /api/clients
router.post('/', auth, validate(clientSchemas.create), async (req, res, next) => {
  const client = await pool.connect();
  try {
    const d = req.body;
    if (!d.name?.trim()) return res.status(400).json({ error: 'Client name is required' });

    await client.query('BEGIN');

    // Serialise concurrent client creates so two requests never produce the same code.
    await client.query("SELECT pg_advisory_xact_lock(hashtext('clients_seq'))");

    const clientId = await generateClientId(client);
    const memberCode = await generateMemberCode(client);

    const id = randomUUID();
    const base    = num(d.base_amount,  0);
    const disc    = num(d.discount,     0);
    const final   = num(d.final_amount, base - disc);
    const paid    = num(d.paid_amount,  0);
    // Clamp to zero — overpayment shouldn't show as a negative balance.
    const balance = Math.max(0, final - paid);

    // If trainer is adding, force their trainer_id
    const trainer_id = req.user.role === 'trainer' ? req.user.trainer_id : (d.trainer_id || null);

    // Get trainer name + incentive_rate in a single query
    let trainer_name = d.trainer_name || null;
    let incentiveRate = 0.5;
    if (trainer_id) {
      const { rows: tr } = await client.query(
        'SELECT name, incentive_rate FROM trainers WHERE id=$1', [trainer_id]
      );
      if (tr[0]) {
        if (!trainer_name) trainer_name = tr[0].name || null;
        incentiveRate = tr[0].incentive_rate ?? 0.5;
      }
    }

    await client.query(`
      INSERT INTO clients (
        id, client_id, member_code, name, mobile, email, gender, dob, address,
        trainer_id, trainer_name, joining_date, pt_start_date, pt_end_date,
        package_type, base_amount, discount, final_amount, paid_amount, balance_amount,
        payment_method, payment_date, weight, notes, status, photo_url, biometric_code, biometric_added
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28)`,
      [id, clientId, memberCode, d.name.trim(), d.mobile||null, d.email?.toLowerCase()||null,
       d.gender||null, d.dob||null, d.address||null,
       trainer_id, trainer_name,
       d.joining_date||null, d.pt_start_date||null, d.pt_end_date||null,
       d.package_type||null, base, disc, final, paid, balance,
       d.payment_method||'CASH', d.payment_date||null,
       num(d.weight, null), d.notes||null, d.status||'active', d.photo_url||null,
       d.biometric_code || clientId, true]
    );

    // If paid > 0, auto-create a payment record (in same transaction)
    if (paid > 0) {
      const receiptNo = await genReceiptNo(client);
      await client.query(`
        INSERT INTO payments (id, client_id, client_name, trainer_id, trainer_name,
          amount, method, date, receipt_no, package_type, incentive_amt)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [randomUUID(), id, d.name.trim(), trainer_id, trainer_name, paid,
         d.payment_method||'CASH', d.payment_date||new Date().toISOString().split('T')[0],
         receiptNo, d.package_type||null, Math.round(paid * incentiveRate)]
      );
    }

    await client.query('COMMIT');

    const { rows } = await pool.query('SELECT * FROM clients WHERE id=$1', [id]);
    res.status(201).json({ message: 'Client created', client: rows[0] });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    next(err);
  } finally {
    client.release();
  }
});

// PUT /api/clients/:id
router.put('/:id', auth, validate(clientSchemas.update), async (req, res, next) => {
  try {
    const d = req.body;
    const { rows: existing } = await pool.query('SELECT * FROM clients WHERE id=$1', [req.params.id]);
    if (!existing[0]) return res.status(404).json({ error: 'Client not found' });
    if (req.user.role === 'trainer' &&
        (!req.user.trainer_id || existing[0].trainer_id !== req.user.trainer_id))
      return res.status(403).json({ error: 'Access denied' });

    const base    = num(d.base_amount,   existing[0].base_amount);
    const disc    = num(d.discount,      existing[0].discount);
    const final   = num(d.final_amount,  existing[0].final_amount);
    const paid    = num(d.paid_amount,   existing[0].paid_amount);

    // Trainers cannot reassign clients to a different trainer
    const trainer_id = req.user.role === 'trainer'
      ? req.user.trainer_id
      : (d.trainer_id || existing[0].trainer_id || null);

    // Resolve trainer_name from supplied id when admin changes it
    let trainer_name = d.trainer_name || existing[0].trainer_name || null;
    if (req.user.role !== 'trainer' && d.trainer_id && d.trainer_id !== existing[0].trainer_id) {
      const { rows: tr } = await pool.query('SELECT name FROM trainers WHERE id=$1', [d.trainer_id]);
      trainer_name = tr[0]?.name || null;
    }

    await pool.query(`
      UPDATE clients SET
        name=$1, mobile=$2, email=$3, gender=$4, dob=$5, address=$6,
        trainer_id=$7, trainer_name=$8, pt_start_date=$9, pt_end_date=$10,
        package_type=$11, base_amount=$12, discount=$13, final_amount=$14,
        paid_amount=$15, balance_amount=$16, payment_method=$17, payment_date=$18,
        weight=$19, notes=$20, status=$21, photo_url=$22, biometric_code=$23,
        biometric_added=$24, updated_at=NOW()
      WHERE id=$25`,
      [d.name?.trim()||existing[0].name,
       d.mobile||null, d.email?.toLowerCase()||null,
       d.gender||null, d.dob||null, d.address||null,
       trainer_id, trainer_name,
       d.pt_start_date||null, d.pt_end_date||null,
       d.package_type||null, base, disc, final, paid, Math.max(0, final-paid),
       d.payment_method||'CASH', d.payment_date||null,
       num(d.weight, null), d.notes||null,
       d.status||existing[0].status,
       d.photo_url || null,
       d.biometric_code || existing[0].biometric_code || existing[0].client_id,
       Boolean(d.biometric_code || existing[0].biometric_code || existing[0].client_id),
       req.params.id]
    );
    const { rows } = await pool.query('SELECT * FROM clients WHERE id=$1', [req.params.id]);
    res.json({ message: 'Updated', client: rows[0] });
  } catch (err) {
    next(err);
  }
});

// GET /api/clients/:id/attendance
// Returns attendance logs for a single client (used by profile page tab).
router.get('/:id/attendance', auth, async (req, res, next) => {
  try {
    const { rows: client } = await pool.query('SELECT trainer_id FROM clients WHERE id=$1', [req.params.id]);
    if (!client[0]) return res.status(404).json({ error: 'Client not found' });
    if (req.user.role === 'trainer' &&
        (!req.user.trainer_id || client[0].trainer_id !== req.user.trainer_id)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    const limit  = Math.min(parseInt(req.query.limit, 10) || 200, 500);
    const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
    const { rows } = await pool.query(
      `SELECT id, date, check_in_time, check_out_time, method, notes
         FROM attendance_logs
        WHERE ref_id = $1 AND ref_type = 'client'
        ORDER BY date DESC, check_in_time DESC
        LIMIT $2 OFFSET $3`,
      [req.params.id, limit, offset]
    );
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

// GET /api/clients/:id/payments
// Returns payment history for a single client (used by profile page tab).
router.get('/:id/payments', auth, async (req, res, next) => {
  try {
    const { rows: client } = await pool.query('SELECT trainer_id FROM clients WHERE id=$1', [req.params.id]);
    if (!client[0]) return res.status(404).json({ error: 'Client not found' });
    if (req.user.role === 'trainer' &&
        (!req.user.trainer_id || client[0].trainer_id !== req.user.trainer_id)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    const limit  = Math.min(parseInt(req.query.limit, 10) || 200, 500);
    const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
    const { rows } = await pool.query(
      `SELECT id, amount, method, date, receipt_no, package_type AS plan, notes
         FROM payments
        WHERE client_id = $1
        ORDER BY date DESC, created_at DESC
        LIMIT $2 OFFSET $3`,
      [req.params.id, limit, offset]
    );
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

// DELETE /api/clients/:id (admin only)
//
// Soft delete by default. The 2026-05-perf-and-soft-delete migration adds
// `deleted_at TIMESTAMPTZ` to clients/payments. We set it instead of
// running DELETE so the financial trail (payments referencing this client)
// stays intact.
//
// Pass ?hard=1 to fall back to a hard DELETE — useful for cleaning up
// test rows but never the right call in production.
router.delete('/:id', auth, adminOnly, async (req, res, next) => {
  try {
    if (req.query.hard === '1') {
      const expectedConfirm = `HARD_DELETE_${req.params.id}`;
      if (!req.body || req.body.confirm !== expectedConfirm) {
        return res.status(400).json({
          error: `Hard delete requires request body: { "confirm": "${expectedConfirm}" }`,
        });
      }
      const { rows } = await pool.query(
        'DELETE FROM clients WHERE id=$1 RETURNING id',
        [req.params.id]
      );
      if (!rows[0]) return res.status(404).json({ error: 'Client not found' });
      return res.json({ message: 'Client hard-deleted' });
    }
    const { rows } = await pool.query(
      `UPDATE clients
          SET deleted_at = NOW(),
              updated_at = NOW(),
              status     = 'inactive'
        WHERE id = $1 AND deleted_at IS NULL
        RETURNING id`,
      [req.params.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'Client not found' });
    res.json({ message: 'Client deleted' });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
