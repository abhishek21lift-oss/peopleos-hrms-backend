// src/routes/staff.js
const express = require('express');
const router  = express.Router();
const { auth, adminOnly } = require('../middleware/auth');
const { validate } = require('../middleware/validate');
const { staffSchemas } = require('../lib/validation');
const pool = require('../db/pool');

// ─────────────────────────────────────────────────────────────────
// IMPORTANT: /targets routes MUST come before /:id routes.
// Express matches routes in order — literal paths before params.
// ─────────────────────────────────────────────────────────────────

// GET /api/staff/targets
router.get('/targets', auth, async (req, res, next) => {
  try {
    const { month } = req.query;
    let query = `
      SELECT st.*, s.name AS staff_name, s.role
      FROM staff_targets st
      LEFT JOIN staff s ON s.id = st.staff_id
      WHERE 1=1`;
    const params = [];
    if (month) {
      params.push(month);
      query += ` AND st.month = $${params.length}`;
    }
    const limit  = Math.min(parseInt(req.query.limit, 10) || 200, 500);
    const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
    params.push(limit, offset);
    query += ` ORDER BY st.month DESC, s.name LIMIT $${params.length - 1} OFFSET $${params.length}`;
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) { next(err); }
});

// POST /api/staff/targets
router.post('/targets', auth, adminOnly, async (req, res, next) => {
  try {
    const {
      staff_id, month,
      target_revenue = 0, target_clients = 0, target_sessions = 0,
      achieved_revenue = 0, achieved_clients = 0, achieved_sessions = 0,
    } = req.body;
    if (!staff_id || !month) return res.status(400).json({ error: 'staff_id and month are required' });
    const { rows } = await pool.query(
      `INSERT INTO staff_targets
         (staff_id, month, target_revenue, target_clients, target_sessions,
          achieved_revenue, achieved_clients, achieved_sessions)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       RETURNING *`,
      [staff_id, month, target_revenue, target_clients, target_sessions,
       achieved_revenue, achieved_clients, achieved_sessions]
    );
    res.status(201).json({ message: 'Target created', target: rows[0] });
  } catch (err) {
    if (err.code === '23505' && err.constraint === 'staff_targets_staff_id_month_key') {
      return res.status(409).json({ error: 'A target already exists for this staff member and month. Use edit instead.' });
    }
    next(err);
  }
});

// PUT /api/staff/targets/:id
router.put('/targets/:id', auth, adminOnly, async (req, res, next) => {
  try {
    const fields = [
      'target_revenue','target_clients','target_sessions',
      'achieved_revenue','achieved_clients','achieved_sessions','month',
    ];
    const updates = [];
    const params  = [];
    fields.forEach((f) => {
      if (req.body[f] !== undefined) {
        params.push(req.body[f]);
        updates.push(`${f} = $${params.length}`);
      }
    });
    if (!updates.length) return res.status(400).json({ error: 'No fields to update' });
    params.push(req.params.id);
    const { rows } = await pool.query(
      `UPDATE staff_targets SET ${updates.join(', ')} WHERE id = $${params.length} RETURNING *`,
      params
    );
    if (!rows.length) return res.status(404).json({ error: 'Target not found' });
    res.json({ message: 'Target updated', target: rows[0] });
  } catch (err) { next(err); }
});

// DELETE /api/staff/targets/:id
router.delete('/targets/:id', auth, adminOnly, async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      'DELETE FROM staff_targets WHERE id=$1 RETURNING id', [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Target not found' });
    res.json({ message: 'Target deleted' });
  } catch (err) { next(err); }
});

// ─────────────────────────────────────────────────────────────────
// STAFF CRUD  (/:id routes come AFTER /targets)
// ─────────────────────────────────────────────────────────────────

// GET /api/staff
router.get('/', auth, async (req, res, next) => {
  try {
    const { role, status, search } = req.query;
    let query = 'SELECT * FROM staff WHERE 1=1';
    const params = [];
    if (role) {
      params.push(role);
      query += ` AND role = $${params.length}`;
    }
    if (status) {
      params.push(status);
      query += ` AND status = $${params.length}`;
    }
    if (search) {
      params.push(`%${search}%`);
      const n = params.length;
      query += ` AND (name ILIKE $${n} OR email ILIKE $${n} OR phone ILIKE $${n})`;
    }
    const limit  = Math.min(parseInt(req.query.limit, 10) || 200, 500);
    const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
    params.push(limit, offset);
    query += ` ORDER BY created_at DESC LIMIT $${params.length - 1} OFFSET $${params.length}`;
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) { next(err); }
});

// GET /api/staff/:id
router.get('/:id', auth, async (req, res, next) => {
  try {
    const { rows } = await pool.query('SELECT * FROM staff WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Staff member not found' });
    res.json(rows[0]);
  } catch (err) { next(err); }
});

// POST /api/staff
router.post('/', auth, adminOnly, validate(staffSchemas.create), async (req, res, next) => {
  try {
    const { name, email, phone, role, status = 'active' } = req.body;
    if (!name || !role) return res.status(400).json({ error: 'name and role are required' });
    const { rows } = await pool.query(
      `INSERT INTO staff (name, email, phone, role, status, created_at)
       VALUES ($1, $2, $3, $4, $5, NOW()) RETURNING *`,
      [name, email || null, phone || null, role, status]
    );
    res.status(201).json({ message: 'Staff member created', staff: rows[0] });
  } catch (err) { next(err); }
});

// PUT /api/staff/:id
router.put('/:id', auth, adminOnly, validate(staffSchemas.update), async (req, res, next) => {
  try {
    const { name, email, phone, role, status } = req.body;
    const { rows: ex } = await pool.query('SELECT * FROM staff WHERE id = $1', [req.params.id]);
    if (!ex.length) return res.status(404).json({ error: 'Staff member not found' });
    const cur = ex[0];
    const { rows } = await pool.query(
      `UPDATE staff SET name=$1, email=$2, phone=$3, role=$4, status=$5
       WHERE id=$6 RETURNING *`,
      [
        name   ?? cur.name,
        email  ?? cur.email,
        phone  ?? cur.phone,
        role   ?? cur.role,
        status ?? cur.status,
        req.params.id,
      ]
    );
    res.json({ message: 'Staff member updated', staff: rows[0] });
  } catch (err) { next(err); }
});

// DELETE /api/staff/:id
router.delete('/:id', auth, adminOnly, async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      'DELETE FROM staff WHERE id = $1 RETURNING id', [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Staff member not found' });
    res.json({ message: 'Staff member deleted' });
  } catch (err) { next(err); }
});

module.exports = router;
