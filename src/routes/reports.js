// src/routes/reports.js
const router = require('express').Router();
const pool = require('../db/pool');
const { auth, adminOnly } = require('../middleware/auth');

// GET /api/reports/monthly
router.get('/monthly', auth, async (req, res, next) => {
  try {
    const { year = new Date().getFullYear() } = req.query;
    const isTrainer = req.user.role === 'trainer';
    const tid = isTrainer ? req.user.trainer_id : null;
    const params = tid ? [parseInt(year), tid] : [parseInt(year)];
    const trainerWhere = tid ? 'AND trainer_id=$2' : '';

    const { rows } = await pool.query(`
      SELECT
        EXTRACT(MONTH FROM date::date) AS month_num,
        TO_CHAR(DATE_TRUNC('month', date::date), 'Month') AS month_name,
        COUNT(*) AS payment_count,
        COALESCE(SUM(amount),0) AS revenue,
        COALESCE(SUM(incentive_amt),0) AS incentives
      FROM payments
      WHERE EXTRACT(YEAR FROM date::date) = $1 ${trainerWhere}
      GROUP BY month_num, month_name
      ORDER BY month_num`, params
    );
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

// GET /api/reports/trainers (admin only)
// Note: /trainer-summary was removed as a duplicate — use /trainers instead
router.get('/trainers', auth, adminOnly, async (req, res, next) => {
  try {
    const { rows } = await pool.query(`
      SELECT t.id, t.name, t.specialization,
        COUNT(DISTINCT c.id) FILTER (WHERE c.status='active') AS active_clients,
        COUNT(DISTINCT c.id) AS total_clients,
        COALESCE(SUM(p.amount) FILTER (WHERE p.date >= DATE_TRUNC('month',NOW())),0) AS month_revenue,
        COALESCE(SUM(p.amount),0) AS total_revenue
      FROM trainers t
      LEFT JOIN clients  c ON c.trainer_id = t.id
      LEFT JOIN payments p ON p.trainer_id = t.id
      WHERE t.status = 'active'
      GROUP BY t.id, t.name, t.specialization
      ORDER BY total_revenue DESC`
    );
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

// GET /api/reports/dues
router.get('/dues', auth, async (req, res, next) => {
  try {
    const tid = req.user.role === 'trainer' ? req.user.trainer_id : null;
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 50));
    const offset = (page - 1) * limit;

    const params = [];
    let where = 'c.balance_amount > 0';
    if (tid) {
      params.push(tid);
      where += ` AND c.trainer_id = $${params.length}`;
    }

    const countParams = [...params];
    const countResult = await pool.query(
      `SELECT COUNT(*) AS total FROM clients c WHERE ${where}`,
      countParams
    );
    const total = parseInt(countResult.rows[0].total) || 0;

    params.push(limit, offset);
    const { rows } = await pool.query(`
      SELECT c.id, c.client_id, c.name, c.mobile, c.trainer_name,
             c.balance_amount, c.pt_end_date, c.status
      FROM clients c
      WHERE ${where}
      ORDER BY c.balance_amount DESC
      LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );
    res.json({
      data: rows,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
