// src/routes/payments.js
const express = require('express');
const router = express.Router();
const { randomUUID } = require('crypto');
const pool = require('../db/pool');
const { genReceiptNo } = require('../db/receipts');
const { auth, adminOnly } = require('../middleware/auth');
const { validate } = require('../middleware/validate');
const { paymentSchemas } = require('../lib/validation');
const logger = require('../lib/logger');

// POST /api/payments/webhook — Razorpay webhook handler (signature-verified)
router.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    const signature = req.headers['x-razorpay-signature'];
    const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET;
    if (!webhookSecret) {
      logger.warn('RAZORPAY_WEBHOOK_SECRET not configured');
      return res.status(500).json({ error: 'Webhook not configured' });
    }
    const crypto = require('crypto');
    const expectedSignature = crypto
      .createHmac('sha256', webhookSecret)
      .update(req.body)
      .digest('hex');
    if (expectedSignature !== signature) {
      return res.status(400).json({ error: 'Invalid webhook signature' });
    }
    const event = JSON.parse(req.body.toString());
    logger.info({ event: event.event }, 'Razorpay webhook received');
    if (event.event === 'payment.captured') {
      const paymentId = event.payload?.payment?.entity?.id;
      const orderId = event.payload?.payment?.entity?.order_id;
      logger.info({ paymentId, orderId }, 'Payment captured');
    }
    res.json({ status: 'ok' });
  } catch (err) {
    logger.error(err, 'Webhook handler error');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/payments
router.get('/', auth, async (req, res, next) => {
  try {
    const { client_id, trainer_id, from, to, limit = 200, offset = 0 } = req.query;
    const conditions = [];
    const params = [];
    let p = 1;

    if (req.user.role === 'trainer' && req.user.trainer_id) {
      conditions.push(`p.trainer_id = $${p++}`); params.push(req.user.trainer_id);
    } else if (trainer_id) {
      conditions.push(`p.trainer_id = $${p++}`); params.push(trainer_id);
    }
    if (client_id) { conditions.push(`p.client_id = $${p++}`); params.push(client_id); }
    if (from)      { conditions.push(`p.date >= $${p++}`);     params.push(from); }
    if (to)        { conditions.push(`p.date <= $${p++}`);     params.push(to); }
    // Hide soft-deleted payments unless caller explicitly asks for them.
    if (req.query.include_deleted !== '1') {
      conditions.push(`p.deleted_at IS NULL`);
    }

    const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';

    const { rows } = await pool.query(`
      SELECT p.*, c.name AS client_name, t.name AS trainer_name_full
      FROM payments p
      LEFT JOIN clients  c ON c.id = p.client_id
      LEFT JOIN trainers t ON t.id = p.trainer_id
      ${where}
      ORDER BY p.date DESC, p.created_at DESC
      LIMIT $${p++} OFFSET $${p++}`,
      [...params, parseInt(limit), parseInt(offset)]
    );
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

// POST /api/payments
router.post('/', auth, validate(paymentSchemas.create), async (req, res, next) => {
  const tx = await pool.connect();
  try {
    const d = req.body;
    if (!d.client_id || !d.amount || !d.date)
      return res.status(400).json({ error: 'client_id, amount and date required' });

    const amount = parseFloat(d.amount);
    if (!Number.isFinite(amount) || amount <= 0)
      return res.status(400).json({ error: 'Amount must be a positive number' });

    await tx.query('BEGIN');

    // Get client info (lock the row to prevent concurrent balance drift)
    const { rows: cl } = await tx.query(
      'SELECT * FROM clients WHERE id=$1 FOR UPDATE', [d.client_id]
    );
    if (!cl[0]) {
      await tx.query('ROLLBACK');
      return res.status(404).json({ error: 'Client not found' });
    }

    // ── RBAC: trainers can only record payments for THEIR OWN clients ──
    // (Without this check, any trainer could post a payment against any client
    // by guessing/pasting a client_id — breaking the data isolation guarantee.)
    if (req.user.role === 'trainer' && cl[0].trainer_id !== req.user.trainer_id) {
      await tx.query('ROLLBACK');
      return res.status(403).json({ error: 'Access denied: client is not assigned to you' });
    }

    // Get trainer incentive rate — use ?? not || so a legitimate 0 doesn't fall back to 0.5
    let incentiveRate = 0.5;
    if (cl[0].trainer_id) {
      const { rows: tr } = await tx.query(
        'SELECT incentive_rate FROM trainers WHERE id=$1', [cl[0].trainer_id]
      );
      incentiveRate = tr[0]?.incentive_rate ?? 0.5;
    }

    const id = randomUUID();
    const receiptNo = await genReceiptNo(tx);

    await tx.query(`
      INSERT INTO payments (id,client_id,client_name,trainer_id,trainer_name,
        amount,method,date,receipt_no,package_type,incentive_amt,notes)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [id, d.client_id, cl[0].name,
       cl[0].trainer_id, cl[0].trainer_name,
       amount, d.method||'CASH', d.date, receiptNo,
       cl[0].package_type, Math.round(amount * incentiveRate),
       d.notes||null]
    );

    // Update client balance
    await tx.query(`
      UPDATE clients
      SET paid_amount = paid_amount + $1,
          balance_amount = GREATEST(0, balance_amount - $1),
          updated_at = NOW()
      WHERE id = $2`, [amount, d.client_id]
    );

    await tx.query('COMMIT');

    const { rows } = await pool.query('SELECT * FROM payments WHERE id=$1', [id]);
    res.status(201).json({ message: 'Payment recorded', payment: rows[0] });
  } catch (err) {
    await tx.query('ROLLBACK').catch(() => {});
    logger.error({ err: err.message }, 'Payment error');
    next(err);
  } finally {
    tx.release();
  }
});

// DELETE /api/payments/:id (admin only)
//
// Soft delete by default (sets deleted_at). The balance reversal still runs
// so the client's paid/balance figures stay correct. Pass ?hard=1 to fully
// remove the row — only do this for tests.
router.delete('/:id', auth, adminOnly, async (req, res, next) => {
  const tx = await pool.connect();
  try {
    await tx.query('BEGIN');

    let payment;
    let alreadyReversed = false;
    if (req.query.hard === '1') {
      // Don't double-reverse a balance that a prior soft-delete already reset.
      const { rows } = await tx.query(
        'DELETE FROM payments WHERE id=$1 RETURNING *', [req.params.id]
      );
      payment = rows[0];
      if (payment && payment.deleted_at) alreadyReversed = true;
    } else {
      const { rows } = await tx.query(
        `UPDATE payments
            SET deleted_at = NOW(), updated_at = NOW()
          WHERE id = $1 AND deleted_at IS NULL
          RETURNING *`, [req.params.id]
      );
      payment = rows[0];
    }

    if (!payment) {
      await tx.query('ROLLBACK');
      return res.status(404).json({ error: 'Not found' });
    }

    // Reverse the balance change atomically (only if not already done
    // by a previous soft-delete of the same row).
    if (!alreadyReversed) {
      await tx.query(`
        UPDATE clients
        SET paid_amount = GREATEST(0, paid_amount - $1),
            balance_amount = balance_amount + $1,
            updated_at = NOW()
        WHERE id = $2`, [payment.amount, payment.client_id]
      );
    }
    await tx.query('COMMIT');
    res.json({ message: 'Payment deleted' });
  } catch (err) {
    await tx.query('ROLLBACK').catch(() => {});
    next(err);
  } finally {
    tx.release();
  }
});

module.exports = router;
