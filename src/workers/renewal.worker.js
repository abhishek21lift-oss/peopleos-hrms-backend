// src/workers/renewal.worker.js
// Daily job: send expiry reminders + auto-renew memberships flagged auto_renew=true.
//
// Run via: node src/workers/renewal.worker.js
// In production: schedule via cron, BullMQ, or a Vercel cron route.

const pool = require('../db/pool');
const notifier = require('../modules/notifications/notifications.service');
const razorpay = require('../lib/razorpay');
const logger = require('../lib/logger');

const REMINDER_DAYS = [7, 3, 1];   // send reminder when this many days remain

async function runReminders() {
  for (const days of REMINDER_DAYS) {
    let rows;
    try {
      const result = await pool.query(`
        SELECT m.id AS member_id, m.user_id, m.name, m.email, m.phone,
               pl.name AS plan_name, mm.end_date,
               (mm.end_date - CURRENT_DATE) AS days_remaining
        FROM member_memberships mm
        JOIN members m ON m.id = mm.member_id
        JOIN plans pl ON pl.id = mm.plan_id
        WHERE mm.status = 'active'
          AND (mm.end_date - CURRENT_DATE) = $1
          AND m.deleted_at IS NULL
      `, [days]);
      rows = result.rows;
    } catch (err) {
      if (err.code === '42P01') {
        logger.warn({ days }, 'member_memberships or related table does not exist yet, skipping reminders');
        continue;
      }
      throw err;
    }

    for (const m of rows) {
      await notifier.send('membership_expiring', m, { days, plan: m.plan_name },
        ['inapp', 'email', 'whatsapp']);
    }
    logger.info({ count: rows.length, days }, 'sent expiry reminders');
  }
}


async function runAutoRenew() {
  if (!razorpay.isConfigured()) {
    logger.warn('Razorpay not configured — skipping auto-renew. Set RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET to enable.');
    return;
  }

  // Find memberships expiring TODAY with auto_renew=true and gateway available
  let rows;
  try {
    const result = await pool.query(`
      SELECT mm.*, m.name, m.email, m.phone, m.user_id, pl.name AS plan_name, pl.duration, pl.price
      FROM member_memberships mm
      JOIN members m ON m.id = mm.member_id
      JOIN plans pl ON pl.id = mm.plan_id
      WHERE mm.auto_renew = TRUE
        AND mm.status = 'active'
        AND mm.end_date = CURRENT_DATE
    `);
    rows = result.rows;
  } catch (err) {
    if (err.code === '42P01') {
      logger.warn('member_memberships or related table does not exist yet, skipping auto-renew');
      return;
    }
    throw err;
  }

  for (const m of rows) {
    const memberId = m.member_id;

    // Idempotency guard: skip if a renewal was already created in the last hour
    try {
      const recent = await pool.query(
        `SELECT id FROM member_memberships WHERE member_id = $1 AND created_at > NOW() - INTERVAL '1 hour'`,
        [memberId]
      );
      if (recent.rows.length > 0) {
        logger.info({ memberId }, 'Renewal already processed recently, skipping');
        continue;
      }
    } catch (err) {
      if (err.code === '42P01') {
        logger.warn({ memberId }, 'member_memberships table does not exist, skipping idempotency check');
        continue;
      }
      throw err;
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // 1. Create Razorpay order for the renewal amount.
      // NOTE: We do NOT call capturePayment here — a payment ID does not exist yet
      // at order creation time. Payment capture happens via Razorpay webhook after
      // the customer completes payment. See POST /api/payments/webhook.
      const order = await razorpay.createOrder(m.price * 100, 'INR', `renew_${m.id}_${Date.now()}`);
      logger.info({ orderId: order.id, member: m.name }, 'Razorpay order created for renewal — awaiting payment via webhook');

      // 2. Create new membership (pending payment confirmation via webhook)
      const newEnd = new Date();
      newEnd.setDate(newEnd.getDate() + m.duration);

      await client.query(
        `INSERT INTO member_memberships
           (member_id, plan_id, trainer_id, start_date, end_date,
            base_amount, final_amount, paid_amount, auto_renew, renewed_from_id, status)
         VALUES ($1,$2,$3, CURRENT_DATE, $4, $5, $5, 0, TRUE, $6, 'pending')`,
        [m.member_id, m.plan_id, m.trainer_id, newEnd, m.price, m.id]
      );

      // 3. Mark old as expired
      await client.query(`UPDATE member_memberships SET status='expired' WHERE id = $1`, [m.id]);

      await client.query('COMMIT');

      logger.info({ member: m.name, orderId: order.id }, 'auto-renew order created — payment pending');
    } catch (err) {
      await client.query('ROLLBACK');
      if (err.code === '42P01') {
        logger.warn({ member: m.name }, 'member_memberships table missing during auto-renew insert, skipping');
        continue;
      }
      logger.error({ member: m.name, err: err.message }, 'auto-renew failed');
      try {
        await notifier.send('payment_failed', m,
          { amount: m.price, error: err.message }, ['inapp', 'email']);
      } catch (_) { /* best-effort */ }
    } finally {
      client.release();
    }
  }
  logger.info({ count: rows.length }, 'auto-renew processed');
}

async function runClassReminders() {
  // 30 minutes before each class, ping confirmed members
  let rows;
  try {
    const result = await pool.query(`
      SELECT b.id AS booking_id, m.user_id, m.name, m.phone, m.email,
             ct.name AS class_name, TO_CHAR(cs.starts_at, 'HH24:MI') AS time,
             cs.id AS session_id
      FROM bookings b
      JOIN class_sessions cs ON cs.id = b.session_id
      JOIN class_templates ct ON ct.id = cs.template_id
      JOIN members m ON m.id = b.member_id
      WHERE b.status = 'confirmed'
        AND cs.starts_at BETWEEN NOW() + INTERVAL '25 minutes' AND NOW() + INTERVAL '35 minutes'
    `);
    rows = result.rows;
  } catch (err) {
    if (err.code === '42P01') {
      logger.warn('bookings or class_sessions table does not exist yet, skipping class reminders');
      return;
    }
    throw err;
  }
  for (const r of rows) {
    await notifier.send('class_reminder', r,
      { class_name: r.class_name, time: r.time }, ['inapp', 'whatsapp', 'push']);
  }
}

async function main() {
  logger.info('worker run starting');
  try {
    await runReminders();
    await runAutoRenew();
    await runClassReminders();
  } catch (err) {
    logger.error({ err: err.message }, 'worker run failed');
    process.exitCode = 1;
  }
  process.exit(0);
}

if (require.main === module) main();

module.exports = { runReminders, runAutoRenew, runClassReminders };
