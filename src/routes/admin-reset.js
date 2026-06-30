const express = require('express');
const router  = express.Router();
const pool    = require('../db/pool');
const { auth, adminOnly } = require('../middleware/auth');
const logger  = require('../lib/logger');
const { escapeIdentifier } = require('pg');

const ALLOWED_TABLES = new Set([
  'attendance_logs', 'payments', 'subscriptions', 'invoices', 'outstanding_dues',
  'client_goals', 'transformations', 'face_embeddings', 'notifications', 'message_logs',
  'clients', 'clients_id_seq', 'payments_id_seq', 'attendance_logs_id_seq',
  'subscriptions_id_seq', 'invoices_id_seq',
]);

function validateTableName(tableName) {
  if (!ALLOWED_TABLES.has(tableName)) {
    throw new Error(`Invalid table name: ${tableName}`);
  }
  return tableName;
}

async function deleteIfExists(client, tableName) {
  const safe = escapeIdentifier(validateTableName(tableName));
  await client.query(`
    DO $$
    BEGIN
      IF to_regclass('public.${safe}') IS NOT NULL THEN
        EXECUTE 'DELETE FROM ${safe}';
      END IF;
    END
    $$;
  `);
}

async function dropIfExists(client, tableName) {
  await client.query(`DROP TABLE IF EXISTS ${escapeIdentifier(validateTableName(tableName))} CASCADE`);
}

/* ══════════════════════════════════════════════════════════════════════
   POST /admin/reset-all-data
   Body: { confirm: "DELETE_ALL_619_DATA" }
══════════════════════════════════════════════════════════════════════ */
router.post('/reset-all-data', auth, adminOnly, async (req, res) => {
  if (req.body?.confirm !== 'DELETE_ALL_619_DATA') {
    return res.status(400).json({ error: 'Missing confirmation token. Send { confirm: "DELETE_ALL_619_DATA" } in request body.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    await deleteIfExists(client, 'attendance_logs');
    await deleteIfExists(client, 'payments');
    await deleteIfExists(client, 'subscriptions');
    await deleteIfExists(client, 'invoices');
    await dropIfExists(client, 'outstanding_dues');
    await deleteIfExists(client, 'client_goals');
    await deleteIfExists(client, 'transformations');
    await deleteIfExists(client, 'face_embeddings');
    await deleteIfExists(client, 'notifications');
    await deleteIfExists(client, 'message_logs');
    if ((await client.query("SELECT to_regclass('public.clients') AS exists")).rows[0].exists) {
      await client.query(`UPDATE clients SET balance_amount = 0 WHERE COALESCE(balance_amount, 0) <> 0`);
      await client.query(`DELETE FROM clients`);
    }

    const seqs = [
      'clients_id_seq',
      'payments_id_seq',
      'attendance_logs_id_seq',
      'subscriptions_id_seq',
      'invoices_id_seq',
    ];
    for (const seq of seqs) {
      try {
        await client.query(`ALTER SEQUENCE ${seq} RESTART WITH 1`);
      } catch {}
    }

    await client.query('COMMIT');
    res.json({ success: true, message: 'All member data, payments, attendance, and related records have been cleared safely. Missing legacy tables were skipped automatically.' });
  } catch (err) {
    await client.query('ROLLBACK');
    logger.error({ err: err.message }, 'Reset all data error');
    res.status(500).json({ error: 'Reset failed. Check server logs.' });
  } finally {
    client.release();
  }
});

async function doClearDuesAndPayments() {
  await dropIfExists(pool, 'outstanding_dues');
  await deleteIfExists(pool, 'payments');
  const hasClients = (await pool.query("SELECT to_regclass('public.clients') AS exists")).rows[0].exists;
  if (hasClients) {
    await pool.query(`UPDATE clients SET balance_amount = 0 WHERE COALESCE(balance_amount, 0) <> 0`).catch(() => {});
  }
}

router.post('/reset-outstanding-dues', auth, adminOnly, async (req, res) => {
  if (req.body?.confirm !== 'CLEAR_DUES_619') {
    return res.status(400).json({ error: 'Missing confirmation token. Send { confirm: "CLEAR_DUES_619" }' });
  }
  try {
    await doClearDuesAndPayments();
    res.json({ success: true, message: 'Payments and dues-related data cleared safely, and client balances were reset to zero.' });
  } catch (err) {
    logger.error({ err: err.message }, 'Reset dues error');
    res.status(500).json({ error: 'Operation failed. Check server logs.' });
  }
});

router.post('/clear-dues-and-payments', auth, adminOnly, async (req, res) => {
  if (req.body?.confirm !== 'CLEAR_DUES_619') {
    return res.status(400).json({ error: 'Missing confirmation token. Send { confirm: "CLEAR_DUES_619" }' });
  }
  try {
    await doClearDuesAndPayments();
    res.json({ success: true, message: 'Payments and dues-related data cleared safely, and client balances were reset to zero.' });
  } catch (err) {
    logger.error({ err: err.message }, 'Clear dues and payments error');
    res.status(500).json({ error: 'Operation failed. Check server logs.' });
  }
});

module.exports = router;
