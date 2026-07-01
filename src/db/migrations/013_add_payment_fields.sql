-- ─────────────────────────────────────────────────────────────
-- 013: Add payment fields to subscriptions table
-- Adds paid_amount, sale_amount, balance_amount, payment_status
-- subscriptions was removed in migration 021; guard all statements
-- ─────────────────────────────────────────────────────────────

DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'subscriptions') THEN
    ALTER TABLE subscriptions
      ADD COLUMN IF NOT EXISTS paid_amount     NUMERIC(12,2) NOT NULL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS sale_amount     NUMERIC(12,2) NOT NULL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS balance_amount  NUMERIC(12,2) NOT NULL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS payment_status  TEXT NOT NULL DEFAULT 'PAID'
        CHECK (payment_status IN ('PAID','PENDING','PARTIAL','REFUNDED'));

    UPDATE subscriptions
      SET paid_amount    = COALESCE(NULLIF(paid_amount, 0), final_amount),
          sale_amount    = COALESCE(NULLIF(sale_amount, 0), final_amount),
          balance_amount = 0,
          payment_status = 'PAID'
      WHERE paid_amount IS NULL OR paid_amount = 0;
  END IF;
END $$;
