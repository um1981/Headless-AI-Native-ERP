-- ============================================================================
-- Migration 0002: Document Sequences, General Ledger (GL), Inventory & RLS
-- Project: Headless AI-Native ERP
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Document Number Sequences (Atomic & Gapless with Row-Level Locking)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.document_sequences (
    doc_type text NOT NULL,
    period_key text NOT NULL, -- e.g. '202610'
    prefix text NOT NULL,
    last_number integer NOT NULL DEFAULT 0,
    padding integer NOT NULL DEFAULT 4,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (doc_type, period_key)
);

CREATE OR REPLACE FUNCTION public.fn_next_doc_number(
    p_doc_type text,
    p_prefix text,
    p_date date DEFAULT CURRENT_DATE
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_period_key text;
    v_next_num integer;
    v_padding integer;
BEGIN
    v_period_key := to_char(COALESCE(p_date, CURRENT_DATE), 'YYYYMM');

    INSERT INTO public.document_sequences (doc_type, period_key, prefix, last_number, padding)
    VALUES (p_doc_type, v_period_key, p_prefix, 1, 4)
    ON CONFLICT (doc_type, period_key)
    DO UPDATE SET
        last_number = public.document_sequences.last_number + 1,
        updated_at = now()
    RETURNING last_number, padding INTO v_next_num, v_padding;

    RETURN p_prefix || '-' || v_period_key || '-' || lpad(v_next_num::text, v_padding, '0');
END;
$$;

-- ----------------------------------------------------------------------------
-- 2. Fiscal Periods & Chart of Accounts (COA)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.fiscal_periods (
    period_key text PRIMARY KEY, -- 'YYYYMM', e.g., '202610'
    start_date date NOT NULL,
    end_date date NOT NULL,
    status text NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'CLOSED', 'LOCKED')),
    closed_at timestamptz,
    closed_by uuid REFERENCES public.erp_users(id),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.gl_accounts (
    code text PRIMARY KEY,
    name text NOT NULL,
    account_type text NOT NULL CHECK (account_type IN ('ASSET', 'LIABILITY', 'EQUITY', 'REVENUE', 'EXPENSE')),
    normal_balance text NOT NULL CHECK (normal_balance IN ('DEBIT', 'CREDIT')),
    parent_code text REFERENCES public.gl_accounts(code),
    is_control_account boolean NOT NULL DEFAULT false,
    allow_direct_posting boolean NOT NULL DEFAULT true,
    is_active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- ----------------------------------------------------------------------------
-- 3. Journal Vouchers (Drafts & Header) & Immutable GL Entries (Rule 3)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.journal_vouchers (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    voucher_no text UNIQUE NOT NULL,
    posting_date date NOT NULL,
    period_key text NOT NULL,
    source_module text NOT NULL DEFAULT 'GL' CHECK (source_module IN ('GL', 'INVENTORY', 'SALES', 'PURCHASE', 'SYSTEM')),
    description text NOT NULL,
    reference_no text,
    status text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'POSTED', 'REVERSED', 'CANCELLED')),
    total_debit numeric(18,2) NOT NULL DEFAULT 0 CHECK (total_debit >= 0),
    total_credit numeric(18,2) NOT NULL DEFAULT 0 CHECK (total_credit >= 0),
    reversal_of_voucher_id uuid REFERENCES public.journal_vouchers(id),
    reversed_by_voucher_id uuid REFERENCES public.journal_vouchers(id),
    -- Dual-Identity Maker (Draft Creator)
    created_by_user_id uuid NOT NULL REFERENCES public.erp_users(id),
    created_by_token_id uuid REFERENCES public.user_agent_tokens(id),
    created_by_client text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    -- Dual-Identity Checker (Approver / Poster)
    posted_by_user_id uuid REFERENCES public.erp_users(id),
    posted_by_token_id uuid REFERENCES public.user_agent_tokens(id),
    posted_by_client text,
    posted_at timestamptz
);

CREATE INDEX IF NOT EXISTS idx_journal_vouchers_status_date ON public.journal_vouchers (status, posting_date DESC);

CREATE TABLE IF NOT EXISTS public.journal_lines (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    voucher_id uuid NOT NULL REFERENCES public.journal_vouchers(id),
    line_no integer NOT NULL,
    account_code text NOT NULL REFERENCES public.gl_accounts(code),
    description text,
    debit numeric(18,2) NOT NULL DEFAULT 0 CHECK (debit >= 0),
    credit numeric(18,2) NOT NULL DEFAULT 0 CHECK (credit >= 0),
    department text,
    CHECK ((debit > 0 AND credit = 0) OR (credit > 0 AND debit = 0)),
    UNIQUE (voucher_id, line_no)
);

-- Strictly Immutable General Ledger Entries (Rule 3)
CREATE TABLE IF NOT EXISTS public.gl_entries (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    entry_no bigserial UNIQUE NOT NULL,
    voucher_id uuid NOT NULL REFERENCES public.journal_vouchers(id),
    voucher_no text NOT NULL,
    line_no integer NOT NULL,
    posting_date date NOT NULL,
    period_key text NOT NULL,
    account_code text NOT NULL REFERENCES public.gl_accounts(code),
    description text,
    debit numeric(18,2) NOT NULL DEFAULT 0 CHECK (debit >= 0),
    credit numeric(18,2) NOT NULL DEFAULT 0 CHECK (credit >= 0),
    department text,
    -- Dual-Identity Audit Columns
    actor_user_id uuid NOT NULL REFERENCES public.erp_users(id),
    token_id uuid REFERENCES public.user_agent_tokens(id),
    agent_client text NOT NULL,
    posted_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((debit > 0 AND credit = 0) OR (credit > 0 AND debit = 0))
);

CREATE INDEX IF NOT EXISTS idx_gl_entries_account_date ON public.gl_entries (account_code, posting_date);
CREATE INDEX IF NOT EXISTS idx_gl_entries_voucher ON public.gl_entries (voucher_id);

-- Enforce strict immutability on gl_entries (Rule 3)
CREATE OR REPLACE TRIGGER trg_gl_entries_immutable
BEFORE UPDATE OR DELETE ON public.gl_entries
FOR EACH ROW EXECUTE FUNCTION public.fn_block_mutation();

-- ----------------------------------------------------------------------------
-- 4. Inventory Master, Documents & Immutable Inventory Transactions (Rule 3)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.warehouses (
    code text PRIMARY KEY,
    name text NOT NULL,
    is_active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.items (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    sku text UNIQUE NOT NULL,
    name text NOT NULL,
    uom text NOT NULL DEFAULT 'PCS',
    standard_cost numeric(18,4) NOT NULL DEFAULT 0 CHECK (standard_cost >= 0),
    inventory_account_code text NOT NULL REFERENCES public.gl_accounts(code),
    cogs_account_code text NOT NULL REFERENCES public.gl_accounts(code),
    is_active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.inventory_balances (
    item_id uuid NOT NULL REFERENCES public.items(id),
    warehouse_code text NOT NULL REFERENCES public.warehouses(code),
    qty_on_hand numeric(18,4) NOT NULL DEFAULT 0 CHECK (qty_on_hand >= 0),
    avg_unit_cost numeric(18,4) NOT NULL DEFAULT 0 CHECK (avg_unit_cost >= 0),
    total_value numeric(18,2) NOT NULL DEFAULT 0 CHECK (total_value >= 0),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (item_id, warehouse_code)
);

CREATE TABLE IF NOT EXISTS public.inventory_documents (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    doc_no text UNIQUE NOT NULL,
    doc_type text NOT NULL CHECK (doc_type IN ('RECEIPT', 'ISSUE', 'ADJUSTMENT_IN', 'ADJUSTMENT_OUT')),
    warehouse_code text NOT NULL REFERENCES public.warehouses(code),
    movement_date date NOT NULL,
    offset_account_code text NOT NULL REFERENCES public.gl_accounts(code),
    reference_no text,
    notes text,
    status text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'POSTED', 'REVERSED', 'CANCELLED')),
    total_amount numeric(18,2) NOT NULL DEFAULT 0 CHECK (total_amount >= 0),
    gl_voucher_id uuid REFERENCES public.journal_vouchers(id),
    -- Dual-Identity Maker
    created_by_user_id uuid NOT NULL REFERENCES public.erp_users(id),
    created_by_token_id uuid REFERENCES public.user_agent_tokens(id),
    created_by_client text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    -- Dual-Identity Checker (Poster)
    posted_by_user_id uuid REFERENCES public.erp_users(id),
    posted_by_token_id uuid REFERENCES public.user_agent_tokens(id),
    posted_by_client text,
    posted_at timestamptz
);

CREATE TABLE IF NOT EXISTS public.inventory_document_lines (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    doc_id uuid NOT NULL REFERENCES public.inventory_documents(id),
    line_no integer NOT NULL,
    item_id uuid NOT NULL REFERENCES public.items(id),
    qty numeric(18,4) NOT NULL CHECK (qty > 0),
    unit_cost numeric(18,4) NOT NULL CHECK (unit_cost >= 0),
    line_amount numeric(18,2) NOT NULL CHECK (line_amount >= 0),
    notes text,
    UNIQUE (doc_id, line_no)
);

-- Strictly Immutable Inventory Ledger Transactions (Rule 3)
CREATE TABLE IF NOT EXISTS public.inventory_transactions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tx_no bigserial UNIQUE NOT NULL,
    doc_id uuid NOT NULL REFERENCES public.inventory_documents(id),
    doc_no text NOT NULL,
    doc_type text NOT NULL,
    movement_date date NOT NULL,
    warehouse_code text NOT NULL REFERENCES public.warehouses(code),
    item_id uuid NOT NULL REFERENCES public.items(id),
    qty_change numeric(18,4) NOT NULL CHECK (qty_change <> 0),
    unit_cost numeric(18,4) NOT NULL CHECK (unit_cost >= 0),
    value_change numeric(18,2) NOT NULL,
    qty_balance_after numeric(18,4) NOT NULL CHECK (qty_balance_after >= 0),
    value_balance_after numeric(18,2) NOT NULL CHECK (value_balance_after >= 0),
    gl_voucher_id uuid REFERENCES public.journal_vouchers(id),
    -- Dual-Identity Audit Columns
    actor_user_id uuid NOT NULL REFERENCES public.erp_users(id),
    token_id uuid REFERENCES public.user_agent_tokens(id),
    agent_client text NOT NULL,
    posted_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_inv_tx_item_wh ON public.inventory_transactions (item_id, warehouse_code, posted_at DESC);

-- Enforce strict immutability on inventory_transactions (Rule 3)
CREATE OR REPLACE TRIGGER trg_inventory_transactions_immutable
BEFORE UPDATE OR DELETE ON public.inventory_transactions
FOR EACH ROW EXECUTE FUNCTION public.fn_block_mutation();

-- ----------------------------------------------------------------------------
-- 5. System Heartbeats (Rule 4: Supabase Free Tier Keep-Alive)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.system_heartbeats (
    id bigserial PRIMARY KEY,
    source text NOT NULL,
    beat_at timestamptz NOT NULL DEFAULT now(),
    details jsonb
);

-- ----------------------------------------------------------------------------
-- 6. Attach Audit Triggers to All Domain Tables (Rule 4)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE TRIGGER trg_audit_fiscal_periods AFTER INSERT OR UPDATE OR DELETE ON public.fiscal_periods FOR EACH ROW EXECUTE FUNCTION public.fn_audit_trigger();
CREATE OR REPLACE TRIGGER trg_audit_gl_accounts AFTER INSERT OR UPDATE OR DELETE ON public.gl_accounts FOR EACH ROW EXECUTE FUNCTION public.fn_audit_trigger();
CREATE OR REPLACE TRIGGER trg_audit_journal_vouchers AFTER INSERT OR UPDATE OR DELETE ON public.journal_vouchers FOR EACH ROW EXECUTE FUNCTION public.fn_audit_trigger();
CREATE OR REPLACE TRIGGER trg_audit_gl_entries AFTER INSERT OR UPDATE OR DELETE ON public.gl_entries FOR EACH ROW EXECUTE FUNCTION public.fn_audit_trigger();
CREATE OR REPLACE TRIGGER trg_audit_warehouses AFTER INSERT OR UPDATE OR DELETE ON public.warehouses FOR EACH ROW EXECUTE FUNCTION public.fn_audit_trigger();
CREATE OR REPLACE TRIGGER trg_audit_items AFTER INSERT OR UPDATE OR DELETE ON public.items FOR EACH ROW EXECUTE FUNCTION public.fn_audit_trigger();
CREATE OR REPLACE TRIGGER trg_audit_inventory_documents AFTER INSERT OR UPDATE OR DELETE ON public.inventory_documents FOR EACH ROW EXECUTE FUNCTION public.fn_audit_trigger();
CREATE OR REPLACE TRIGGER trg_audit_inventory_transactions AFTER INSERT OR UPDATE OR DELETE ON public.inventory_transactions FOR EACH ROW EXECUTE FUNCTION public.fn_audit_trigger();

-- ----------------------------------------------------------------------------
-- 7. Row-Level Security & Zero Direct Table Mutation Enforcement (Rule 1)
-- ----------------------------------------------------------------------------
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.erp_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.role_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_agent_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.document_sequences ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.fiscal_periods ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.gl_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.journal_vouchers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.journal_lines ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.gl_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.warehouses ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.items ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.inventory_balances ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.inventory_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.inventory_document_lines ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.inventory_transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.system_heartbeats ENABLE ROW LEVEL SECURITY;

CREATE POLICY pol_read_audit_logs ON public.audit_logs FOR SELECT USING (true);
CREATE POLICY pol_read_erp_users ON public.erp_users FOR SELECT USING (true);
CREATE POLICY pol_read_roles ON public.roles FOR SELECT USING (true);
CREATE POLICY pol_read_permissions ON public.permissions FOR SELECT USING (true);
CREATE POLICY pol_read_role_permissions ON public.role_permissions FOR SELECT USING (true);
CREATE POLICY pol_read_user_roles ON public.user_roles FOR SELECT USING (true);
CREATE POLICY pol_read_fiscal_periods ON public.fiscal_periods FOR SELECT USING (true);
CREATE POLICY pol_read_gl_accounts ON public.gl_accounts FOR SELECT USING (true);
CREATE POLICY pol_read_journal_vouchers ON public.journal_vouchers FOR SELECT USING (true);
CREATE POLICY pol_read_journal_lines ON public.journal_lines FOR SELECT USING (true);
CREATE POLICY pol_read_gl_entries ON public.gl_entries FOR SELECT USING (true);
CREATE POLICY pol_read_warehouses ON public.warehouses FOR SELECT USING (true);
CREATE POLICY pol_read_items ON public.items FOR SELECT USING (true);
CREATE POLICY pol_read_inventory_balances ON public.inventory_balances FOR SELECT USING (true);
CREATE POLICY pol_read_inventory_documents ON public.inventory_documents FOR SELECT USING (true);
CREATE POLICY pol_read_inventory_document_lines ON public.inventory_document_lines FOR SELECT USING (true);
CREATE POLICY pol_read_inventory_transactions ON public.inventory_transactions FOR SELECT USING (true);
CREATE POLICY pol_read_system_heartbeats ON public.system_heartbeats FOR SELECT USING (true);
