-- ============================================================================
-- Migration 0003: Fat Database PL/pgSQL RPC Functions (Rule 1, 2, 3, 4, 5)
-- Project: Headless AI-Native ERP
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. rpc_whoami: Inspect Authenticated User, Agent Token & Effective RBAC
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.rpc_whoami(p_agent_token text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_auth public.auth_context_result;
    v_roles jsonb;
    v_permissions jsonb;
    v_scopes text[];
BEGIN
    v_auth := public.fn_authenticate_and_authorize(p_agent_token, NULL, 'rpc_whoami');

    SELECT allowed_scopes INTO v_scopes
    FROM public.user_agent_tokens
    WHERE id = v_auth.token_id;

    SELECT COALESCE(jsonb_agg(jsonb_build_object(
        'role_code', r.code,
        'role_name', r.name
    )), '[]'::jsonb)
    INTO v_roles
    FROM public.user_roles ur
    JOIN public.roles r ON r.code = ur.role_code AND r.is_active = true
    WHERE ur.user_id = v_auth.user_id;

    SELECT COALESCE(jsonb_agg(jsonb_build_object(
        'permission_code', p.permission_code,
        'module', p.module,
        'require_different_approver', p.require_different_approver,
        'max_approval_amount', p.max_approval_amount
    )), '[]'::jsonb)
    INTO v_permissions
    FROM (
        SELECT
            rp.permission_code,
            perm.module,
            bool_and(rp.require_different_approver) AS require_different_approver,
            CASE WHEN bool_or(rp.max_approval_amount IS NULL) THEN NULL ELSE max(rp.max_approval_amount) END AS max_approval_amount
        FROM public.user_roles ur
        JOIN public.roles r ON r.code = ur.role_code AND r.is_active = true
        JOIN public.role_permissions rp ON rp.role_code = r.code
        JOIN public.permissions perm ON perm.code = rp.permission_code
        WHERE ur.user_id = v_auth.user_id
          AND (v_scopes IS NULL OR rp.permission_code = ANY(v_scopes) OR '*' = ANY(v_scopes))
        GROUP BY rp.permission_code, perm.module
        ORDER BY rp.permission_code
    ) p;

    RETURN jsonb_build_object(
        'user_id', v_auth.user_id,
        'email', v_auth.email,
        'full_name', v_auth.full_name,
        'token_id', v_auth.token_id,
        'agent_client', v_auth.agent_client,
        'allowed_scopes', v_scopes,
        'roles', v_roles,
        'effective_permissions', v_permissions
    );
END;
$$;

-- ----------------------------------------------------------------------------
-- 2. Dynamic RBAC & Multi-Agent PAT Management RPCs
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.rpc_assign_user_role(
    p_agent_token text,
    p_target_email text,
    p_full_name text,
    p_department text,
    p_role_code text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_auth public.auth_context_result;
    v_target_user_id uuid;
BEGIN
    v_auth := public.fn_authenticate_and_authorize(p_agent_token, 'rbac.manage', 'rpc_assign_user_role');

    IF NOT EXISTS (SELECT 1 FROM public.roles WHERE code = p_role_code AND is_active = true) THEN
        RAISE EXCEPTION 'INVALID_ROLE: Role "%" does not exist or is inactive.', p_role_code;
    END IF;

    INSERT INTO public.erp_users (email, full_name, department, is_active)
    VALUES (lower(btrim(p_target_email)), btrim(p_full_name), p_department, true)
    ON CONFLICT (email) DO UPDATE SET
        full_name = EXCLUDED.full_name,
        department = COALESCE(EXCLUDED.department, public.erp_users.department),
        is_active = true,
        updated_at = now()
    RETURNING id INTO v_target_user_id;

    INSERT INTO public.user_roles (user_id, role_code, assigned_by)
    VALUES (v_target_user_id, p_role_code, v_auth.user_id)
    ON CONFLICT (user_id, role_code) DO NOTHING;

    RETURN jsonb_build_object(
        'status', 'SUCCESS',
        'user_id', v_target_user_id,
        'email', lower(btrim(p_target_email)),
        'assigned_role', p_role_code,
        'executed_by_client', v_auth.agent_client
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.rpc_configure_role_permission(
    p_agent_token text,
    p_role_code text,
    p_permission_code text,
    p_require_different_approver boolean DEFAULT false,
    p_max_approval_amount numeric DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_auth public.auth_context_result;
    v_rp_id uuid;
BEGIN
    v_auth := public.fn_authenticate_and_authorize(p_agent_token, 'rbac.manage', 'rpc_configure_role_permission');

    INSERT INTO public.role_permissions (
        role_code, permission_code, require_different_approver, max_approval_amount
    ) VALUES (
        p_role_code, p_permission_code, COALESCE(p_require_different_approver, false), p_max_approval_amount
    )
    ON CONFLICT (role_code, permission_code) DO UPDATE SET
        require_different_approver = EXCLUDED.require_different_approver,
        max_approval_amount = EXCLUDED.max_approval_amount,
        updated_at = now()
    RETURNING id INTO v_rp_id;

    RETURN jsonb_build_object(
        'status', 'SUCCESS',
        'role_permission_id', v_rp_id,
        'role_code', p_role_code,
        'permission_code', p_permission_code,
        'require_different_approver', COALESCE(p_require_different_approver, false),
        'max_approval_amount', p_max_approval_amount
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.rpc_issue_agent_token(
    p_agent_token text,
    p_target_email text,
    p_client_name text,
    p_allowed_scopes text[] DEFAULT NULL,
    p_expires_in_days integer DEFAULT 365
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_auth public.auth_context_result;
    v_target_user public.erp_users%ROWTYPE;
    v_clean_client text;
    v_raw_secret text;
    v_Plain_token text;
    v_token_hash text;
    v_token_id uuid;
    v_expires_at timestamptz;
BEGIN
    v_auth := public.fn_authenticate_and_authorize(p_agent_token, NULL, 'rpc_issue_agent_token');

    SELECT * INTO v_target_user
    FROM public.erp_users
    WHERE email = lower(btrim(p_target_email)) AND is_active = true;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'USER_NOT_FOUND: Active user with email "%" not found.', p_target_email;
    END IF;

    IF v_target_user.id <> v_auth.user_id THEN
        PERFORM public.fn_authenticate_and_authorize(p_agent_token, 'rbac.manage', 'rpc_issue_agent_token');
    END IF;

    v_clean_client := regexp_replace(lower(btrim(p_client_name)), '[^a-z0-9_-]', '-', 'g');
    v_raw_secret := replace(gen_random_uuid()::text, '-', '') || substr(md5(random()::text || clock_timestamp()::text), 1, 16);
    v_Plain_token := 'erp_pat_' || v_clean_client || '_' || v_raw_secret;
    v_token_hash := encode(pg_catalog.sha256(convert_to(v_Plain_token, 'UTF8')), 'hex');
    v_expires_at := CASE WHEN p_expires_in_days IS NOT NULL THEN now() + (p_expires_in_days || ' days')::interval ELSE NULL END;

    INSERT INTO public.user_agent_tokens (
        user_id, client_name, token_prefix, token_hash, allowed_scopes, is_active, expires_at
    ) VALUES (
        v_target_user.id,
        v_clean_client,
        substr(v_Plain_token, 1, 20) || '...',
        v_token_hash,
        p_allowed_scopes,
        true,
        v_expires_at
    )
    RETURNING id INTO v_token_id;

    RETURN jsonb_build_object(
        'status', 'SUCCESS',
        'token_id', v_token_id,
        'user_id', v_target_user.id,
        'email', v_target_user.email,
        'client_name', v_clean_client,
        'allowed_scopes', p_allowed_scopes,
        'expires_at', v_expires_at,
        'personal_agent_token', v_Plain_token,
        'notice', 'Store this personal_agent_token securely. Only its SHA-256 hash is stored in the database.'
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.rpc_revoke_agent_token(
    p_agent_token text,
    p_target_token_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_auth public.auth_context_result;
    v_target_token public.user_agent_tokens%ROWTYPE;
BEGIN
    v_auth := public.fn_authenticate_and_authorize(p_agent_token, NULL, 'rpc_revoke_agent_token');

    SELECT * INTO v_target_token
    FROM public.user_agent_tokens
    WHERE id = p_target_token_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'TOKEN_NOT_FOUND: Token ID "%" not found.', p_target_token_id;
    END IF;

    IF v_target_token.user_id <> v_auth.user_id THEN
        PERFORM public.fn_authenticate_and_authorize(p_agent_token, 'rbac.manage', 'rpc_revoke_agent_token');
    END IF;

    UPDATE public.user_agent_tokens
    SET is_active = false,
        revoked_at = now()
    WHERE id = p_target_token_id;

    RETURN jsonb_build_object(
        'status', 'REVOKED',
        'token_id', p_target_token_id,
        'client_name', v_target_token.client_name,
        'revoked_at', now()
    );
END;
$$;

-- ----------------------------------------------------------------------------
-- 3. General Ledger (GL) RPCs: COA, Draft, Post (with Maker-Checker), Reverse
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.rpc_create_gl_account(
    p_agent_token text,
    p_code text,
    p_name text,
    p_account_type text,
    p_normal_balance text,
    p_parent_code text DEFAULT NULL,
    p_is_control_account boolean DEFAULT false,
    p_allow_direct_posting boolean DEFAULT true
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_auth public.auth_context_result;
BEGIN
    v_auth := public.fn_authenticate_and_authorize(p_agent_token, 'gl.coa.manage', 'rpc_create_gl_account');

    INSERT INTO public.gl_accounts (
        code, name, account_type, normal_balance, parent_code, is_control_account, allow_direct_posting, is_active
    ) VALUES (
        btrim(p_code), btrim(p_name), upper(btrim(p_account_type)), upper(btrim(p_normal_balance)),
        p_parent_code, COALESCE(p_is_control_account, false), COALESCE(p_allow_direct_posting, true), true
    )
    ON CONFLICT (code) DO UPDATE SET
        name = EXCLUDED.name,
        account_type = EXCLUDED.account_type,
        normal_balance = EXCLUDED.normal_balance,
        parent_code = EXCLUDED.parent_code,
        is_control_account = EXCLUDED.is_control_account,
        allow_direct_posting = EXCLUDED.allow_direct_posting,
        updated_at = now();

    RETURN jsonb_build_object(
        'status', 'SUCCESS',
        'account_code', btrim(p_code),
        'name', btrim(p_name),
        'account_type', upper(btrim(p_account_type))
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.rpc_create_journal_draft(
    p_agent_token text,
    p_posting_date date,
    p_description text,
    p_reference_no text,
    p_lines jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_auth public.auth_context_result;
    v_period_key text;
    v_period_status text;
    v_voucher_id uuid;
    v_voucher_no text;
    v_line jsonb;
    v_idx integer := 0;
    v_debit numeric(18,2);
    v_credit numeric(18,2);
    v_total_debit numeric(18,2) := 0;
    v_total_credit numeric(18,2) := 0;
    v_acc_code text;
    v_acc_row public.gl_accounts%ROWTYPE;
BEGIN
    v_auth := public.fn_authenticate_and_authorize(p_agent_token, 'gl.voucher.draft', 'rpc_create_journal_draft');

    IF p_lines IS NULL OR jsonb_typeof(p_lines) <> 'array' OR jsonb_array_length(p_lines) < 2 THEN
        RAISE EXCEPTION 'GL_VALIDATION_ERROR: Journal voucher must contain at least 2 lines.';
    END IF;

    v_period_key := to_char(p_posting_date, 'YYYYMM');

    INSERT INTO public.fiscal_periods (period_key, start_date, end_date, status)
    VALUES (
        v_period_key,
        date_trunc('month', p_posting_date)::date,
        (date_trunc('month', p_posting_date) + interval '1 month - 1 day')::date,
        'OPEN'
    )
    ON CONFLICT (period_key) DO NOTHING;

    SELECT status INTO v_period_status
    FROM public.fiscal_periods
    WHERE period_key = v_period_key;

    IF v_period_status <> 'OPEN' THEN
        RAISE EXCEPTION 'FISCAL_PERIOD_CLOSED: Fiscal period "%" is % and cannot accept postings.', v_period_key, v_period_status;
    END IF;

    v_voucher_no := public.fn_next_doc_number('JV', 'JV', p_posting_date);

    INSERT INTO public.journal_vouchers (
        voucher_no, posting_date, period_key, source_module, description, reference_no,
        status, total_debit, total_credit,
        created_by_user_id, created_by_token_id, created_by_client
    ) VALUES (
        v_voucher_no, p_posting_date, v_period_key, 'GL', btrim(p_description), p_reference_no,
        'DRAFT', 0, 0,
        v_auth.user_id, v_auth.token_id, v_auth.agent_client
    )
    RETURNING id INTO v_voucher_id;

    FOR v_line IN SELECT * FROM jsonb_array_elements(p_lines)
    LOOP
        v_idx := v_idx + 1;
        v_acc_code := btrim(v_line->>'account_code');
        v_debit := ROUND(COALESCE((v_line->>'debit')::numeric, 0), 2);
        v_credit := ROUND(COALESCE((v_line->>'credit')::numeric, 0), 2);

        SELECT * INTO v_acc_row
        FROM public.gl_accounts
        WHERE code = v_acc_code AND is_active = true;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'GL_INVALID_ACCOUNT: Line % references non-existent or inactive GL account "%".', v_idx, v_acc_code;
        END IF;

        IF NOT v_acc_row.allow_direct_posting THEN
            RAISE EXCEPTION 'GL_CONTROL_ACCOUNT_RESTRICTED: Account "%" (%) does not allow direct manual journal lines.', v_acc_code, v_acc_row.name;
        END IF;

        IF (v_debit <= 0 AND v_credit <= 0) OR (v_debit > 0 AND v_credit > 0) THEN
            RAISE EXCEPTION 'GL_LINE_ERROR: Line % must have either debit > 0 OR credit > 0 (not both).', v_idx;
        END IF;

        INSERT INTO public.journal_lines (
            voucher_id, line_no, account_code, description, debit, credit, department
        ) VALUES (
            v_voucher_id, v_idx, v_acc_code, COALESCE(v_line->>'description', btrim(p_description)),
            v_debit, v_credit, v_line->>'department'
        );

        v_total_debit := v_total_debit + v_debit;
        v_total_credit := v_total_credit + v_credit;
    END LOOP;

    IF v_total_debit <> v_total_credit OR v_total_debit <= 0 THEN
        RAISE EXCEPTION 'DOUBLE_ENTRY_IMBALANCE: Total Debit (%) does not equal Total Credit (%).', v_total_debit, v_total_credit;
    END IF;

    UPDATE public.journal_vouchers
    SET total_debit = v_total_debit,
        total_credit = v_total_credit
    WHERE id = v_voucher_id;

    RETURN jsonb_build_object(
        'status', 'DRAFT',
        'voucher_id', v_voucher_id,
        'voucher_no', v_voucher_no,
        'posting_date', p_posting_date,
        'total_debit', v_total_debit,
        'total_credit', v_total_credit,
        'created_by_user', v_auth.email,
        'created_by_client', v_auth.agent_client
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.rpc_post_journal_voucher(
    p_agent_token text,
    p_voucher_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_auth public.auth_context_result;
    v_voucher public.journal_vouchers%ROWTYPE;
    v_period_status text;
    v_sum_debit numeric(18,2);
    v_sum_credit numeric(18,2);
    v_line_count integer;
BEGIN
    v_auth := public.fn_authenticate_and_authorize(p_agent_token, 'gl.voucher.post', 'rpc_post_journal_voucher');

    SELECT * INTO v_voucher
    FROM public.journal_vouchers
    WHERE id = p_voucher_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'VOUCHER_NOT_FOUND: Voucher ID "%" does not exist.', p_voucher_id;
    END IF;

    IF v_voucher.status <> 'DRAFT' THEN
        RAISE EXCEPTION 'INVALID_VOUCHER_STATUS: Voucher "%" has status "%" and cannot be posted.', v_voucher.voucher_no, v_voucher.status;
    END IF;

    IF v_auth.require_different_approver AND v_voucher.created_by_user_id = v_auth.user_id THEN
        RAISE EXCEPTION 'MAKER_CHECKER_VIOLATION: Separation of duties policy requires a different user to approve/post voucher "%" than its creator (%).',
            v_voucher.voucher_no, v_auth.email;
    END IF;

    IF v_auth.max_approval_amount IS NOT NULL AND v_voucher.total_debit > v_auth.max_approval_amount THEN
        RAISE EXCEPTION 'APPROVAL_LIMIT_EXCEEDED: Voucher amount (%) exceeds your role maximum approval limit (%).',
            v_voucher.total_debit, v_auth.max_approval_amount;
    END IF;

    SELECT status INTO v_period_status
    FROM public.fiscal_periods
    WHERE period_key = v_voucher.period_key;

    IF v_period_status IS DISTINCT FROM 'OPEN' THEN
        RAISE EXCEPTION 'FISCAL_PERIOD_CLOSED: Period "%" is not OPEN.', v_voucher.period_key;
    END IF;

    SELECT COUNT(*), COALESCE(SUM(debit), 0), COALESCE(SUM(credit), 0)
    INTO v_line_count, v_sum_debit, v_sum_credit
    FROM public.journal_lines
    WHERE voucher_id = v_voucher.id;

    IF v_line_count < 2 OR v_sum_debit <= 0 OR v_sum_debit <> v_sum_credit THEN
        RAISE EXCEPTION 'DOUBLE_ENTRY_VALIDATION_FAILED: Voucher "%" failed double-entry check (lines=%, debit=%, credit=%).',
            v_voucher.voucher_no, v_line_count, v_sum_debit, v_sum_credit;
    END IF;

    INSERT INTO public.gl_entries (
        voucher_id, voucher_no, line_no, posting_date, period_key,
        account_code, description, debit, credit, department,
        actor_user_id, token_id, agent_client
    )
    SELECT
        v_voucher.id, v_voucher.voucher_no, jl.line_no, v_voucher.posting_date, v_voucher.period_key,
        jl.account_code, jl.description, jl.debit, jl.credit, jl.department,
        v_auth.user_id, v_auth.token_id, v_auth.agent_client
    FROM public.journal_lines jl
    WHERE jl.voucher_id = v_voucher.id
    ORDER BY jl.line_no;

    UPDATE public.journal_vouchers
    SET status = 'POSTED',
        total_debit = v_sum_debit,
        total_credit = v_sum_credit,
        posted_by_user_id = v_auth.user_id,
        posted_by_token_id = v_auth.token_id,
        posted_by_client = v_auth.agent_client,
        posted_at = now()
    WHERE id = v_voucher.id;

    RETURN jsonb_build_object(
        'status', 'POSTED',
        'voucher_id', v_voucher.id,
        'voucher_no', v_voucher.voucher_no,
        'total_debit', v_sum_debit,
        'total_credit', v_sum_credit,
        'posted_by_user', v_auth.email,
        'posted_by_client', v_auth.agent_client,
        'posted_at', now()
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.rpc_reverse_journal_voucher(
    p_agent_token text,
    p_voucher_id uuid,
    p_reversal_date date DEFAULT CURRENT_DATE,
    p_reason text DEFAULT 'Reversal entry'
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_auth public.auth_context_result;
    v_orig public.journal_vouchers%ROWTYPE;
    v_rev_period_key text;
    v_rev_voucher_id uuid;
    v_rev_voucher_no text;
BEGIN
    v_auth := public.fn_authenticate_and_authorize(p_agent_token, 'gl.voucher.reverse', 'rpc_reverse_journal_voucher');

    SELECT * INTO v_orig
    FROM public.journal_vouchers
    WHERE id = p_voucher_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'VOUCHER_NOT_FOUND: Voucher ID "%" does not exist.', p_voucher_id;
    END IF;

    IF v_orig.status <> 'POSTED' THEN
        RAISE EXCEPTION 'INVALID_REVERSAL_TARGET: Only POSTED vouchers can be reversed (current status: "%").', v_orig.status;
    END IF;

    IF v_orig.reversed_by_voucher_id IS NOT NULL THEN
        RAISE EXCEPTION 'ALREADY_REVERSED: Voucher "%" has already been reversed.', v_orig.voucher_no;
    END IF;

    v_rev_period_key := to_char(p_reversal_date, 'YYYYMM');
    INSERT INTO public.fiscal_periods (period_key, start_date, end_date, status)
    VALUES (
        v_rev_period_key,
        date_trunc('month', p_reversal_date)::date,
        (date_trunc('month', p_reversal_date) + interval '1 month - 1 day')::date,
        'OPEN'
    )
    ON CONFLICT (period_key) DO NOTHING;

    v_rev_voucher_no := public.fn_next_doc_number('JV', 'JVR', p_reversal_date);

    INSERT INTO public.journal_vouchers (
        voucher_no, posting_date, period_key, source_module,
        description, reference_no, status,
        total_debit, total_credit, reversal_of_voucher_id,
        created_by_user_id, created_by_token_id, created_by_client,
        posted_by_user_id, posted_by_token_id, posted_by_client, posted_at
    ) VALUES (
        v_rev_voucher_no, p_reversal_date, v_rev_period_key, v_orig.source_module,
        'REVERSAL OF ' || v_orig.voucher_no || ': ' || COALESCE(btrim(p_reason), 'Reversal'),
        v_orig.voucher_no, 'POSTED',
        v_orig.total_credit, v_orig.total_debit, v_orig.id,
        v_auth.user_id, v_auth.token_id, v_auth.agent_client,
        v_auth.user_id, v_auth.token_id, v_auth.agent_client, now()
    )
    RETURNING id INTO v_rev_voucher_id;

    INSERT INTO public.journal_lines (
        voucher_id, line_no, account_code, description, debit, credit, department
    )
    SELECT
        v_rev_voucher_id, jl.line_no, jl.account_code,
        'Reversal: ' || COALESCE(jl.description, ''),
        jl.credit, jl.debit, jl.department
    FROM public.journal_lines jl
    WHERE jl.voucher_id = v_orig.id
    ORDER BY jl.line_no;

    INSERT INTO public.gl_entries (
        voucher_id, voucher_no, line_no, posting_date, period_key,
        account_code, description, debit, credit, department,
        actor_user_id, token_id, agent_client
    )
    SELECT
        v_rev_voucher_id, v_rev_voucher_no, jl.line_no, p_reversal_date, v_rev_period_key,
        jl.account_code, jl.description, jl.debit, jl.credit, jl.department,
        v_auth.user_id, v_auth.token_id, v_auth.agent_client
    FROM public.journal_lines jl
    WHERE jl.voucher_id = v_rev_voucher_id
    ORDER BY jl.line_no;

    UPDATE public.journal_vouchers
    SET status = 'REVERSED',
        reversed_by_voucher_id = v_rev_voucher_id
    WHERE id = v_orig.id;

    RETURN jsonb_build_object(
        'status', 'REVERSED',
        'original_voucher_id', v_orig.id,
        'original_voucher_no', v_orig.voucher_no,
        'reversal_voucher_id', v_rev_voucher_id,
        'reversal_voucher_no', v_rev_voucher_no,
        'reversal_date', p_reversal_date,
        'reversed_by_user', v_auth.email,
        'reversed_by_client', v_auth.agent_client
    );
END;
$$;

-- ----------------------------------------------------------------------------
-- 4. Inventory & Warehouse RPCs (Integrated with Immutable GL Entries)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.rpc_create_item(
    p_agent_token text,
    p_sku text,
    p_name text,
    p_uom text DEFAULT 'PCS',
    p_standard_cost numeric DEFAULT 0,
    p_inventory_account_code text DEFAULT '1300',
    p_cogs_account_code text DEFAULT '5100'
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_auth public.auth_context_result;
    v_item_id uuid;
BEGIN
    v_auth := public.fn_authenticate_and_authorize(p_agent_token, 'inventory.master.manage', 'rpc_create_item');

    INSERT INTO public.items (
        sku, name, uom, standard_cost, inventory_account_code, cogs_account_code, is_active
    ) VALUES (
        upper(btrim(p_sku)), btrim(p_name), upper(btrim(COALESCE(p_uom, 'PCS'))),
        COALESCE(p_standard_cost, 0), btrim(p_inventory_account_code), btrim(p_cogs_account_code), true
    )
    ON CONFLICT (sku) DO UPDATE SET
        name = EXCLUDED.name,
        uom = EXCLUDED.uom,
        standard_cost = EXCLUDED.standard_cost,
        inventory_account_code = EXCLUDED.inventory_account_code,
        cogs_account_code = EXCLUDED.cogs_account_code,
        updated_at = now()
    RETURNING id INTO v_item_id;

    RETURN jsonb_build_object(
        'status', 'SUCCESS',
        'item_id', v_item_id,
        'sku', upper(btrim(p_sku)),
        'name', btrim(p_name)
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.rpc_create_inventory_doc_draft(
    p_agent_token text,
    p_doc_type text,
    p_warehouse_code text,
    p_movement_date date,
    p_offset_account_code text,
    p_reference_no text,
    p_notes text,
    p_lines jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_auth public.auth_context_result;
    v_clean_type text;
    v_doc_id uuid;
    v_doc_no text;
    v_line jsonb;
    v_idx integer := 0;
    v_item public.items%ROWTYPE;
    v_qty numeric(18,4);
    v_unit_cost numeric(18,4);
    v_line_amount numeric(18,2);
    v_total_amount numeric(18,2) := 0;
BEGIN
    v_auth := public.fn_authenticate_and_authorize(p_agent_token, 'inventory.movement.draft', 'rpc_create_inventory_doc_draft');

    v_clean_type := upper(btrim(p_doc_type));
    IF v_clean_type NOT IN ('RECEIPT', 'ISSUE', 'ADJUSTMENT_IN', 'ADJUSTMENT_OUT') THEN
        RAISE EXCEPTION 'INVALID_DOC_TYPE: Must be RECEIPT, ISSUE, ADJUSTMENT_IN, or ADJUSTMENT_OUT.';
    END IF;

    IF p_lines IS NULL OR jsonb_typeof(p_lines) <> 'array' OR jsonb_array_length(p_lines) < 1 THEN
        RAISE EXCEPTION 'INV_VALIDATION_ERROR: Inventory document must contain at least 1 item line.';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM public.warehouses WHERE code = btrim(p_warehouse_code) AND is_active = true) THEN
        RAISE EXCEPTION 'WAREHOUSE_NOT_FOUND: Warehouse "%" does not exist.', p_warehouse_code;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM public.gl_accounts WHERE code = btrim(p_offset_account_code) AND is_active = true) THEN
        RAISE EXCEPTION 'GL_ACCOUNT_NOT_FOUND: Offset GL account "%" does not exist.', p_offset_account_code;
    END IF;

    v_doc_no := public.fn_next_doc_number('INV_' || v_clean_type, 'INV', p_movement_date);

    INSERT INTO public.inventory_documents (
        doc_no, doc_type, warehouse_code, movement_date, offset_account_code,
        reference_no, notes, status, total_amount,
        created_by_user_id, created_by_token_id, created_by_client
    ) VALUES (
        v_doc_no, v_clean_type, btrim(p_warehouse_code), p_movement_date, btrim(p_offset_account_code),
        p_reference_no, p_notes, 'DRAFT', 0,
        v_auth.user_id, v_auth.token_id, v_auth.agent_client
    )
    RETURNING id INTO v_doc_id;

    FOR v_line IN SELECT * FROM jsonb_array_elements(p_lines)
    LOOP
        v_idx := v_idx + 1;

        SELECT * INTO v_item
        FROM public.items
        WHERE (sku = upper(btrim(COALESCE(v_line->>'sku', ''))) OR id::text = COALESCE(v_line->>'item_id', ''))
          AND is_active = true;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'ITEM_NOT_FOUND: Line % references unknown SKU/item_id.', v_idx;
        END IF;

        v_qty := ROUND(COALESCE((v_line->>'qty')::numeric, 0), 4);
        IF v_qty <= 0 THEN
            RAISE EXCEPTION 'INVALID_QTY: Line % qty must be > 0.', v_idx;
        END IF;

        v_unit_cost := ROUND(COALESCE((v_line->>'unit_cost')::numeric, v_item.standard_cost), 4);
        v_line_amount := ROUND(v_qty * v_unit_cost, 2);

        INSERT INTO public.inventory_document_lines (
            doc_id, line_no, item_id, qty, unit_cost, line_amount, notes
        ) VALUES (
            v_doc_id, v_idx, v_item.id, v_qty, v_unit_cost, v_line_amount, v_line->>'notes'
        );

        v_total_amount := v_total_amount + v_line_amount;
    END LOOP;

    UPDATE public.inventory_documents
    SET total_amount = v_total_amount
    WHERE id = v_doc_id;

    RETURN jsonb_build_object(
        'status', 'DRAFT',
        'doc_id', v_doc_id,
        'doc_no', v_doc_no,
        'doc_type', v_clean_type,
        'warehouse_code', btrim(p_warehouse_code),
        'total_amount', v_total_amount,
        'created_by_user', v_auth.email,
        'created_by_client', v_auth.agent_client
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.rpc_post_inventory_doc(
    p_agent_token text,
    p_doc_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_auth public.auth_context_result;
    v_doc public.inventory_documents%ROWTYPE;
    v_line RECORD;
    v_bal public.inventory_balances%ROWTYPE;
    v_is_inbound boolean;
    v_qty_change numeric(18,4);
    v_eff_unit_cost numeric(18,4);
    v_val_change numeric(18,2);
    v_new_qty numeric(18,4);
    v_new_val numeric(18,2);
    v_new_avg numeric(18,4);
    v_total_posted_val numeric(18,2) := 0;
    v_period_key text;
    v_voucher_id uuid;
    v_voucher_no text;
    v_gl_line_no integer := 0;
BEGIN
    v_auth := public.fn_authenticate_and_authorize(p_agent_token, 'inventory.movement.post', 'rpc_post_inventory_doc');

    SELECT * INTO v_doc
    FROM public.inventory_documents
    WHERE id = p_doc_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'INV_DOC_NOT_FOUND: Document ID "%" not found.', p_doc_id;
    END IF;

    IF v_doc.status <> 'DRAFT' THEN
        RAISE EXCEPTION 'INVALID_INV_DOC_STATUS: Document "%" has status "%" and cannot be posted.', v_doc.doc_no, v_doc.status;
    END IF;

    IF v_auth.require_different_approver AND v_doc.created_by_user_id = v_auth.user_id THEN
        RAISE EXCEPTION 'MAKER_CHECKER_VIOLATION: Separation of duties requires a different user to post inventory document "%" than its creator (%).',
            v_doc.doc_no, v_auth.email;
    END IF;

    IF v_auth.max_approval_amount IS NOT NULL AND v_doc.total_amount > v_auth.max_approval_amount THEN
        RAISE EXCEPTION 'APPROVAL_LIMIT_EXCEEDED: Document amount (%) exceeds your role approval limit (%).',
            v_doc.total_amount, v_auth.max_approval_amount;
    END IF;

    v_is_inbound := v_doc.doc_type IN ('RECEIPT', 'ADJUSTMENT_IN');
    v_period_key := to_char(v_doc.movement_date, 'YYYYMM');

    INSERT INTO public.fiscal_periods (period_key, start_date, end_date, status)
    VALUES (
        v_period_key,
        date_trunc('month', v_doc.movement_date)::date,
        (date_trunc('month', v_doc.movement_date) + interval '1 month - 1 day')::date,
        'OPEN'
    )
    ON CONFLICT (period_key) DO NOTHING;

    v_voucher_no := public.fn_next_doc_number('JV', 'JVI', v_doc.movement_date);
    INSERT INTO public.journal_vouchers (
        voucher_no, posting_date, period_key, source_module,
        description, reference_no, status, total_debit, total_credit,
        created_by_user_id, created_by_token_id, created_by_client,
        posted_by_user_id, posted_by_token_id, posted_by_client, posted_at
    ) VALUES (
        v_voucher_no, v_doc.movement_date, v_period_key, 'INVENTORY',
        'Auto GL from Inventory ' || v_doc.doc_type || ' ' || v_doc.doc_no,
        v_doc.doc_no, 'POSTED', 0, 0,
        v_doc.created_by_user_id, v_doc.created_by_token_id, v_doc.created_by_client,
        v_auth.user_id, v_auth.token_id, v_auth.agent_client, now()
    )
    RETURNING id INTO v_voucher_id;

    FOR v_line IN
        SELECT l.*, i.sku, i.name AS item_name, i.inventory_account_code, i.cogs_account_code
        FROM public.inventory_document_lines l
        JOIN public.items i ON i.id = l.item_id
        WHERE l.doc_id = v_doc.id
        ORDER BY l.line_no
    LOOP
        INSERT INTO public.inventory_balances (item_id, warehouse_code, qty_on_hand, avg_unit_cost, total_value)
        VALUES (v_line.item_id, v_doc.warehouse_code, 0, 0, 0)
        ON CONFLICT (item_id, warehouse_code) DO NOTHING;

        SELECT * INTO v_bal
        FROM public.inventory_balances
        WHERE item_id = v_line.item_id AND warehouse_code = v_doc.warehouse_code
        FOR UPDATE;

        IF v_is_inbound THEN
            v_qty_change := v_line.qty;
            v_eff_unit_cost := v_line.unit_cost;
            v_val_change := ROUND(v_line.qty * v_eff_unit_cost, 2);
            v_new_qty := v_bal.qty_on_hand + v_qty_change;
            v_new_val := v_bal.total_value + v_val_change;
            v_new_avg := CASE WHEN v_new_qty > 0 THEN ROUND(v_new_val / v_new_qty, 4) ELSE 0 END;
        ELSE
            IF v_bal.qty_on_hand < v_line.qty THEN
                RAISE EXCEPTION 'INSUFFICIENT_STOCK: Item "%" in warehouse "%" has on-hand % but document requires %.',
                    v_line.sku, v_doc.warehouse_code, v_bal.qty_on_hand, v_line.qty;
            END IF;
            v_qty_change := -v_line.qty;
            v_eff_unit_cost := v_bal.avg_unit_cost;
            IF v_bal.qty_on_hand = v_line.qty THEN
                v_val_change := -v_bal.total_value;
            ELSE
                v_val_change := -ROUND(v_line.qty * v_eff_unit_cost, 2);
            END IF;
            v_new_qty := v_bal.qty_on_hand + v_qty_change;
            v_new_val := v_bal.total_value + v_val_change;
            v_new_avg := CASE WHEN v_new_qty > 0 THEN v_bal.avg_unit_cost ELSE 0 END;
        END IF;

        UPDATE public.inventory_balances
        SET qty_on_hand = v_new_qty,
            avg_unit_cost = v_new_avg,
            total_value = v_new_val,
            updated_at = now()
        WHERE item_id = v_line.item_id AND warehouse_code = v_doc.warehouse_code;

        INSERT INTO public.inventory_transactions (
            doc_id, doc_no, doc_type, movement_date, warehouse_code, item_id,
            qty_change, unit_cost, value_change, qty_balance_after, value_balance_after,
            gl_voucher_id, actor_user_id, token_id, agent_client
        ) VALUES (
            v_doc.id, v_doc.doc_no, v_doc.doc_type, v_doc.movement_date, v_doc.warehouse_code, v_line.item_id,
            v_qty_change, v_eff_unit_cost, v_val_change, v_new_qty, v_new_val,
            v_voucher_id, v_auth.user_id, v_auth.token_id, v_auth.agent_client
        );

        IF abs(v_val_change) > 0 THEN
            v_total_posted_val := v_total_posted_val + abs(v_val_change);

            v_gl_line_no := v_gl_line_no + 1;
            INSERT INTO public.journal_lines (
                voucher_id, line_no, account_code, description, debit, credit
            ) VALUES (
                v_voucher_id, v_gl_line_no,
                CASE WHEN v_is_inbound THEN v_line.inventory_account_code ELSE v_doc.offset_account_code END,
                v_doc.doc_no || ' - ' || v_line.sku || ' (' || v_line.qty || ')',
                abs(v_val_change), 0
            );

            v_gl_line_no := v_gl_line_no + 1;
            INSERT INTO public.journal_lines (
                voucher_id, line_no, account_code, description, debit, credit
            ) VALUES (
                v_voucher_id, v_gl_line_no,
                CASE WHEN v_is_inbound THEN v_doc.offset_account_code ELSE v_line.inventory_account_code END,
                v_doc.doc_no || ' - ' || v_line.sku || ' (' || v_line.qty || ')',
                0, abs(v_val_change)
            );
        END IF;
    END LOOP;

    INSERT INTO public.gl_entries (
        voucher_id, voucher_no, line_no, posting_date, period_key,
        account_code, description, debit, credit,
        actor_user_id, token_id, agent_client
    )
    SELECT
        v_voucher_id, v_voucher_no, jl.line_no, v_doc.movement_date, v_period_key,
        jl.account_code, jl.description, jl.debit, jl.credit,
        v_auth.user_id, v_auth.token_id, v_auth.agent_client
    FROM public.journal_lines jl
    WHERE jl.voucher_id = v_voucher_id
    ORDER BY jl.line_no;

    UPDATE public.journal_vouchers
    SET total_debit = v_total_posted_val,
        total_credit = v_total_posted_val
    WHERE id = v_voucher_id;

    UPDATE public.inventory_documents
    SET status = 'POSTED',
        total_amount = v_total_posted_val,
        gl_voucher_id = v_voucher_id,
        posted_by_user_id = v_auth.user_id,
        posted_by_token_id = v_auth.token_id,
        posted_by_client = v_auth.agent_client,
        posted_at = now()
    WHERE id = v_doc.id;

    RETURN jsonb_build_object(
        'status', 'POSTED',
        'doc_id', v_doc.id,
        'doc_no', v_doc.doc_no,
        'doc_type', v_doc.doc_type,
        'total_posted_value', v_total_posted_val,
        'gl_voucher_id', v_voucher_id,
        'gl_voucher_no', v_voucher_no,
        'posted_by_user', v_auth.email,
        'posted_by_client', v_auth.agent_client
    );
END;
$$;

-- ----------------------------------------------------------------------------
-- 5. Reporting & Keep-Alive RPCs
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.rpc_get_trial_balance(
    p_agent_token text,
    p_as_of_date date DEFAULT CURRENT_DATE
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_auth public.auth_context_result;
    v_rows jsonb;
    v_tot_dr numeric(18,2);
    v_tot_cr numeric(18,2);
BEGIN
    v_auth := public.fn_authenticate_and_authorize(p_agent_token, 'gl.report.read', 'rpc_get_trial_balance');

    SELECT
        COALESCE(jsonb_agg(jsonb_build_object(
            'account_code', a.code,
            'account_name', a.name,
            'account_type', a.account_type,
            'normal_balance', a.normal_balance,
            'total_debit', COALESCE(e.sum_debit, 0),
            'total_credit', COALESCE(e.sum_credit, 0),
            'net_balance', CASE
                WHEN a.normal_balance = 'DEBIT' THEN COALESCE(e.sum_debit, 0) - COALESCE(e.sum_credit, 0)
                ELSE COALESCE(e.sum_credit, 0) - COALESCE(e.sum_debit, 0)
            END
        ) ORDER BY a.code), '[]'::jsonb),
        COALESCE(SUM(e.sum_debit), 0),
        COALESCE(SUM(e.sum_credit), 0)
    INTO v_rows, v_tot_dr, v_tot_cr
    FROM public.gl_accounts a
    LEFT JOIN (
        SELECT account_code, SUM(debit) AS sum_debit, SUM(credit) AS sum_credit
        FROM public.gl_entries
        WHERE posting_date <= p_as_of_date
        GROUP BY account_code
    ) e ON e.account_code = a.code
    WHERE a.is_active = true
      AND (COALESCE(e.sum_debit, 0) > 0 OR COALESCE(e.sum_credit, 0) > 0);

    RETURN jsonb_build_object(
        'as_of_date', p_as_of_date,
        'is_balanced', (v_tot_dr = v_tot_cr),
        'total_debit', v_tot_dr,
        'total_credit', v_tot_cr,
        'accounts', v_rows
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.rpc_health_keepalive(
    p_source text DEFAULT 'scheduled_keepalive'
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_beat_id bigint;
BEGIN
    INSERT INTO public.system_heartbeats (source, details)
    VALUES (COALESCE(p_source, 'scheduled_keepalive'), jsonb_build_object('timestamp', now()))
    RETURNING id INTO v_beat_id;

    RETURN jsonb_build_object(
        'status', 'ALIVE',
        'heartbeat_id', v_beat_id,
        'timestamp', now()
    );
END;
$$;
