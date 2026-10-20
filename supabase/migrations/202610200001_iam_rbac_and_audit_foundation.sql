-- ============================================================================
-- Migration 0001: IAM, Dynamic RBAC, Dual-Identity PAT & Immutable Audit Logs
-- Project: Headless AI-Native ERP
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ----------------------------------------------------------------------------
-- 1. Immutability Guard Trigger Function (Rule 3 & Rule 4)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fn_block_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'IMMUTABLE_LEDGER_VIOLATION: Table %.% is strictly immutable. UPDATE and DELETE are prohibited. Use reversal or adjustment RPCs.', TG_TABLE_SCHEMA, TG_TABLE_NAME;
END;
$$;

-- ----------------------------------------------------------------------------
-- 2. Audit Logs Table (Rule 4 & Rule 5: Dual-Identity Audit Trail)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.audit_logs (
    id bigserial PRIMARY KEY,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    table_name text NOT NULL,
    record_id text,
    operation text NOT NULL CHECK (operation IN ('INSERT', 'UPDATE', 'DELETE', 'RPC_CALL')),
    actor_user_id uuid,
    actor_email text,
    token_id uuid,
    agent_client text,
    rpc_name text,
    old_data jsonb,
    new_data jsonb,
    txid bigint NOT NULL DEFAULT txid_current()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_occurred_at ON public.audit_logs (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_table_record ON public.audit_logs (table_name, record_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON public.audit_logs (actor_user_id, agent_client);

-- Audit logs themselves are strictly immutable
CREATE OR REPLACE TRIGGER trg_audit_logs_immutable
BEFORE UPDATE OR DELETE ON public.audit_logs
FOR EACH ROW EXECUTE FUNCTION public.fn_block_mutation();

-- Generic Trigger Function to Populate audit_logs with Dual-Identity Context
CREATE OR REPLACE FUNCTION public.fn_audit_trigger()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_record_id text;
    v_actor_user_id uuid;
    v_actor_email text;
    v_token_id uuid;
    v_agent_client text;
    v_rpc_name text;
BEGIN
    v_actor_user_id := NULLIF(current_setting('erp.actor_user_id', true), '')::uuid;
    v_actor_email   := NULLIF(current_setting('erp.actor_email', true), '');
    v_token_id      := NULLIF(current_setting('erp.token_id', true), '')::uuid;
    v_agent_client  := COALESCE(NULLIF(current_setting('erp.agent_client', true), ''), 'system_or_direct');
    v_rpc_name      := NULLIF(current_setting('erp.rpc_name', true), '');

    IF TG_OP = 'DELETE' THEN
        v_record_id := COALESCE(to_jsonb(OLD)->>'id', to_jsonb(OLD)->>'code');
        INSERT INTO public.audit_logs (
            table_name, record_id, operation,
            actor_user_id, actor_email, token_id, agent_client, rpc_name,
            old_data, new_data
        ) VALUES (
            TG_TABLE_NAME, v_record_id, TG_OP,
            v_actor_user_id, v_actor_email, v_token_id, v_agent_client, v_rpc_name,
            to_jsonb(OLD), NULL
        );
        RETURN OLD;
    ELSIF TG_OP = 'UPDATE' THEN
        v_record_id := COALESCE(to_jsonb(NEW)->>'id', to_jsonb(NEW)->>'code');
        INSERT INTO public.audit_logs (
            table_name, record_id, operation,
            actor_user_id, actor_email, token_id, agent_client, rpc_name,
            old_data, new_data
        ) VALUES (
            TG_TABLE_NAME, v_record_id, TG_OP,
            v_actor_user_id, v_actor_email, v_token_id, v_agent_client, v_rpc_name,
            to_jsonb(OLD), to_jsonb(NEW)
        );
        RETURN NEW;
    ELSIF TG_OP = 'INSERT' THEN
        v_record_id := COALESCE(to_jsonb(NEW)->>'id', to_jsonb(NEW)->>'code');
        INSERT INTO public.audit_logs (
            table_name, record_id, operation,
            actor_user_id, actor_email, token_id, agent_client, rpc_name,
            old_data, new_data
        ) VALUES (
            TG_TABLE_NAME, v_record_id, TG_OP,
            v_actor_user_id, v_actor_email, v_token_id, v_agent_client, v_rpc_name,
            NULL, to_jsonb(NEW)
        );
        RETURN NEW;
    END IF;
    RETURN NULL;
END;
$$;

-- ----------------------------------------------------------------------------
-- 3. ERP Users & Multi-Agent Personal Access Tokens (1 User : N Agent Tokens)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.erp_users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    auth_user_id uuid UNIQUE REFERENCES auth.users(id),
    email text UNIQUE NOT NULL,
    full_name text NOT NULL,
    department text,
    is_active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.roles (
    code text PRIMARY KEY,
    name text NOT NULL,
    description text,
    is_system boolean NOT NULL DEFAULT false,
    is_active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.permissions (
    code text PRIMARY KEY,
    module text NOT NULL,
    name text NOT NULL,
    description text,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.role_permissions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    role_code text NOT NULL REFERENCES public.roles(code),
    permission_code text NOT NULL REFERENCES public.permissions(code),
    require_different_approver boolean NOT NULL DEFAULT false,
    max_approval_amount numeric(18,2),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (role_code, permission_code)
);

CREATE TABLE IF NOT EXISTS public.user_roles (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES public.erp_users(id),
    role_code text NOT NULL REFERENCES public.roles(code),
    assigned_at timestamptz NOT NULL DEFAULT now(),
    assigned_by uuid REFERENCES public.erp_users(id),
    UNIQUE (user_id, role_code)
);

-- 1 User : Multiple Personal Agent Tokens (PAT) for Antigravity, Claude Desktop, Claude Code, DSH, etc.
CREATE TABLE IF NOT EXISTS public.user_agent_tokens (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES public.erp_users(id),
    client_name text NOT NULL,
    token_prefix text NOT NULL,
    token_hash text UNIQUE NOT NULL,
    allowed_scopes text[],
    is_active boolean NOT NULL DEFAULT true,
    expires_at timestamptz,
    last_used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);

CREATE INDEX IF NOT EXISTS idx_user_agent_tokens_hash ON public.user_agent_tokens (token_hash) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_user_agent_tokens_user ON public.user_agent_tokens (user_id);

-- Attach Audit Triggers to IAM & RBAC tables
CREATE OR REPLACE TRIGGER trg_audit_erp_users AFTER INSERT OR UPDATE OR DELETE ON public.erp_users FOR EACH ROW EXECUTE FUNCTION public.fn_audit_trigger();
CREATE OR REPLACE TRIGGER trg_audit_roles AFTER INSERT OR UPDATE OR DELETE ON public.roles FOR EACH ROW EXECUTE FUNCTION public.fn_audit_trigger();
CREATE OR REPLACE TRIGGER trg_audit_role_permissions AFTER INSERT OR UPDATE OR DELETE ON public.role_permissions FOR EACH ROW EXECUTE FUNCTION public.fn_audit_trigger();
CREATE OR REPLACE TRIGGER trg_audit_user_roles AFTER INSERT OR UPDATE OR DELETE ON public.user_roles FOR EACH ROW EXECUTE FUNCTION public.fn_audit_trigger();
CREATE OR REPLACE TRIGGER trg_audit_user_agent_tokens AFTER INSERT OR UPDATE OR DELETE ON public.user_agent_tokens FOR EACH ROW EXECUTE FUNCTION public.fn_audit_trigger();

-- ----------------------------------------------------------------------------
-- 4. Core Helper: Authenticate Agent Token & Check Dynamic RBAC Permission
-- ----------------------------------------------------------------------------
CREATE TYPE public.auth_context_result AS (
    user_id uuid,
    email text,
    full_name text,
    token_id uuid,
    agent_client text,
    require_different_approver boolean,
    max_approval_amount numeric(18,2)
);

CREATE OR REPLACE FUNCTION public.fn_authenticate_and_authorize(
    p_agent_token text,
    p_required_permission text,
    p_rpc_name text DEFAULT NULL
)
RETURNS public.auth_context_result
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_token_hash text;
    v_token_row public.user_agent_tokens%ROWTYPE;
    v_user_row public.erp_users%ROWTYPE;
    v_has_perm boolean := false;
    v_req_diff_approver boolean := true;
    v_max_amount numeric(18,2) := NULL;
    v_has_unlimited boolean := false;
    v_result public.auth_context_result;
BEGIN
    IF p_agent_token IS NULL OR btrim(p_agent_token) = '' THEN
        RAISE EXCEPTION 'AUTH_ERROR: Missing Personal Agent Token (PAT).';
    END IF;

    v_token_hash := encode(pg_catalog.sha256(convert_to(btrim(p_agent_token), 'UTF8')), 'hex');

    SELECT * INTO v_token_row
    FROM public.user_agent_tokens
    WHERE token_hash = v_token_hash
      AND is_active = true
      AND (expires_at IS NULL OR expires_at > now());

    IF NOT FOUND THEN
        RAISE EXCEPTION 'AUTH_ERROR: Invalid, expired, or revoked Personal Agent Token.';
    END IF;

    SELECT * INTO v_user_row
    FROM public.erp_users
    WHERE id = v_token_row.user_id
      AND is_active = true;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'AUTH_ERROR: User account associated with this token is inactive or does not exist.';
    END IF;

    -- Set transaction-local Dual-Identity Audit variables (Rule 5)
    PERFORM set_config('erp.actor_user_id', v_user_row.id::text, true);
    PERFORM set_config('erp.actor_email', v_user_row.email, true);
    PERFORM set_config('erp.token_id', v_token_row.id::text, true);
    PERFORM set_config('erp.agent_client', v_token_row.client_name, true);
    IF p_rpc_name IS NOT NULL THEN
        PERFORM set_config('erp.rpc_name', p_rpc_name, true);
    END IF;

    -- Update last_used_at
    UPDATE public.user_agent_tokens
    SET last_used_at = now()
    WHERE id = v_token_row.id
      AND (last_used_at IS NULL OR last_used_at < now() - interval '5 minutes');

    -- Evaluate Dynamic RBAC + Token Scope Cap
    IF p_required_permission IS NOT NULL THEN
        IF v_token_row.allowed_scopes IS NOT NULL AND NOT (p_required_permission = ANY(v_token_row.allowed_scopes) OR '*' = ANY(v_token_row.allowed_scopes)) THEN
            RAISE EXCEPTION 'RBAC_SCOPE_CAP_DENIED: Agent client "%" token does not allow scope "%" (Token Scope Cap).',
                v_token_row.client_name, p_required_permission;
        END IF;

        SELECT
            COUNT(*) > 0,
            COALESCE(bool_and(rp.require_different_approver), true),
            bool_or(rp.max_approval_amount IS NULL),
            max(rp.max_approval_amount)
        INTO
            v_has_perm,
            v_req_diff_approver,
            v_has_unlimited,
            v_max_amount
        FROM public.user_roles ur
        JOIN public.roles r ON r.code = ur.role_code AND r.is_active = true
        JOIN public.role_permissions rp ON rp.role_code = r.code
        WHERE ur.user_id = v_user_row.id
          AND rp.permission_code = p_required_permission;

        IF NOT v_has_perm THEN
            RAISE EXCEPTION 'RBAC_PERMISSION_DENIED: User "%" (via agent "%") lacks required permission "%".',
                v_user_row.email, v_token_row.client_name, p_required_permission;
        END IF;

        IF v_has_unlimited THEN
            v_max_amount := NULL;
        END IF;
    ELSE
        v_req_diff_approver := false;
        v_max_amount := NULL;
    END IF;

    v_result.user_id := v_user_row.id;
    v_result.email := v_user_row.email;
    v_result.full_name := v_user_row.full_name;
    v_result.token_id := v_token_row.id;
    v_result.agent_client := v_token_row.client_name;
    v_result.require_different_approver := v_req_diff_approver;
    v_result.max_approval_amount := v_max_amount;

    RETURN v_result;
END;
$$;
