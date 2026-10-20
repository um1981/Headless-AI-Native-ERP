-- ============================================================================
-- Migration 0005: Zero-Trust Security Hardening
-- 1. Lock down all RLS SELECT policies to USING (false) so no table can be read
--    directly via PostgREST with only SUPABASE_ANON_KEY.
-- 2. Add PAT-authenticated read RPCs (rpc_list_inventory_balances,
--    rpc_list_audit_logs, rpc_export_ledger_snapshot).
-- ============================================================================

-- 1. Lock down all direct table SELECT policies
ALTER POLICY pol_read_audit_logs ON public.audit_logs USING (false);
ALTER POLICY pol_read_erp_users ON public.erp_users USING (false);
ALTER POLICY pol_read_roles ON public.roles USING (false);
ALTER POLICY pol_read_permissions ON public.permissions USING (false);
ALTER POLICY pol_read_role_permissions ON public.role_permissions USING (false);
ALTER POLICY pol_read_user_roles ON public.user_roles USING (false);
ALTER POLICY pol_read_fiscal_periods ON public.fiscal_periods USING (false);
ALTER POLICY pol_read_gl_accounts ON public.gl_accounts USING (false);
ALTER POLICY pol_read_journal_vouchers ON public.journal_vouchers USING (false);
ALTER POLICY pol_read_journal_lines ON public.journal_lines USING (false);
ALTER POLICY pol_read_gl_entries ON public.gl_entries USING (false);
ALTER POLICY pol_read_warehouses ON public.warehouses USING (false);
ALTER POLICY pol_read_items ON public.items USING (false);
ALTER POLICY pol_read_inventory_balances ON public.inventory_balances USING (false);
ALTER POLICY pol_read_inventory_documents ON public.inventory_documents USING (false);
ALTER POLICY pol_read_inventory_document_lines ON public.inventory_document_lines USING (false);
ALTER POLICY pol_read_inventory_transactions ON public.inventory_transactions USING (false);
ALTER POLICY pol_read_system_heartbeats ON public.system_heartbeats USING (false);

-- 2. PAT-Authenticated Read RPC: Inventory Balances
CREATE OR REPLACE FUNCTION public.rpc_list_inventory_balances(
    p_agent_token text,
    p_warehouse_code text DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_auth public.auth_context_result;
    v_rows jsonb;
BEGIN
    v_auth := public.fn_authenticate_and_authorize(p_agent_token, NULL, 'rpc_list_inventory_balances');

    SELECT COALESCE(jsonb_agg(jsonb_build_object(
        'warehouse_code', b.warehouse_code,
        'sku', i.sku,
        'item_name', i.name,
        'uom', i.uom,
        'qty_on_hand', b.qty_on_hand,
        'avg_unit_cost', b.avg_unit_cost,
        'total_value', b.total_value,
        'updated_at', b.updated_at
    ) ORDER BY b.warehouse_code, i.sku), '[]'::jsonb)
    INTO v_rows
    FROM public.inventory_balances b
    JOIN public.items i ON i.id = b.item_id
    WHERE (p_warehouse_code IS NULL OR b.warehouse_code = btrim(p_warehouse_code));

    RETURN jsonb_build_object(
        'requested_by', v_auth.email,
        'agent_client', v_auth.agent_client,
        'balances', v_rows
    );
END;
$$;

-- 3. PAT-Authenticated Read RPC: Immutable Dual-Identity Audit Logs
CREATE OR REPLACE FUNCTION public.rpc_list_audit_logs(
    p_agent_token text,
    p_limit integer DEFAULT 20
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_auth public.auth_context_result;
    v_rows jsonb;
    v_safe_limit integer;
BEGIN
    v_auth := public.fn_authenticate_and_authorize(p_agent_token, 'audit.read', 'rpc_list_audit_logs');
    v_safe_limit := LEAST(GREATEST(COALESCE(p_limit, 20), 1), 500);

    SELECT COALESCE(jsonb_agg(jsonb_build_object(
        'id', a.id,
        'occurred_at', a.occurred_at,
        'table_name', a.table_name,
        'record_id', a.record_id,
        'operation', a.operation,
        'actor_email', a.actor_email,
        'agent_client', a.agent_client,
        'rpc_name', a.rpc_name
    )), '[]'::jsonb)
    INTO v_rows
    FROM (
        SELECT id, occurred_at, table_name, record_id, operation, actor_email, agent_client, rpc_name
        FROM public.audit_logs
        ORDER BY id DESC
        LIMIT v_safe_limit
    ) a;

    RETURN jsonb_build_object(
        'requested_by', v_auth.email,
        'agent_client', v_auth.agent_client,
        'count', jsonb_array_length(v_rows),
        'logs', v_rows
    );
END;
$$;

-- 4. PAT-Authenticated Ledger Snapshot Export for Daily Backup Script
CREATE OR REPLACE FUNCTION public.rpc_export_ledger_snapshot(
    p_agent_token text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_auth public.auth_context_result;
BEGIN
    v_auth := public.fn_authenticate_and_authorize(p_agent_token, 'audit.read', 'rpc_export_ledger_snapshot');

    RETURN jsonb_build_object(
        'exported_at', now(),
        'exported_by', v_auth.email,
        'agent_client', v_auth.agent_client,
        'gl_accounts', COALESCE((SELECT jsonb_agg(t) FROM public.gl_accounts t), '[]'::jsonb),
        'journal_vouchers', COALESCE((SELECT jsonb_agg(t) FROM public.journal_vouchers t), '[]'::jsonb),
        'gl_entries', COALESCE((SELECT jsonb_agg(t) FROM public.gl_entries t), '[]'::jsonb),
        'items', COALESCE((SELECT jsonb_agg(t) FROM public.items t), '[]'::jsonb),
        'inventory_balances', COALESCE((SELECT jsonb_agg(t) FROM public.inventory_balances t), '[]'::jsonb),
        'inventory_transactions', COALESCE((SELECT jsonb_agg(t) FROM public.inventory_transactions t), '[]'::jsonb)
    );
END;
$$;
