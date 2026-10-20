# Project: Headless AI-Native ERP (Supabase + MCP Server)

## Core Architecture Rules (Strict Enforcement)
1. **Zero Direct Table Access/Mutation from Agent:** The end-user ERP MCP Server MUST NEVER perform raw `SELECT`, `INSERT`, `UPDATE`, or `DELETE` directly on ERP tables via PostgREST. All RLS direct policies are locked to `USING (false)`.
2. **Fat Database Pattern (PL/pgSQL RPC):** All business transactions and queries (creating drafts, posting journals, inventory movements, number sequences, reports, audit logs) MUST be encapsulated inside PostgreSQL `SECURITY DEFINER` or `SECURITY INVOKER` functions (`rpc_*`) with strict ACID transaction boundaries.
3. **Ledger-First & Immutability:**
   - Posted records in `gl_entries` and `inventory_transactions` are strictly immutable (block `UPDATE` and `DELETE` via PostgreSQL Triggers).
   - Corrections must be done via reversal or adjustment transactions.
   - Double-entry validation: Every GL voucher must verify `SUM(debit) = SUM(credit)` before commit.
4. **Supabase Free Tier Mitigations:**
   - Maintain an internal `audit_logs` table populated automatically via database triggers (since Free Tier log retention is 1 day).
   - Provide a daily `pg_dump` / snapshot backup & keep-alive script to prevent the 7-day inactivity pause.
5. **Multi-Agent Authentication, Dynamic RBAC & Dual-Identity Auditability:**
   - **1 User : Multiple Personal Agent Tokens (PAT):** Each user has a single identity (`erp_users` / `auth.users`) and can issue multiple Personal Agent Tokens (`user_agent_tokens`, stored as SHA-256 hashes) for different AI clients (e.g., `antigravity`, `claude-desktop`, `claude-code`, `dsh`). Each token can be individually revoked or restricted with optional scope caps (e.g., read-only or draft-only).
   - **Dynamic Database-Driven RBAC & Maker-Checker:** Roles (`roles`), permissions (`permissions`), role assignments (`user_roles`), and policy constraints (`role_permissions` including `require_different_approver` for Maker-Checker separation of duties and `max_approval_amount`) MUST be stored in PostgreSQL tables and evaluated dynamically inside every `rpc_*` function at runtime—never hardcoded.
   - **Dual-Identity Audit Trail:** Every transaction and `audit_logs` record MUST capture both the human owner (`actor_user_id`) and the specific AI client/token (`agent_client` / `token_id`) that executed the action.
