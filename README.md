# Headless AI-Native ERP (Supabase + MCP Server)

> [!IMPORTANT]
> **สถานะโปรเจกต์ (Project Status: Work in Progress / Open for Fork & Adaptation)**
> โปรเจกต์นี้อยู่ระหว่างการพัฒนาอย่างต่อเนื่อง (Active Development) โดยเปิดเป็น **Public / Open-Source** เพื่อให้ผู้ที่สนใจ นักพัฒนา หรือองค์กรต่างๆ สามารถ **Clone / Fork นำไปดัดแปลง ต่อยอด หรือสร้างระบบ ERP บน Supabase ของตัวเองได้อย่างอิสระ**

ระบบ **Headless AI-Native ERP** ที่ออกแบบด้วยสถาปัตยกรรม **Ledger-First**, **Fat Database Pattern (PL/pgSQL RPC)**, **Dynamic Database-Driven RBAC (Maker-Checker)** และ **1 User : Multiple Personal Agent Tokens (PAT)** รองรับการสั่งงานจาก AI Agent หลายตัวพร้อมกัน (Antigravity, Claude Desktop, Claude Code, DSH)

---

## แผนภาพสถาปัตยกรรมระบบ (System Architecture Diagram)

![Headless AI-Native ERP Architecture](./docs/architecture.svg)

*สร้างด้วย [Pikchr](./docs/architecture.pikchr) — สามารถดูโค้ดต้นฉบับได้ที่ [`docs/architecture.pikchr`](./docs/architecture.pikchr)*

---

## กฎสถาปัตยกรรมหลัก 5 ข้อ (Core Architecture Rules)

1. **Zero Direct Table Access/Mutation from Agent:**
   - เปิดใช้งาน Row-Level Security (RLS) ทุกตารางโดยปิดกั้นการอ่านและเขียนตารางตรง (`USING (false)`) ไม่อนุญาตให้ทำคำสั่ง `SELECT`, `INSERT`, `UPDATE`, `DELETE` ผ่าน REST API โดยตรงแม้จะมี Anon Key
2. **Fat Database Pattern (PL/pgSQL RPC):**
   - ทุกธุรกรรมและการดึงข้อมูลทางธุรกิจทำงานผ่านฟังก์ชัน `rpc_*` ใน PostgreSQL ภายใต้ Transaction (ACID) เดียวกันทั้งหมด พร้อมตรวจ `ERP_AGENT_TOKEN` ทุกครั้ง
3. **Ledger-First & Immutability:**
   - ตารางสมุดบัญชีแยกประเภท (`gl_entries`), ตารางเคลื่อนไหวสต็อก (`inventory_transactions`) และตารางประวัติ (`audit_logs`) มี Trigger `fn_block_mutation` ป้องกันการ `UPDATE` และ `DELETE` 100%
   - การแก้ไขต้องทำผ่านการกลับรายการ (`rpc_reverse_journal_voucher`) หรือปรับปรุงยอดเท่านั้น
   - ตรวจสอบสมการบัญชีคู่ `SUM(debit) = SUM(credit)` ทุกครั้งก่อนบันทึกบัญชี
4. **Supabase Free Tier Mitigations:**
   - มีตาราง `audit_logs` ที่บันทึกอัตโนมัติผ่าน Trigger `fn_audit_trigger` ทุกตาราง
   - มีฟังก์ชัน `rpc_health_keepalive`, สคริปต์ `scripts/keepalive_and_backup.ps1` และ GitHub Actions `.github/workflows/supabase-keepalive-backup.yml` รันทุกวันเพื่อป้องกันการหยุดทำงานเมื่อไม่มีการใช้งานครบ 7 วัน
5. **Multi-Agent Authentication, Dynamic RBAC & Dual-Identity Auditability:**
   - **1 User : Multiple Personal Agent Tokens (PAT):** ผู้ใช้ 1 คน (`erp_users`) สามารถออก Token (`user_agent_tokens` เก็บเป็น SHA-256 Hash) แยกตามเครื่องมือ AI ที่ใช้ (`antigravity`, `claude-desktop`, `claude-code`, `dsh`) พร้อมกำหนด Scope จำกัดสิทธิ์รายตัว (`allowed_scopes`) หรือยกเลิกรายตัวได้
   - **Dynamic Database-Driven RBAC & Maker-Checker:** ตั้งค่า `roles`, `permissions`, `role_permissions` (`require_different_approver`, `max_approval_amount`) และ `user_roles` ในฐานข้อมูล ปรับเปลี่ยนได้ทันทีโดยไม่ต้องแก้โค้ด
   - **Dual-Identity Audit Trail:** บันทึกทั้งตัวบุคคล (`actor_user_id` / `actor_email`) และเครื่องมือ AI (`agent_client` / `token_id`) ในทุกเอกสารและ `audit_logs`

---

## วิธีนำโปรเจกต์ไปสร้างบน Supabase ของคุณเอง (Self-Hosting Guide)

### ขั้นตอนที่ 1: สร้างโปรเจกต์ Supabase และรัน SQL Migrations
1. สร้างโปรเจกต์ใหม่บน [Supabase](https://supabase.com)
2. นำไฟล์ SQL ในโฟลเดอร์ [`supabase/migrations/`](./supabase/migrations/) ไปรันตามลำดับ (`0001` ถึง `0005`) ผ่าน **Supabase SQL Editor** หรือใช้ Supabase CLI (`supabase db push`):
   - `202610200001_iam_rbac_and_audit_foundation.sql`
   - `202610200002_gl_inventory_and_sequences_schema.sql`
   - `202610200003_fat_database_rpc_functions.sql`
   - `202610200004_seed_rbac_coa_warehouses_and_initial_users.sql`
   - `202610200005_security_hardening_zero_direct_access.sql`

### ขั้นตอนที่ 2: สร้าง Admin Token ใบแรก (Bootstrap Initial Admin PAT)
เนื่องจากระบบปิดกั้นการเข้าถึงโดยไม่มี Token ให้รันคำสั่ง SQL ด้านล่างนี้ใน **Supabase SQL Editor** เพียงครั้งเดียวเพื่อสร้าง Personal Agent Token (PAT) ใบแรกสำหรับ `admin@erp.local`:

```sql
DO $$
DECLARE
    v_raw_secret text := replace(gen_random_uuid()::text, '-', '') || substr(md5(random()::text || clock_timestamp()::text), 1, 16);
    v_plain_token text := 'erp_pat_admin_' || v_raw_secret;
    v_token_hash text := encode(pg_catalog.sha256(convert_to(v_plain_token, 'UTF8')), 'hex');
BEGIN
    INSERT INTO public.user_agent_tokens (
        user_id, client_name, token_prefix, token_hash, allowed_scopes, is_active, expires_at
    )
    SELECT
        u.id,
        'admin-cli',
        substr(v_plain_token, 1, 20) || '...',
        v_token_hash,
        NULL,
        true,
        now() + interval '365 days'
    FROM public.erp_users u
    WHERE u.email = 'admin@erp.local';

    RAISE NOTICE 'YOUR INITIAL ADMIN TOKEN (Save this securely!): %', v_plain_token;
END;
$$;
```
> คัดลอกค่า `erp_pat_admin_...` ที่แสดงในแท็บ **Messages / Notices** ไปใช้เป็น `ERP_AGENT_TOKEN` ของคุณ จากนั้นคุณสามารถเรียก Tool `erp_issue_agent_token` ผ่าน MCP เพื่อออก Token แยกตามผู้ใช้และ AI Agent ตัวอื่นๆ (`antigravity`, `claude-desktop`, `claude-code`, `dsh`) ได้ทันที

---

### ขั้นตอนที่ 3: ติดตั้งและตั้งค่า ERP MCP Server

```bash
cd mcp-server
cp .env.example .env
# แก้ไขค่า SUPABASE_URL, SUPABASE_ANON_KEY และ ERP_AGENT_TOKEN ในไฟล์ .env
npm install
npm run build
```

#### ตัวอย่างการตั้งค่าใน AI Clients (1 User : N Agent Tokens)

```json
{
  "mcpServers": {
    "headless-erp": {
      "command": "node",
      "args": ["/path/to/Headless-AI-Native-ERP/mcp-server/dist/index.js"],
      "env": {
        "SUPABASE_URL": "https://<your-project-ref>.supabase.co",
        "SUPABASE_ANON_KEY": "sb_publishable_<your_key>",
        "ERP_AGENT_TOKEN": "erp_pat_<client_name>_<your_secret_pat>"
      }
    }
  }
}
```

---

## รายชื่อฟังก์ชัน PL/pgSQL RPC ในระบบ

| หมวดหมู่ | ชื่อฟังก์ชัน RPC | สิทธิ์ที่ต้องใช้ (Permission) | รายละเอียด |
|---|---|---|---|
| **IAM / RBAC** | `rpc_whoami(p_agent_token)` | *(Valid PAT)* | ตรวจสอบข้อมูลผู้ใช้, Agent Client, Role และสิทธิ์ที่คำนวณแล้ว |
| **IAM / RBAC** | `rpc_issue_agent_token(...)` | เจ้าของบัญชี หรือ `rbac.manage` | ออก Personal Agent Token (`erp_pat_<client>_...`) ใหม่ |
| **IAM / RBAC** | `rpc_revoke_agent_token(...)` | เจ้าของบัญชี หรือ `rbac.manage` | ยกเลิกการใช้งาน Token รายตัว |
| **IAM / RBAC** | `rpc_assign_user_role(...)` | `rbac.manage` | เพิ่ม/อัปเดตผู้ใช้และกำหนด Role |
| **IAM / RBAC** | `rpc_configure_role_permission(...)` | `rbac.manage` | ตั้งค่าสิทธิ์ของ Role, เงื่อนไข Maker-Checker และวงเงินอนุมัติ |
| **General Ledger** | `rpc_create_gl_account(...)` | `gl.coa.manage` | เพิ่ม/แก้ไขผังบัญชี (Chart of Accounts) |
| **General Ledger** | `rpc_create_journal_draft(...)` | `gl.voucher.draft` | สร้างใบสำคัญทั่วไปฉบับร่าง (`DRAFT`) (Maker) |
| **General Ledger** | `rpc_post_journal_voucher(...)` | `gl.voucher.post` | อนุมัติและ Post ใบสำคัญลง `gl_entries` (Checker - ตรวจ Maker-Checker) |
| **General Ledger** | `rpc_reverse_journal_voucher(...)` | `gl.voucher.reverse` | กลับรายการใบสำคัญที่ Post แล้วด้วยใบสำคัญกลับรายการ (`JVR-...`) |
| **General Ledger** | `rpc_get_trial_balance(...)` | `gl.report.read` | เรียกดูงบทดลอง (Trial Balance) แบบ Real-time |
| **Inventory** | `rpc_create_item(...)` | `inventory.master.manage` | สร้าง/แก้ไขรหัสสินค้า (SKU) และการผูกบัญชี |
| **Inventory** | `rpc_create_inventory_doc_draft(...)` | `inventory.movement.draft` | สร้างใบรับ/เบิก/ปรับปรุงสต็อกฉบับร่าง (`DRAFT`) (Maker) |
| **Inventory** | `rpc_post_inventory_doc(...)` | `inventory.movement.post` | อนุมัติเอกสารสต็อก ลง `inventory_transactions` และ Post GL อัตโนมัติ |
| **Inventory** | `rpc_list_inventory_balances(...)` | *(Valid PAT)* | ตรวจสอบยอดคงเหลือและต้นทุนเฉลี่ยในคลังสินค้า |
| **Audit & Backup** | `rpc_list_audit_logs(...)` | `audit.read` | ตรวจสอบประวัติ Dual-Identity Audit Logs |
| **Audit & Backup** | `rpc_export_ledger_snapshot(...)` | `audit.read` | ส่งออกข้อมูลสมุดบัญชีและสต็อกสำหรับสำรองข้อมูลรายวัน |
| **System** | `rpc_health_keepalive(...)` | Public / Cron | บันทึก Heartbeat ป้องกัน Supabase Free Tier หยุดทำงาน |
