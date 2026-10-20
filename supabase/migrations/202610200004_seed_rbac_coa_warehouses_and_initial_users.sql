-- ============================================================================
-- Migration 0004: Seed Dynamic RBAC, Chart of Accounts, Warehouses & Initial Users
-- Project: Headless AI-Native ERP
-- ============================================================================

INSERT INTO public.permissions (code, module, name, description) VALUES
    ('rbac.manage',               'IAM',       'Manage RBAC & Agent Tokens',      'Create/update users, roles, role permissions, and issue/revoke Personal Agent Tokens'),
    ('gl.coa.manage',             'GL',        'Manage Chart of Accounts',        'Create and update GL accounts'),
    ('gl.voucher.draft',          'GL',        'Create Draft Journal Voucher',    'Create draft journal vouchers (Maker)'),
    ('gl.voucher.post',           'GL',        'Post Journal Voucher',            'Approve and post draft journal vouchers to immutable gl_entries (Checker)'),
    ('gl.voucher.reverse',        'GL',        'Reverse Posted Journal Voucher',  'Create and post reversal vouchers for posted GL vouchers'),
    ('gl.report.read',            'GL',        'Read GL & Trial Balance Reports', 'View GL entries, trial balance, and financial statements'),
    ('inventory.master.manage',   'INVENTORY', 'Manage Inventory Master Data',    'Create and update items and warehouses'),
    ('inventory.movement.draft',  'INVENTORY', 'Create Draft Inventory Movement', 'Create draft inventory receipt, issue, or adjustment documents (Maker)'),
    ('inventory.movement.post',   'INVENTORY', 'Post Inventory Movement',         'Approve and post inventory documents to immutable inventory_transactions & GL (Checker)'),
    ('audit.read',                'AUDIT',     'Read Audit Trail Logs',           'Inspect immutable dual-identity audit logs')
ON CONFLICT (code) DO NOTHING;

INSERT INTO public.roles (code, name, description, is_system, is_active) VALUES
    ('erp_admin',          'ERP System Administrator',   'Full administrative access including RBAC configuration and self-approval capability', true,  true),
    ('accounting_manager', 'Accounting Manager',         'Approves and posts GL vouchers and reversals (enforces Maker-Checker separation of duties)', false, true),
    ('accountant_maker',   'Accountant (Maker)',         'Prepares draft journal vouchers and views financial reports (cannot post to GL)', false, true),
    ('warehouse_manager',  'Warehouse Manager',          'Manages items and approves/posts inventory movements (enforces Maker-Checker)', false, true),
    ('warehouse_staff',    'Warehouse Staff (Maker)',    'Creates draft inventory receipts and issues (cannot post to ledger)', false, true),
    ('auditor',            'Internal / External Auditor','Read-only access to GL reports and immutable audit logs', false, true)
ON CONFLICT (code) DO NOTHING;

INSERT INTO public.role_permissions (role_code, permission_code, require_different_approver, max_approval_amount)
SELECT 'erp_admin', code, false, NULL
FROM public.permissions
ON CONFLICT (role_code, permission_code) DO NOTHING;

INSERT INTO public.role_permissions (role_code, permission_code, require_different_approver, max_approval_amount) VALUES
    ('accounting_manager', 'gl.coa.manage',      false, NULL),
    ('accounting_manager', 'gl.voucher.draft',   false, NULL),
    ('accounting_manager', 'gl.voucher.post',    true,  1000000.00),
    ('accounting_manager', 'gl.voucher.reverse', false, 1000000.00),
    ('accounting_manager', 'gl.report.read',     false, NULL),
    ('accounting_manager', 'audit.read',         false, NULL)
ON CONFLICT (role_code, permission_code) DO NOTHING;

INSERT INTO public.role_permissions (role_code, permission_code, require_different_approver, max_approval_amount) VALUES
    ('accountant_maker', 'gl.voucher.draft', false, NULL),
    ('accountant_maker', 'gl.report.read',   false, NULL)
ON CONFLICT (role_code, permission_code) DO NOTHING;

INSERT INTO public.role_permissions (role_code, permission_code, require_different_approver, max_approval_amount) VALUES
    ('warehouse_manager', 'inventory.master.manage',  false, NULL),
    ('warehouse_manager', 'inventory.movement.draft', false, NULL),
    ('warehouse_manager', 'inventory.movement.post',  true,  500000.00),
    ('warehouse_manager', 'gl.report.read',           false, NULL)
ON CONFLICT (role_code, permission_code) DO NOTHING;

INSERT INTO public.role_permissions (role_code, permission_code, require_different_approver, max_approval_amount) VALUES
    ('warehouse_staff', 'inventory.movement.draft', false, NULL)
ON CONFLICT (role_code, permission_code) DO NOTHING;

INSERT INTO public.role_permissions (role_code, permission_code, require_different_approver, max_approval_amount) VALUES
    ('auditor', 'gl.report.read', false, NULL),
    ('auditor', 'audit.read',     false, NULL)
ON CONFLICT (role_code, permission_code) DO NOTHING;

INSERT INTO public.gl_accounts (code, name, account_type, normal_balance, is_control_account, allow_direct_posting) VALUES
    ('1110', 'เงินสดและเงินฝากธนาคาร (Cash and Bank)',                 'ASSET',     'DEBIT',  false, true),
    ('1200', 'ลูกหนี้การค้า (Accounts Receivable)',                    'ASSET',     'DEBIT',  false, true),
    ('1300', 'สินค้าคงเหลือ (Merchandise Inventory)',                  'ASSET',     'DEBIT',  true,  true),
    ('2100', 'เจ้าหนี้การค้าและบัญชีพักรับสินค้า (AP / GR-IR Clearing)', 'LIABILITY', 'CREDIT', false, true),
    ('3100', 'ทุนเรือนหุ้น (Authorized Share Capital)',                 'EQUITY',    'CREDIT', false, true),
    ('3200', 'กำไรสะสม (Retained Earnings)',                           'EQUITY',    'CREDIT', false, true),
    ('4100', 'รายได้จากการขาย (Sales Revenue)',                        'REVENUE',   'CREDIT', false, true),
    ('5100', 'ต้นทุนขาย (Cost of Goods Sold - COGS)',                  'EXPENSE',   'DEBIT',  false, true),
    ('5200', 'ค่าใช้จ่ายในการบริหารและดำเนินงาน (Operating Expenses)',  'EXPENSE',   'DEBIT',  false, true),
    ('5290', 'ผลต่างจากการปรับปรุงสต็อก (Inventory Adjustment Variance)','EXPENSE',   'DEBIT',  false, true)
ON CONFLICT (code) DO NOTHING;

INSERT INTO public.warehouses (code, name, is_active) VALUES
    ('WH-MAIN', 'คลังสินค้ากลาง (Main Central Warehouse)', true),
    ('WH-BKK',  'คลังกระจายสินค้ากรุงเทพฯ (Bangkok Distribution Center)', true)
ON CONFLICT (code) DO NOTHING;

INSERT INTO public.items (sku, name, uom, standard_cost, inventory_account_code, cogs_account_code) VALUES
    ('SKU-LAPTOP-01', 'AI Developer Workstation Laptop 64GB', 'UNIT', 45000.0000, '1300', '5100'),
    ('SKU-SENSOR-01', 'Industrial Smart IoT Sensor Node',     'PCS',   1250.0000, '1300', '5100')
ON CONFLICT (sku) DO NOTHING;

INSERT INTO public.erp_users (email, full_name, department, is_active) VALUES
    ('admin@erp.local',    'System Administrator',       'IT & Governance', true),
    ('maker@erp.local',    'Somying (Maker Staff)',      'Accounting & WH', true),
    ('approver@erp.local', 'Somchai (Approver Manager)', 'Management',      true)
ON CONFLICT (email) DO NOTHING;

INSERT INTO public.user_roles (user_id, role_code)
SELECT u.id, 'erp_admin' FROM public.erp_users u WHERE u.email = 'admin@erp.local'
ON CONFLICT (user_id, role_code) DO NOTHING;

INSERT INTO public.user_roles (user_id, role_code)
SELECT u.id, r.code FROM public.erp_users u CROSS JOIN public.roles r
WHERE u.email = 'maker@erp.local' AND r.code IN ('accountant_maker', 'warehouse_staff')
ON CONFLICT (user_id, role_code) DO NOTHING;

INSERT INTO public.user_roles (user_id, role_code)
SELECT u.id, r.code FROM public.erp_users u CROSS JOIN public.roles r
WHERE u.email = 'approver@erp.local' AND r.code IN ('accounting_manager', 'warehouse_manager')
ON CONFLICT (user_id, role_code) DO NOTHING;
