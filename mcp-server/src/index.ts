import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { createClient } from "@supabase/supabase-js";
import dotenv from "dotenv";

dotenv.config();

const SUPABASE_URL = process.env.SUPABASE_URL || "";
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || "";
const DEFAULT_AGENT_TOKEN = process.env.ERP_AGENT_TOKEN || "";

if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
  console.error(
    "Missing SUPABASE_URL or SUPABASE_ANON_KEY environment variables."
  );
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: { persistSession: false },
});

function resolveToken(args: Record<string, unknown> | undefined): string {
  const token = (args?.agent_token as string) || DEFAULT_AGENT_TOKEN;
  if (!token) {
    throw new Error(
      "Missing Personal Agent Token (PAT). Set ERP_AGENT_TOKEN in MCP env or pass agent_token."
    );
  }
  return token;
}

const server = new Server(
  {
    name: "headless-ai-native-erp-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "erp_whoami",
        description:
          "Inspect the current authenticated ERP user, AI client token (antigravity/claude-desktop/claude-code/dsh), assigned roles, and effective dynamic permissions.",
        inputSchema: {
          type: "object",
          properties: {
            agent_token: {
              type: "string",
              description: "Optional PAT override (uses ERP_AGENT_TOKEN env by default)",
            },
          },
        },
      },
      {
        name: "erp_issue_agent_token",
        description:
          "Issue a new Personal Agent Token (PAT) for a user and a specific AI client (e.g., antigravity, claude-desktop, claude-code, dsh) with optional scope caps.",
        inputSchema: {
          type: "object",
          required: ["target_email", "client_name"],
          properties: {
            target_email: { type: "string" },
            client_name: {
              type: "string",
              description: "AI client identifier (e.g. antigravity, claude-desktop, claude-code, dsh)",
            },
            allowed_scopes: {
              type: "array",
              items: { type: "string" },
              description: "Optional permission scope cap array (omit or null for full role permissions)",
            },
            expires_in_days: { type: "number", default: 365 },
            agent_token: { type: "string" },
          },
        },
      },
      {
        name: "erp_revoke_agent_token",
        description: "Revoke a specific Personal Agent Token (PAT) by token_id.",
        inputSchema: {
          type: "object",
          required: ["target_token_id"],
          properties: {
            target_token_id: { type: "string" },
            agent_token: { type: "string" },
          },
        },
      },
      {
        name: "erp_assign_user_role",
        description:
          "Create/update an ERP user and assign a dynamic role (requires rbac.manage).",
        inputSchema: {
          type: "object",
          required: ["target_email", "full_name", "role_code"],
          properties: {
            target_email: { type: "string" },
            full_name: { type: "string" },
            department: { type: "string" },
            role_code: { type: "string" },
            agent_token: { type: "string" },
          },
        },
      },
      {
        name: "erp_configure_role_permission",
        description:
          "Dynamically configure a role permission, Maker-Checker separation of duties (require_different_approver), and max_approval_amount in PostgreSQL.",
        inputSchema: {
          type: "object",
          required: ["role_code", "permission_code"],
          properties: {
            role_code: { type: "string" },
            permission_code: { type: "string" },
            require_different_approver: { type: "boolean", default: false },
            max_approval_amount: { type: "number" },
            agent_token: { type: "string" },
          },
        },
      },
      {
        name: "erp_create_journal_draft",
        description:
          "Create a balanced DRAFT General Ledger Journal Voucher (Maker action). Never mutates tables directly; executes rpc_create_journal_draft.",
        inputSchema: {
          type: "object",
          required: ["posting_date", "description", "lines"],
          properties: {
            posting_date: { type: "string", description: "YYYY-MM-DD" },
            description: { type: "string" },
            reference_no: { type: "string" },
            lines: {
              type: "array",
              items: {
                type: "object",
                required: ["account_code", "debit", "credit"],
                properties: {
                  account_code: { type: "string" },
                  debit: { type: "number" },
                  credit: { type: "number" },
                  description: { type: "string" },
                  department: { type: "string" },
                },
              },
            },
            agent_token: { type: "string" },
          },
        },
      },
      {
        name: "erp_post_journal_voucher",
        description:
          "Approve and post a DRAFT Journal Voucher into immutable gl_entries (Checker action). Enforces Maker-Checker, approval limits, and SUM(debit)=SUM(credit).",
        inputSchema: {
          type: "object",
          required: ["voucher_id"],
          properties: {
            voucher_id: { type: "string" },
            agent_token: { type: "string" },
          },
        },
      },
      {
        name: "erp_reverse_journal_voucher",
        description:
          "Reverse a POSTED Journal Voucher by generating and posting an immutable contra-entry voucher.",
        inputSchema: {
          type: "object",
          required: ["voucher_id", "reason"],
          properties: {
            voucher_id: { type: "string" },
            reversal_date: { type: "string", description: "YYYY-MM-DD" },
            reason: { type: "string" },
            agent_token: { type: "string" },
          },
        },
      },
      {
        name: "erp_create_inventory_doc_draft",
        description:
          "Create a DRAFT Inventory Document (RECEIPT, ISSUE, ADJUSTMENT_IN, ADJUSTMENT_OUT) via rpc_create_inventory_doc_draft.",
        inputSchema: {
          type: "object",
          required: [
            "doc_type",
            "warehouse_code",
            "movement_date",
            "offset_account_code",
            "lines",
          ],
          properties: {
            doc_type: {
              type: "string",
              enum: ["RECEIPT", "ISSUE", "ADJUSTMENT_IN", "ADJUSTMENT_OUT"],
            },
            warehouse_code: { type: "string" },
            movement_date: { type: "string", description: "YYYY-MM-DD" },
            offset_account_code: { type: "string" },
            reference_no: { type: "string" },
            notes: { type: "string" },
            lines: {
              type: "array",
              items: {
                type: "object",
                required: ["sku", "qty"],
                properties: {
                  sku: { type: "string" },
                  qty: { type: "number" },
                  unit_cost: { type: "number" },
                  notes: { type: "string" },
                },
              },
            },
            agent_token: { type: "string" },
          },
        },
      },
      {
        name: "erp_post_inventory_doc",
        description:
          "Approve and post a DRAFT Inventory Document into immutable inventory_transactions and auto-post balanced gl_entries.",
        inputSchema: {
          type: "object",
          required: ["doc_id"],
          properties: {
            doc_id: { type: "string" },
            agent_token: { type: "string" },
          },
        },
      },
      {
        name: "erp_get_trial_balance",
        description:
          "Compute real-time Trial Balance from immutable gl_entries as of a given date.",
        inputSchema: {
          type: "object",
          properties: {
            as_of_date: { type: "string", description: "YYYY-MM-DD" },
            agent_token: { type: "string" },
          },
        },
      },
      {
        name: "erp_list_inventory_balances",
        description:
          "Read current on-hand inventory balances and weighted average costs via rpc_list_inventory_balances.",
        inputSchema: {
          type: "object",
          properties: {
            warehouse_code: { type: "string" },
            agent_token: { type: "string" },
          },
        },
      },
      {
        name: "erp_list_audit_logs",
        description:
          "Inspect immutable Dual-Identity Audit Logs showing human actor_email and AI agent_client via rpc_list_audit_logs.",
        inputSchema: {
          type: "object",
          properties: {
            limit: { type: "number", default: 20 },
            agent_token: { type: "string" },
          },
        },
      },
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "erp_whoami": {
        const { data, error } = await supabase.rpc("rpc_whoami", {
          p_agent_token: resolveToken(args),
        });
        if (error) throw error;
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
      }

      case "erp_issue_agent_token": {
        const { data, error } = await supabase.rpc("rpc_issue_agent_token", {
          p_agent_token: resolveToken(args),
          p_target_email: args?.target_email,
          p_client_name: args?.client_name,
          p_allowed_scopes: args?.allowed_scopes ?? null,
          p_expires_in_days: args?.expires_in_days ?? 365,
        });
        if (error) throw error;
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
      }

      case "erp_revoke_agent_token": {
        const { data, error } = await supabase.rpc("rpc_revoke_agent_token", {
          p_agent_token: resolveToken(args),
          p_target_token_id: args?.target_token_id,
        });
        if (error) throw error;
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
      }

      case "erp_assign_user_role": {
        const { data, error } = await supabase.rpc("rpc_assign_user_role", {
          p_agent_token: resolveToken(args),
          p_target_email: args?.target_email,
          p_full_name: args?.full_name,
          p_department: args?.department ?? null,
          p_role_code: args?.role_code,
        });
        if (error) throw error;
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
      }

      case "erp_configure_role_permission": {
        const { data, error } = await supabase.rpc("rpc_configure_role_permission", {
          p_agent_token: resolveToken(args),
          p_role_code: args?.role_code,
          p_permission_code: args?.permission_code,
          p_require_different_approver: args?.require_different_approver ?? false,
          p_max_approval_amount: args?.max_approval_amount ?? null,
        });
        if (error) throw error;
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
      }

      case "erp_create_journal_draft": {
        const { data, error } = await supabase.rpc("rpc_create_journal_draft", {
          p_agent_token: resolveToken(args),
          p_posting_date: args?.posting_date,
          p_description: args?.description,
          p_reference_no: args?.reference_no ?? null,
          p_lines: args?.lines,
        });
        if (error) throw error;
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
      }

      case "erp_post_journal_voucher": {
        const { data, error } = await supabase.rpc("rpc_post_journal_voucher", {
          p_agent_token: resolveToken(args),
          p_voucher_id: args?.voucher_id,
        });
        if (error) throw error;
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
      }

      case "erp_reverse_journal_voucher": {
        const { data, error } = await supabase.rpc("rpc_reverse_journal_voucher", {
          p_agent_token: resolveToken(args),
          p_voucher_id: args?.voucher_id,
          p_reversal_date: args?.reversal_date ?? new Date().toISOString().slice(0, 10),
          p_reason: args?.reason,
        });
        if (error) throw error;
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
      }

      case "erp_create_inventory_doc_draft": {
        const { data, error } = await supabase.rpc("rpc_create_inventory_doc_draft", {
          p_agent_token: resolveToken(args),
          p_doc_type: args?.doc_type,
          p_warehouse_code: args?.warehouse_code,
          p_movement_date: args?.movement_date,
          p_offset_account_code: args?.offset_account_code,
          p_reference_no: args?.reference_no ?? null,
          p_notes: args?.notes ?? null,
          p_lines: args?.lines,
        });
        if (error) throw error;
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
      }

      case "erp_post_inventory_doc": {
        const { data, error } = await supabase.rpc("rpc_post_inventory_doc", {
          p_agent_token: resolveToken(args),
          p_doc_id: args?.doc_id,
        });
        if (error) throw error;
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
      }

      case "erp_get_trial_balance": {
        const { data, error } = await supabase.rpc("rpc_get_trial_balance", {
          p_agent_token: resolveToken(args),
          p_as_of_date: args?.as_of_date ?? new Date().toISOString().slice(0, 10),
        });
        if (error) throw error;
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
      }

      case "erp_list_inventory_balances": {
        const { data, error } = await supabase.rpc("rpc_list_inventory_balances", {
          p_agent_token: resolveToken(args),
          p_warehouse_code: args?.warehouse_code ?? null,
        });
        if (error) throw error;
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
      }

      case "erp_list_audit_logs": {
        const { data, error } = await supabase.rpc("rpc_list_audit_logs", {
          p_agent_token: resolveToken(args),
          p_limit: Number(args?.limit ?? 20),
        });
        if (error) throw error;
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
      }

      default:
        throw new Error(`Unknown ERP tool: ${name}`);
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : JSON.stringify(err);
    return {
      isError: true,
      content: [{ type: "text", text: `ERP_RPC_ERROR: ${message}` }],
    };
  }
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error("Fatal error running Headless AI-Native ERP MCP Server:", err);
  process.exit(1);
});
