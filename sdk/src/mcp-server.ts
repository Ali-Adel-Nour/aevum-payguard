import * as fs from "node:fs";
import * as path from "node:path";
import * as readline from "node:readline";
import { fileURLToPath } from "node:url";
import { AEVUM_TESTNET_CONFIG } from "./constants.js";
import {
  verifyVerdictAudit,
  type CanonicalVerdictPayload,
} from "./canonical.js";
import { AevumPayGuardSDK } from "./clients.js";
import { decodePayGuardError } from "./errors.js";
import { assertValidAddress } from "./resilientRpc.js";

export interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

export interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: unknown;
  error?: {
    code: number;
    message: string;
  };
}

interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

const MCP_TOOLS: McpToolDefinition[] = [
  {
    name: "aevum_get_network_config",
    description:
      "Returns QDay Aevum Testnet configuration (Chain ID 44005, RPC URL, Explorer, and tUSD8 address).",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: "aevum_check_agent_reputation",
    description:
      "Queries an agent's on-chain ERC-8004 Identity and Reputation score from Aevum Testnet.",
    inputSchema: {
      type: "object",
      properties: {
        agentAddress: {
          type: "string",
          description: "EVM address of the seller or service agent.",
        },
      },
      required: ["agentAddress"],
      additionalProperties: false,
    },
  },
  {
    name: "aevum_check_vault_allowance",
    description:
      "Reads a scoped session key's active status, per-tx limit, expiry, and remaining 24h tUSD8 spend allowance.",
    inputSchema: {
      type: "object",
      properties: {
        sessionKey: {
          type: "string",
          description: "EVM address of the agent's scoped session key.",
        },
      },
      required: ["sessionKey"],
      additionalProperties: false,
    },
  },
  {
    name: "aevum_preflight_payment_check",
    description:
      "Dry-runs all on-chain AevumAgentVault & ERC-8004 guardrails before initiating a tUSD8 escrow payment.",
    inputSchema: {
      type: "object",
      properties: {
        sessionKey: { type: "string" },
        sellerAddress: { type: "string" },
        amountTusd8: { type: "string" },
      },
      required: ["sessionKey", "sellerAddress", "amountTusd8"],
      additionalProperties: false,
    },
  },
  {
    name: "aevum_get_deal_status",
    description:
      "Fetches on-chain state, tUSD8 amount, deadline, and AI Judge verdict hash for an AevumEscrowCourt deal.",
    inputSchema: {
      type: "object",
      properties: {
        dealId: {
          type: "string",
          description: "0x-prefixed 32-byte escrow dealId.",
        },
      },
      required: ["dealId"],
      additionalProperties: false,
    },
  },
  {
    name: "aevum_verify_verdict_audit",
    description:
      "Independently recomputes the canonical keccak256 verdictHash and compares it against the on-chain hash.",
    inputSchema: {
      type: "object",
      properties: {
        payload: { type: "object" },
        expectedVerdictHash: { type: "string" },
      },
      required: ["payload", "expectedVerdictHash"],
      additionalProperties: false,
    },
  },
];

function tryBuildSdkFromEnvironment(): AevumPayGuardSDK | undefined {
  let contracts = {
    identityRegistry: process.env.AEVUM_IDENTITY_REGISTRY_ADDRESS || "",
    reputationRegistry: process.env.AEVUM_REPUTATION_REGISTRY_ADDRESS || "",
    validationRegistry: process.env.AEVUM_VALIDATION_REGISTRY_ADDRESS || "",
    agentVault: process.env.AEVUM_AGENT_VAULT_ADDRESS || "",
    escrowCourt: process.env.AEVUM_ESCROW_COURT_ADDRESS || "",
  };
  let tusd8Address = process.env.AEVUM_TUSD8_ADDRESS;

  if (!contracts.agentVault || !contracts.escrowCourt) {
    try {
      const __dirname = path.dirname(fileURLToPath(import.meta.url));
      const manifestPath = path.resolve(__dirname, "../../deployments.json");
      if (fs.existsSync(manifestPath)) {
        const parsed = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as {
          tusd8Address?: string;
          contracts?: Partial<typeof contracts>;
        };
        if (parsed.contracts) {
          contracts = {
            identityRegistry: parsed.contracts.identityRegistry || "",
            reputationRegistry: parsed.contracts.reputationRegistry || "",
            validationRegistry: parsed.contracts.validationRegistry || "",
            agentVault: parsed.contracts.agentVault || "",
            escrowCourt: parsed.contracts.escrowCourt || "",
          };
        }
        if (!tusd8Address && parsed.tusd8Address) {
          tusd8Address = parsed.tusd8Address;
        }
      }
    } catch {
      return undefined;
    }
  }

  if (
    !contracts.identityRegistry ||
    !contracts.reputationRegistry ||
    !contracts.agentVault ||
    !contracts.escrowCourt
  ) {
    return undefined;
  }

  return new AevumPayGuardSDK({
    rpcUrl: process.env.AEVUM_RPC_URL,
    chainId: process.env.AEVUM_CHAIN_ID
      ? Number.parseInt(process.env.AEVUM_CHAIN_ID, 10)
      : undefined,
    explorerUrl: process.env.AEVUM_EXPLORER_URL,
    tusd8Address,
    contracts,
  });
}

export class AevumMcpHandler {
  private readonly sdk?: AevumPayGuardSDK;

  constructor(options?: { sdk?: AevumPayGuardSDK }) {
    this.sdk = options?.sdk ?? tryBuildSdkFromEnvironment();
  }

  private requireSdk(): AevumPayGuardSDK {
    if (!this.sdk) {
      throw new Error(
        "Aevum PayGuard contract addresses are not configured. Set AEVUM_*_ADDRESS env vars or deploy contracts first."
      );
    }
    return this.sdk;
  }

  async handleRequest(raw: unknown): Promise<JsonRpcResponse | null> {
    if (!raw || typeof raw !== "object") {
      return {
        jsonrpc: "2.0",
        id: null,
        error: { code: -32600, message: "Invalid JSON-RPC request object" },
      };
    }

    const req = raw as JsonRpcRequest;
    const id = req.id !== undefined ? req.id : null;

    if (req.jsonrpc !== "2.0" || typeof req.method !== "string") {
      return {
        jsonrpc: "2.0",
        id,
        error: { code: -32600, message: "Malformed JSON-RPC 2.0 envelope" },
      };
    }

    if (req.method === "notifications/initialized") {
      return null;
    }

    if (req.method === "initialize") {
      return {
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: {
            name: "aevum-payguard-mcp",
            version: "1.0.0",
          },
        },
      };
    }

    if (req.method === "ping") {
      return { jsonrpc: "2.0", id, result: {} };
    }

    if (req.method === "tools/list") {
      return {
        jsonrpc: "2.0",
        id,
        result: { tools: MCP_TOOLS },
      };
    }

    if (req.method === "tools/call") {
      const params = req.params ?? {};
      const toolName = params.name;
      const args = (params.arguments ?? {}) as Record<string, unknown>;

      if (typeof toolName !== "string") {
        return {
          jsonrpc: "2.0",
          id,
          error: { code: -32602, message: "Missing tool name" },
        };
      }

      try {
        const output = await this.executeTool(toolName, args);
        return {
          jsonrpc: "2.0",
          id,
          result: {
            content: [
              {
                type: "text",
                text: JSON.stringify(output, null, 2),
              },
            ],
          },
        };
      } catch (err) {
        const decoded = decodePayGuardError(err);
        return {
          jsonrpc: "2.0",
          id,
          result: {
            isError: true,
            content: [
              {
                type: "text",
                text: JSON.stringify(decoded, null, 2),
              },
            ],
          },
        };
      }
    }

    return {
      jsonrpc: "2.0",
      id,
      error: { code: -32601, message: `Method not found: ${req.method}` },
    };
  }

  private async executeTool(
    toolName: string,
    args: Record<string, unknown>
  ): Promise<unknown> {
    switch (toolName) {
      case "aevum_get_network_config":
        return {
          ...AEVUM_TESTNET_CONFIG,
          contractsConfigured: Boolean(this.sdk),
        };

      case "aevum_check_agent_reputation": {
        const sdk = this.requireSdk();
        const addr = assertValidAddress(
          String(args.agentAddress ?? ""),
          "agentAddress"
        );
        return sdk.erc8004.getAgentProfile(addr);
      }

      case "aevum_check_vault_allowance": {
        const sdk = this.requireSdk();
        const key = assertValidAddress(
          String(args.sessionKey ?? ""),
          "sessionKey"
        );
        return sdk.vault.getSessionPolicy(key);
      }

      case "aevum_preflight_payment_check": {
        const sdk = this.requireSdk();
        return sdk.vault.preflightCheck({
          sessionKey: assertValidAddress(
            String(args.sessionKey ?? ""),
            "sessionKey"
          ),
          sellerAddress: assertValidAddress(
            String(args.sellerAddress ?? ""),
            "sellerAddress"
          ),
          amountTusd8: String(args.amountTusd8 ?? ""),
        });
      }

      case "aevum_get_deal_status": {
        const sdk = this.requireSdk();
        const dealId = String(args.dealId ?? "");
        return sdk.escrow.getDeal(dealId);
      }

      case "aevum_verify_verdict_audit": {
        const payload = args.payload as CanonicalVerdictPayload | undefined;
        const expectedVerdictHash = String(args.expectedVerdictHash ?? "");
        if (!payload || typeof payload !== "object") {
          throw new Error("payload must be a canonical verdict object");
        }
        if (!/^0x[0-9a-fA-F]{64}$/.test(expectedVerdictHash)) {
          throw new Error("expectedVerdictHash must be a 32-byte 0x hex string");
        }
        return verifyVerdictAudit(payload, expectedVerdictHash);
      }

      default:
        throw new Error(`Unknown MCP tool: ${toolName}`);
    }
  }
}

export function startStdioMcpServer(): void {
  const handler = new AevumMcpHandler();
  const rl = readline.createInterface({
    input: process.stdin,
    crlfDelay: Infinity,
  });

  rl.on("line", async (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    try {
      const parsed = JSON.parse(trimmed) as unknown;
      const response = await handler.handleRequest(parsed);
      if (response) {
        process.stdout.write(`${JSON.stringify(response)}\n`);
      }
    } catch {
      const errResp: JsonRpcResponse = {
        jsonrpc: "2.0",
        id: null,
        error: { code: -32700, message: "Parse error" },
      };
      process.stdout.write(`${JSON.stringify(errResp)}\n`);
    }
  });
}

const currentFile = fileURLToPath(import.meta.url);
if (
  process.argv[1] &&
  path.resolve(process.argv[1]).toLowerCase() === currentFile.toLowerCase()
) {
  startStdioMcpServer();
}

