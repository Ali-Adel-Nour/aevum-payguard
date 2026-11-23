import * as dotenv from "dotenv";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { AEVUM_TESTNET_CONFIG } from "@aevum/agent-pay-sdk";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.resolve(__dirname, "../../.env") });
dotenv.config();

/**
 * Typed runtime configuration for the Aevum PayGuard backend AI Judge & Prompt Firewall.
 */
export interface BackendConfig {
  port: number;
  rpcUrl: string;
  chainId: number;
  explorerUrl: string;
  tusd8Address: string;
  validatorPrivateKey: string;
  internalApiKey: string;
  corsAllowedOrigins: string[];
  auditStorePath: string;
  contracts: {
    identityRegistry: string;
    reputationRegistry: string;
    validationRegistry: string;
    agentVault: string;
    escrowCourt: string;
  };
  llm: {
    apiKey: string;
    model: string;
  };
}

interface DeploymentManifest {
  tusd8Address?: string;
  contracts?: {
    identityRegistry?: string;
    reputationRegistry?: string;
    validationRegistry?: string;
    agentVault?: string;
    escrowCourt?: string;
  };
}

function parsePort(raw: string | undefined, fallback: number): number {
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function parseAllowedOrigins(raw: string | undefined): string[] {
  if (!raw || !raw.trim()) {
    return ["http://localhost:3000", "http://127.0.0.1:3000"];
  }
  return raw
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);
}

function loadDeploymentFallback(): DeploymentManifest {
  try {
    const manifestPath = path.resolve(__dirname, "../../deployments.json");
    if (!fs.existsSync(manifestPath)) return {};
    return JSON.parse(fs.readFileSync(manifestPath, "utf8")) as DeploymentManifest;
  } catch {
    return {};
  }
}

export function loadBackendConfig(): BackendConfig {
  const manifest = loadDeploymentFallback();
  const manifestContracts = manifest.contracts ?? {};

  return {
    port: parsePort(process.env.PORT, 3001),
    rpcUrl: process.env.AEVUM_RPC_URL || AEVUM_TESTNET_CONFIG.rpcUrl,
    chainId: parsePort(
      process.env.AEVUM_CHAIN_ID,
      AEVUM_TESTNET_CONFIG.chainId
    ),
    explorerUrl:
      process.env.AEVUM_EXPLORER_URL || AEVUM_TESTNET_CONFIG.explorerUrl,
    tusd8Address:
      process.env.AEVUM_TUSD8_ADDRESS ||
      manifest.tusd8Address ||
      AEVUM_TESTNET_CONFIG.stablecoin.address,
    validatorPrivateKey: process.env.AEVUM_VALIDATOR_PRIVATE_KEY || "",
    internalApiKey: process.env.AEVUM_INTERNAL_API_KEY || "",
    corsAllowedOrigins: parseAllowedOrigins(process.env.CORS_ALLOWED_ORIGINS),
    auditStorePath:
      process.env.AUDIT_STORE_PATH ||
      path.resolve(__dirname, "../data/audit-store.json"),
    contracts: {
      identityRegistry:
        process.env.AEVUM_IDENTITY_REGISTRY_ADDRESS ||
        manifestContracts.identityRegistry ||
        "",
      reputationRegistry:
        process.env.AEVUM_REPUTATION_REGISTRY_ADDRESS ||
        manifestContracts.reputationRegistry ||
        "",
      validationRegistry:
        process.env.AEVUM_VALIDATION_REGISTRY_ADDRESS ||
        manifestContracts.validationRegistry ||
        "",
      agentVault:
        process.env.AEVUM_AGENT_VAULT_ADDRESS ||
        manifestContracts.agentVault ||
        "",
      escrowCourt:
        process.env.AEVUM_ESCROW_COURT_ADDRESS ||
        manifestContracts.escrowCourt ||
        "",
    },
    llm: {
      apiKey: process.env.LLM_API_KEY || "",
      model: process.env.LLM_MODEL || "gemini-2.5-flash",
    },
  };
}
