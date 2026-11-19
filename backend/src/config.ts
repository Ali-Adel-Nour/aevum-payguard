import * as dotenv from "dotenv";
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

function parsePort(raw: string | undefined, fallback: number): number {
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

export function loadBackendConfig(): BackendConfig {
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
      process.env.AEVUM_TUSD8_ADDRESS || AEVUM_TESTNET_CONFIG.stablecoin.address,
    validatorPrivateKey: process.env.AEVUM_VALIDATOR_PRIVATE_KEY || "",
    contracts: {
      identityRegistry: process.env.AEVUM_IDENTITY_REGISTRY_ADDRESS || "",
      reputationRegistry: process.env.AEVUM_REPUTATION_REGISTRY_ADDRESS || "",
      validationRegistry: process.env.AEVUM_VALIDATION_REGISTRY_ADDRESS || "",
      agentVault: process.env.AEVUM_AGENT_VAULT_ADDRESS || "",
      escrowCourt: process.env.AEVUM_ESCROW_COURT_ADDRESS || "",
    },
    llm: {
      apiKey: process.env.LLM_API_KEY || "",
      model: process.env.LLM_MODEL || "gemini-2.5-flash",
    },
  };
}

