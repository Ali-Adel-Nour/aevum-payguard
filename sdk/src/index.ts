export { AEVUM_TESTNET_CONFIG, type AevumTestnetConfig } from "./constants.js";
export {
  ERC20_ABI,
  IDENTITY_REGISTRY_ABI,
  REPUTATION_REGISTRY_ABI,
  VALIDATION_REGISTRY_ABI,
  AGENT_VAULT_ABI,
  ESCROW_COURT_ABI,
} from "./abis.js";
export {
  decodePayGuardError,
  redactSensitiveText,
  type DecodedPayGuardError,
} from "./errors.js";
export {
  canonicalize,
  hashCanonicalPayload,
  computeVerdictHash,
  verifyVerdictAudit,
  EIP712_VERDICT_TYPES,
  buildEscrowEip712Domain,
  signEscrowVerdict,
  recoverVerdictSigner,
  type CanonicalVerdictPayload,
  type EscrowEip712Domain,
  type SignVerdictParams,
} from "./canonical.js";
export {
  isDeterministicRevert,
  withRetry,
  assertExpectedChainId,
  assertValidAddress,
  waitForTxReceipt,
  type RetryOptions,
} from "./resilientRpc.js";
export {
  ERC8004Client,
  AevumVaultClient,
  AevumEscrowClient,
  AevumPayGuardSDK,
  type PreflightCheckResult,
  type AevumSDKInitOptions,
} from "./clients.js";
export {
  AevumMcpHandler,
  type JsonRpcRequest,
  type JsonRpcResponse,
} from "./mcp-server.js";

/**
 * Policy parameters governing an agent's scoped session key inside AevumAgentVault.
 */
export interface SessionPolicyConfig {
  sessionKey: string;
  maxAmountPerTx: string;
  dailySpendLimit: string;
  humanApprovalThreshold: string;
  expiresAt: number;
  minCounterpartyScore: number;
  active: boolean;
}

/**
 * Normalized summary of an on-chain tUSD8 escrow deal in AevumEscrowCourt.
 */
export type EscrowDealStatus =
  | "PendingApproval"
  | "Funded"
  | "Submitted"
  | "ResolvedSuccess"
  | "ResolvedRefund"
  | "ExpiredRefund";

export interface EscrowDealSummary {
  dealId: string;
  buyer: string;
  seller: string;
  token: string;
  amount: string;
  deadline: number;
  status: EscrowDealStatus;
  criteriaHash: string;
  deliverableHash?: string;
  verdictHash?: string;
  txHash?: string;
}

/**
 * Aggregated ERC-8004 reputation metrics for a registered AI agent.
 */
export interface AgentReputationSummary {
  agentAddress: string;
  agentId?: string;
  agentURI?: string;
  averageScore: number;
  totalFeedback: number;
  positiveCount: number;
  negativeCount: number;
}

/**
 * Result produced by the backend Prompt-Injection Firewall prior to LLM evaluation.
 */
export interface PromptFirewallResult {
  safe: boolean;
  promptInjectionDetected: boolean;
  riskScore: number;
  matchedPatterns: string[];
  sanitizedDeliverable: string;
}
