export { AEVUM_TESTNET_CONFIG, type AevumTestnetConfig } from "./constants.js";

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

