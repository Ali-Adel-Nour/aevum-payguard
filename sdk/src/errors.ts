import { ethers } from "ethers";
import { AEVUM_TESTNET_CONFIG } from "./constants.js";
import {
  AGENT_VAULT_ABI,
  ESCROW_COURT_ABI,
  IDENTITY_REGISTRY_ABI,
  REPUTATION_REGISTRY_ABI,
  VALIDATION_REGISTRY_ABI,
} from "./abis.js";

export interface DecodedPayGuardError {
  code: string;
  title: string;
  message: string;
  remediation: string;
}

const COMBINED_ERROR_INTERFACE = new ethers.Interface([
  ...AGENT_VAULT_ABI.filter((line) => line.startsWith("error ")),
  ...ESCROW_COURT_ABI.filter((line) => line.startsWith("error ")),
  ...IDENTITY_REGISTRY_ABI.filter((line) => line.startsWith("error ")),
  ...REPUTATION_REGISTRY_ABI.filter((line) => line.startsWith("error ")),
  ...VALIDATION_REGISTRY_ABI.filter((line) => line.startsWith("error ")),
]);

function formatTusd8(raw: bigint): string {
  return `${ethers.formatUnits(raw, AEVUM_TESTNET_CONFIG.stablecoin.decimals)} ${
    AEVUM_TESTNET_CONFIG.stablecoin.symbol
  }`;
}

/**
 * Redacts private keys, bearer tokens, and provider API keys from untrusted error text.
 */
export function redactSensitiveText(input: string): string {
  return input
    .replace(/Bearer\s+[A-Za-z0-9._\-+/=]+/gi, "Bearer [REDACTED]")
    .replace(/AIza[0-9A-Za-z\-_]{20,}/g, "[REDACTED_GOOGLE_KEY]")
    .replace(/sk-[A-Za-z0-9\-_]{20,}/g, "[REDACTED_API_KEY]")
    .replace(
      /(private[_-]?key|api[_-]?key|secret|signingKey)\s*[:=]\s*["']?[^\s"',}]+["']?/gi,
      "$1=[REDACTED]"
    )
    .replace(
      /(?<!(?:tx|hash|dealId|verdictHash|requestId|salt)\s*[:=]?\s*)(0x[a-fA-F0-9]{64})/g,
      "0x[REDACTED_32B_HEX]"
    );
}

function extractRevertData(err: unknown): string | null {
  if (!err || typeof err !== "object") return null;
  const candidate = err as Record<string, unknown>;

  if (typeof candidate.data === "string" && candidate.data.startsWith("0x")) {
    return candidate.data;
  }

  const info = candidate.info as Record<string, unknown> | undefined;
  const nestedError = info?.error as Record<string, unknown> | undefined;
  if (typeof nestedError?.data === "string" && nestedError.data.startsWith("0x")) {
    return nestedError.data;
  }

  const errorField = candidate.error as Record<string, unknown> | undefined;
  if (typeof errorField?.data === "string" && errorField.data.startsWith("0x")) {
    return errorField.data;
  }

  if (typeof candidate.message === "string") {
    const match = candidate.message.match(/data="(0x[a-fA-F0-9]+)"/);
    if (match?.[1]) return match[1];
  }

  return null;
}

/**
 * Translates raw Ethers/contract reverts into clear, plain-language errors
 * suitable for end-users and autonomous agents.
 */
export function decodePayGuardError(err: unknown): DecodedPayGuardError {
  const revertData = extractRevertData(err);

  if (revertData && revertData.length >= 10) {
    try {
      const parsed = COMBINED_ERROR_INTERFACE.parseError(revertData);
      if (parsed) {
        switch (parsed.name) {
          case "VaultIsFrozen":
            return {
              code: "VAULT_FROZEN",
              title: "Emergency Vault Freeze Active",
              message:
                "All autonomous agent spending is currently paused by the vault owner's emergency freeze switch.",
              remediation:
                "Ask the human vault owner to unfreeze the vault once the incident is cleared.",
            };
          case "SessionKeyInactive":
            return {
              code: "SESSION_KEY_INACTIVE",
              title: "Session Key Revoked or Not Configured",
              message:
                "This agent's scoped session key is inactive or has been revoked via the Kill-Switch.",
              remediation:
                "Issue a fresh scoped session key from the Vault Owner dashboard.",
            };
          case "SessionKeyExpired":
            return {
              code: "SESSION_KEY_EXPIRED",
              title: "Session Key Expired",
              message:
                "The expiration timestamp on this agent's session key has passed.",
              remediation:
                "Renew the session key with a new expiry window in AevumAgentVault.",
            };
          case "ExceedsMaxPerTx": {
            const [requested, maxAllowed] = parsed.args as unknown as [bigint, bigint];
            return {
              code: "EXCEEDS_MAX_PER_TX",
              title: "Per-Transaction Spend Limit Exceeded",
              message: `Agent attempted to spend ${formatTusd8(requested)}, exceeding the per-transaction limit of ${formatTusd8(maxAllowed)}.`,
              remediation:
                "Reduce the deal amount below the policy ceiling or update the session policy.",
            };
          }
          case "ExceedsDailySpendCap": {
            const [requested, remaining] = parsed.args as unknown as [bigint, bigint];
            return {
              code: "EXCEEDS_DAILY_CAP",
              title: "Rolling 24-Hour Spend Cap Exceeded",
              message: `Agent requested ${formatTusd8(requested)}, but only ${formatTusd8(remaining)} remains in the current 24-hour allowance.`,
              remediation:
                "Wait for the 24-hour rolling window to reset or increase the daily spend limit.",
            };
          }
          case "CounterpartyReputationTooLow": {
            const [actual, required] = parsed.args as unknown as [bigint, bigint];
            return {
              code: "REPUTATION_TOO_LOW",
              title: "Seller Failed On-Chain ERC-8004 Reputation Gate",
              message: `Seller's ERC-8004 reputation score is ${actual}/100, below the required minimum of ${required}/100.`,
              remediation:
                "Select a higher-rated seller registered in ERC-8004 or lower the policy score threshold.",
            };
          }
          case "DirectPaymentNotAllowed":
            return {
              code: "DIRECT_PAY_BLOCKED",
              title: "Escrow Protection Required",
              message:
                "This session key has restrictToEscrowOnly enabled and cannot send unescrowed direct payments.",
              remediation:
                "Use executeScopedEscrow to protect funds inside AevumEscrowCourt.",
            };
          case "ApprovalRequestExpired":
            return {
              code: "APPROVAL_EXPIRED",
              title: "Queued Approval Expired (24h TTL)",
              message:
                "This pending high-value transaction exceeded the 24-hour human approval window.",
              remediation:
                "Have the agent submit a fresh payment request for review.",
            };
          case "AgentIdentitySoulbound":
            return {
              code: "IDENTITY_SOULBOUND",
              title: "Soulbound Identity Transfer Blocked",
              message:
                "ERC-8004 Agent Identity NFTs are non-transferable to prevent reputation cloning across wallets.",
              remediation:
                "Register a dedicated ERC-8004 identity passport from the target agent wallet.",
            };
          case "UnauthorizedCourt":
            return {
              code: "UNAUTHORIZED_COURT",
              title: "Unauthorized Reputation Writer",
              message:
                "Only an authorized AevumEscrowCourt contract may record address-level escrow reputation.",
              remediation:
                "Authorize the deployed AevumEscrowCourt in AevumReputationRegistry.",
            };
          case "UnauthorizedValidator":
          case "InvalidValidatorSignature":
            return {
              code: "INVALID_VALIDATOR",
              title: "Invalid AI Validator Authorization",
              message:
                "Settlement signature or caller does not match the authorized AI Validator key on AevumEscrowCourt.",
              remediation:
                "Verify AEVUM_VALIDATOR_PRIVATE_KEY matches escrowCourt.aiValidator().",
            };
          case "OracleGracePeriodNotPassed":
            return {
              code: "ORACLE_GRACE_ACTIVE",
              title: "Validator Grace Period Still Active",
              message:
                "The seller submitted work, and the 24-hour AI Judge evaluation window has not elapsed yet.",
              remediation:
                "Wait for the AI Judge verdict or until 24 hours after submission before claiming a refund.",
            };
          case "DeadlineNotPassed":
            return {
              code: "DEADLINE_ACTIVE",
              title: "Escrow Deadline Has Not Passed",
              message:
                "The seller still has time remaining to submit a deliverable before timeout refund unlocks.",
              remediation: "Wait until deal.deadline passes to claim an expired refund.",
            };
          default:
            return {
              code: parsed.name.toUpperCase(),
              title: `Contract Guardrail: ${parsed.name}`,
              message: `Smart contract rejected the action with ${parsed.name}.`,
              remediation: "Check transaction parameters and contract state.",
            };
        }
      }
    } catch {
      // Fall through to generic handling if custom error signature wasn't recognized
    }
  }

  const rawMessage =
    err instanceof Error
      ? err.message
      : typeof err === "string"
        ? err
        : "Unexpected transaction or RPC error";
  const safeMessage = redactSensitiveText(rawMessage);

  if (/insufficient funds|transfer amount exceeds balance/i.test(safeMessage)) {
    return {
      code: "INSUFFICIENT_FUNDS",
      title: "Insufficient tUSD8 or tQDAY Balance",
      message:
        "The vault or wallet does not hold enough tUSD8 tokens (or tQDAY for gas) to complete this transaction.",
      remediation:
        "Deposit additional tUSD8 into AevumAgentVault or fund the wallet with tQDAY.",
    };
  }

  if (/user rejected|action_rejected/i.test(safeMessage)) {
    return {
      code: "USER_REJECTED",
      title: "Transaction Cancelled by User",
      message: "You cancelled the wallet signature request.",
      remediation: "Re-submit when ready to confirm the transaction.",
    };
  }

  return {
    code: "RPC_OR_EXECUTION_ERROR",
    title: "Transaction Execution Error",
    message: safeMessage.slice(0, 260),
    remediation:
      "Verify Aevum Testnet RPC connectivity (https://rpc-test.qday.info) and contract addresses.",
  };
}

