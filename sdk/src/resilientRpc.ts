import { ethers } from "ethers";
import { AEVUM_TESTNET_CONFIG } from "./constants.js";

export interface RetryOptions {
  maxAttempts?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
}

/**
 * Returns true if the error is a deterministic smart contract revert or user rejection
 * that should fail fast without retrying.
 */
export function isDeterministicRevert(err: unknown): boolean {
  if (!err || typeof err !== "object") return false;
  const record = err as Record<string, unknown>;
  const code = typeof record.code === "string" ? record.code : "";
  const message = typeof record.message === "string" ? record.message : "";

  if (
    code === "CALL_EXCEPTION" ||
    code === "ACTION_REJECTED" ||
    code === "INVALID_ARGUMENT" ||
    code === "INSUFFICIENT_FUNDS"
  ) {
    return true;
  }

  return /revert|execution reverted|custom error|user rejected/i.test(message);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Retries transient RPC or network failures with exponential backoff + jitter,
 * while failing immediately on deterministic contract reverts.
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  options: RetryOptions = {}
): Promise<T> {
  const maxAttempts = options.maxAttempts ?? 3;
  const baseDelayMs = options.baseDelayMs ?? 250;
  const maxDelayMs = options.maxDelayMs ?? 3_000;

  let lastError: unknown;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastError = err;
      if (attempt === maxAttempts || isDeterministicRevert(err)) {
        throw err;
      }
      const expDelay = Math.min(maxDelayMs, baseDelayMs * 2 ** (attempt - 1));
      const jitter = Math.floor(Math.random() * Math.max(10, expDelay * 0.25));
      await sleep(expDelay + jitter);
    }
  }

  throw lastError;
}

/**
 * Guards against cross-chain signing mistakes by verifying the connected RPC chain ID.
 */
export async function assertExpectedChainId(
  provider: ethers.Provider,
  expectedChainId: number = AEVUM_TESTNET_CONFIG.chainId
): Promise<number> {
  const network = await withRetry(() => provider.getNetwork());
  const actual = Number(network.chainId);
  if (actual !== expectedChainId) {
    throw new Error(
      `Chain ID mismatch: expected ${expectedChainId} (${AEVUM_TESTNET_CONFIG.networkName}), connected to ${actual}`
    );
  }
  return actual;
}

/**
 * Validates and checksums an EVM address, throwing cleanly on malformed input.
 */
export function assertValidAddress(address: string, label = "address"): string {
  if (!address || !ethers.isAddress(address)) {
    throw new Error(`Invalid EVM ${label}: ${String(address)}`);
  }
  return ethers.getAddress(address);
}

/**
 * Waits for a transaction confirmation with a bounded timeout.
 */
export async function waitForTxReceipt(
  tx: ethers.TransactionResponse,
  confirmations = 1,
  timeoutMs = 90_000
): Promise<ethers.TransactionReceipt> {
  const receipt = await Promise.race([
    tx.wait(confirmations),
    new Promise<null>((_, reject) =>
      setTimeout(
        () => reject(new Error(`Timed out waiting for tx ${tx.hash} confirmation`)),
        timeoutMs
      )
    ),
  ]);

  if (!receipt) {
    throw new Error(`Transaction ${tx.hash} returned an empty receipt`);
  }
  if (receipt.status !== 1) {
    throw new Error(`Transaction ${tx.hash} reverted on-chain`);
  }
  return receipt;
}

