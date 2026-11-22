import { ethers } from "ethers";

const FORBIDDEN_PROTOTYPE_KEYS = new Set(["__proto__", "constructor", "prototype"]);

/**
 * Deterministically serializes arbitrary JSON-compatible values with sorted ASCII object keys,
 * stripping undefined values and rejecting non-finite numbers or prototype-pollution keys.
 */
export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "bigint") return JSON.stringify(value.toString());

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("Non-finite numbers cannot be canonicalized");
    }
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value
      .map((item) => (item === undefined ? "null" : canonicalize(item)))
      .join(",")}]`;
  }

  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const ownKeys = Object.keys(obj);
    for (const key of ownKeys) {
      if (FORBIDDEN_PROTOTYPE_KEYS.has(key)) {
        throw new Error(`Forbidden prototype pollution key detected: ${key}`);
      }
    }

    const entries = ownKeys
      .filter((key) => obj[key] !== undefined)
      .sort((left, right) => (left < right ? -1 : left > right ? 1 : 0))
      .map((key) => `${JSON.stringify(key)}:${canonicalize(obj[key])}`);

    return `{${entries.join(",")}}`;
  }

  throw new Error(`Unsupported canonicalization type: ${typeof value}`);
}

export function hashCanonicalPayload(value: unknown): string {
  return ethers.keccak256(ethers.toUtf8Bytes(canonicalize(value)));
}

export interface CanonicalVerdictPayload {
  dealId: string;
  buyer: string;
  seller: string;
  amount: string;
  token: string;
  acceptanceCriteria: string[];
  deliverableHash: string;
  firewallSafe: boolean;
  firewallRiskScore: number;
  approved: boolean;
  score: number;
  verdict: "PASS" | "FAIL";
  reasoning: string;
  modelId: string;
}

export function computeVerdictHash(payload: CanonicalVerdictPayload): string {
  return hashCanonicalPayload(payload);
}

export function verifyVerdictAudit(
  payload: CanonicalVerdictPayload,
  expectedVerdictHash: string
): { valid: boolean; computedHash: string; expectedHash: string } {
  const computedHash = computeVerdictHash(payload);
  return {
    valid: computedHash.toLowerCase() === expectedVerdictHash.toLowerCase(),
    computedHash,
    expectedHash: expectedVerdictHash,
  };
}

export const EIP712_VERDICT_TYPES: Record<string, Array<{ name: string; type: string }>> = {
  Verdict: [
    { name: "dealId", type: "bytes32" },
    { name: "approved", type: "bool" },
    { name: "score", type: "uint8" },
    { name: "verdictHash", type: "bytes32" },
    { name: "reasoningURIHash", type: "bytes32" },
    { name: "sigDeadline", type: "uint256" },
  ],
};

export interface EscrowEip712Domain {
  name: string;
  version: string;
  chainId: number;
  verifyingContract: string;
}

export interface SignVerdictParams {
  dealId: string;
  approved: boolean;
  score: number;
  verdictHash: string;
  reasoningURI: string;
  sigDeadline: number | bigint;
}

export function buildEscrowEip712Domain(
  chainId: number,
  verifyingContract: string
): EscrowEip712Domain {
  return {
    name: "AevumEscrowCourt",
    version: "1",
    chainId,
    verifyingContract: ethers.getAddress(verifyingContract),
  };
}

export async function signEscrowVerdict(
  signer: ethers.Signer,
  domain: EscrowEip712Domain,
  params: SignVerdictParams
): Promise<string> {
  const value = {
    dealId: params.dealId,
    approved: params.approved,
    score: params.score,
    verdictHash: params.verdictHash,
    reasoningURIHash: ethers.keccak256(ethers.toUtf8Bytes(params.reasoningURI)),
    sigDeadline: BigInt(params.sigDeadline),
  };

  return signer.signTypedData(domain, EIP712_VERDICT_TYPES, value);
}

export function recoverVerdictSigner(
  domain: EscrowEip712Domain,
  params: SignVerdictParams,
  signature: string
): string {
  const value = {
    dealId: params.dealId,
    approved: params.approved,
    score: params.score,
    verdictHash: params.verdictHash,
    reasoningURIHash: ethers.keccak256(ethers.toUtf8Bytes(params.reasoningURI)),
    sigDeadline: BigInt(params.sigDeadline),
  };

  return ethers.verifyTypedData(domain, EIP712_VERDICT_TYPES, value, signature);
}

