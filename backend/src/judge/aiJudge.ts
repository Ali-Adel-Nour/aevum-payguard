import { ethers } from "ethers";
import {
  buildEscrowEip712Domain,
  computeVerdictHash,
  signEscrowVerdict,
  type CanonicalVerdictPayload,
} from "@aevum/agent-pay-sdk";
import type { BackendConfig } from "../config.js";
import {
  buildIsolatedJudgePrompt,
  inspectDeliverableWithFirewall,
  type DetailedPromptFirewallResult,
} from "../security/promptFirewall.js";

export interface JudgeEvaluationInput {
  dealId: string;
  buyer: string;
  seller: string;
  amount: string;
  token: string;
  acceptanceCriteria: string[];
  deliverable: string;
  reasoningURI?: string;
  mode?: "auto" | "deterministic";
}

export interface JudgeEvaluationResult {
  canonicalPayload: CanonicalVerdictPayload;
  verdictHash: string;
  reasoningURI: string;
  firewall: DetailedPromptFirewallResult;
  eip712?: {
    validator: string;
    sigDeadline: number;
    signature: string;
  };
  evaluatedAt: string;
}

interface LlmVerdictJson {
  approved: boolean;
  score: number;
  reasoning: string;
}

const STOP_WORDS = new Set([
  "the",
  "and",
  "for",
  "with",
  "that",
  "this",
  "from",
  "must",
  "will",
  "should",
  "into",
  "have",
  "your",
  "data",
]);

function extractKeywords(criterion: string): string[] {
  return criterion
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, " ")
    .split(/\s+/)
    .filter((word) => word.length >= 3 && !STOP_WORDS.has(word));
}

function evaluateDeterministicRubric(
  criteria: string[],
  sanitizedDeliverable: string
): LlmVerdictJson & { modelId: string } {
  const normalized = sanitizedDeliverable.trim();
  const lower = normalized.toLowerCase();

  if (normalized.length < 15) {
    return {
      approved: false,
      score: 10,
      reasoning:
        "Deliverable is empty or too short (< 15 characters) to satisfy acceptance criteria.",
      modelId: "deterministic-rubric-v1",
    };
  }

  if (/^(?:todo|tbd|placeholder|lorem ipsum|n\/a|broken|incomplete)\b/i.test(lower)) {
    return {
      approved: false,
      score: 15,
      reasoning:
        "Deliverable appears to be an uncompleted stub or placeholder.",
      modelId: "deterministic-rubric-v1",
    };
  }

  const matchedCriteria: string[] = [];
  const missedCriteria: string[] = [];

  for (const criterion of criteria) {
    const keywords = extractKeywords(criterion);
    if (keywords.length === 0) {
      matchedCriteria.push(criterion);
      continue;
    }

    const hits = keywords.filter((kw) => lower.includes(kw));
    const ratio = hits.length / keywords.length;
    if (ratio >= 0.35 || hits.length >= 2) {
      matchedCriteria.push(criterion);
    } else {
      missedCriteria.push(criterion);
    }
  }

  const coverageRatio =
    criteria.length > 0 ? matchedCriteria.length / criteria.length : 1;
  const lengthBonus = normalized.length >= 80 ? 10 : 0;
  const rawScore = Math.round(coverageRatio * 90) + lengthBonus;
  const score = Math.max(0, Math.min(100, rawScore));
  const approved = score >= 70 && missedCriteria.length === 0;

  const reasoning = approved
    ? `PASS: Matched ${matchedCriteria.length}/${criteria.length} acceptance criteria cleanly with no security anomalies.`
    : `FAIL: Satisfied ${matchedCriteria.length}/${criteria.length} criteria. Missing coverage for: ${missedCriteria.join("; ")}.`;

  return {
    approved,
    score,
    reasoning,
    modelId: "deterministic-rubric-v1",
  };
}

async function evaluateWithGemini(
  criteria: string[],
  sanitizedDeliverable: string,
  apiKey: string,
  model: string
): Promise<(LlmVerdictJson & { modelId: string }) | null> {
  if (!/^[a-zA-Z0-9._-]+$/.test(model)) {
    throw new Error("Invalid LLM model identifier");
  }

  const { systemPrompt, userPrompt } = buildIsolatedJudgePrompt(
    criteria,
    sanitizedDeliverable
  );

  // Use allowlisted Gemini API host and pass key via header (never query params)
  const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;

  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-goog-api-key": apiKey,
    },
    body: JSON.stringify({
      systemInstruction: { parts: [{ text: systemPrompt }] },
      contents: [{ role: "user", parts: [{ text: userPrompt }] }],
      generationConfig: {
        temperature: 0,
        responseMimeType: "application/json",
      },
    }),
    signal: AbortSignal.timeout(15_000),
  });

  if (!response.ok) {
    return null;
  }

  const json = (await response.json()) as {
    candidates?: Array<{
      content?: { parts?: Array<{ text?: string }> };
    }>;
  };
  const text = json.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!text) return null;

  const parsed = JSON.parse(text) as Partial<LlmVerdictJson>;
  if (
    typeof parsed.approved !== "boolean" ||
    typeof parsed.score !== "number" ||
    !Number.isFinite(parsed.score) ||
    parsed.score < 0 ||
    parsed.score > 100 ||
    typeof parsed.reasoning !== "string" ||
    parsed.reasoning.trim().length === 0
  ) {
    return null;
  }

  return {
    approved: parsed.approved,
    score: Math.round(parsed.score),
    reasoning: parsed.reasoning.trim().slice(0, 1_000),
    modelId: `gemini:${model}`,
  };
}

/**
 * Runs the Prompt-Injection Firewall followed by the AI Judge, computes the canonical
 * keccak256 verdictHash, and optionally signs an EIP-712 Verdict for AevumEscrowCourt.
 */
export async function evaluateDeliverable(
  input: JudgeEvaluationInput,
  config: BackendConfig
): Promise<JudgeEvaluationResult> {
  const firewall = inspectDeliverableWithFirewall(input.deliverable);
  const deliverableHash = ethers.keccak256(ethers.toUtf8Bytes(input.deliverable));

  let approved: boolean;
  let score: number;
  let reasoning: string;
  let modelId: string;

  if (firewall.promptInjectionDetected) {
    // Fail-closed security quarantine: never forward injection payloads to the LLM
    approved = false;
    score = 0;
    modelId = "aevum-prompt-firewall-v1";
    reasoning = `SECURITY_REJECTION: Prompt-injection attack blocked by Aevum Prompt Firewall (${firewall.matchedPatterns.join(", ")}). Risk score: ${firewall.riskScore}/100. Escrow funds must refund to buyer vault.`;
  } else {
    let llmVerdict: (LlmVerdictJson & { modelId: string }) | null = null;
    if (config.llm.apiKey && input.mode !== "deterministic") {
      try {
        llmVerdict = await evaluateWithGemini(
          input.acceptanceCriteria,
          firewall.sanitizedDeliverable,
          config.llm.apiKey,
          config.llm.model
        );
      } catch {
        llmVerdict = null;
      }
    }

    const finalEval =
      llmVerdict ??
      evaluateDeterministicRubric(
        input.acceptanceCriteria,
        firewall.sanitizedDeliverable
      );

    approved = finalEval.approved;
    score = finalEval.score;
    reasoning = finalEval.reasoning;
    modelId = finalEval.modelId;
  }

  const verdict: "PASS" | "FAIL" = approved ? "PASS" : "FAIL";
  const canonicalPayload: CanonicalVerdictPayload = {
    dealId: input.dealId,
    buyer: ethers.getAddress(input.buyer),
    seller: ethers.getAddress(input.seller),
    amount: input.amount,
    token: ethers.getAddress(input.token),
    acceptanceCriteria: input.acceptanceCriteria,
    deliverableHash,
    firewallSafe: firewall.safe,
    firewallRiskScore: firewall.riskScore,
    approved,
    score,
    verdict,
    reasoning,
    modelId,
  };

  const verdictHash = computeVerdictHash(canonicalPayload);
  const reasoningURI =
    input.reasoningURI?.trim() || `aevum://audit/${input.dealId}/${verdictHash.slice(0, 12)}`;

  let eip712: JudgeEvaluationResult["eip712"];
  if (
    config.validatorPrivateKey &&
    ethers.isAddress(config.contracts.escrowCourt)
  ) {
    const validatorWallet = new ethers.Wallet(config.validatorPrivateKey);
    const domain = buildEscrowEip712Domain(
      config.chainId,
      config.contracts.escrowCourt
    );
    const sigDeadline = Math.floor(Date.now() / 1000) + 900; // 15 min TTL
    const signature = await signEscrowVerdict(validatorWallet, domain, {
      dealId: input.dealId,
      approved,
      score,
      verdictHash,
      reasoningURI,
      sigDeadline,
    });
    eip712 = {
      validator: validatorWallet.address,
      sigDeadline,
      signature,
    };
  }

  return {
    canonicalPayload,
    verdictHash,
    reasoningURI,
    firewall,
    eip712,
    evaluatedAt: new Date().toISOString(),
  };
}

