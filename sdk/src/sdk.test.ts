import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import { ethers } from "ethers";
import {
  AEVUM_TESTNET_CONFIG,
  AGENT_VAULT_ABI,
  AevumMcpHandler,
  buildEscrowEip712Domain,
  canonicalize,
  computeVerdictHash,
  decodePayGuardError,
  recoverVerdictSigner,
  redactSensitiveText,
  signEscrowVerdict,
  verifyVerdictAudit,
  withRetry,
  type CanonicalVerdictPayload,
} from "./index.js";

describe("@aevum/agent-pay-sdk security & protocol primitives", () => {
  const samplePayload: CanonicalVerdictPayload = {
    dealId: ethers.id("sdk-deal-1"),
    buyer: "0x1111111111111111111111111111111111111111",
    seller: "0x2222222222222222222222222222222222222222",
    amount: "25.0",
    token: AEVUM_TESTNET_CONFIG.stablecoin.address,
    acceptanceCriteria: ["Include CSV export", "Pass schema validation"],
    deliverableHash: ethers.id("sample-deliverable"),
    firewallSafe: true,
    firewallRiskScore: 0,
    approved: true,
    score: 96,
    verdict: "PASS",
    reasoning: "All criteria satisfied.",
    modelId: "deterministic-rubric-v1",
  };

  it("produces deterministic canonical JSON regardless of key insertion order", () => {
    const a = canonicalize({ z: 1, a: { c: 3, b: 2 }, u: undefined });
    const b = canonicalize({ a: { b: 2, c: 3 }, z: 1 });
    assert.equal(a, b);
    assert.equal(a, '{"a":{"b":2,"c":3},"z":1}');
  });

  it("rejects prototype pollution keys during canonicalization", () => {
    const malicious = JSON.parse('{"__proto__":{"isAdmin":true},"ok":1}') as unknown;
    assert.throws(() => canonicalize(malicious), /Forbidden prototype pollution key/);
  });

  it("detects audit tampering via verifyVerdictAudit", () => {
    const hash = computeVerdictHash(samplePayload);
    const validResult = verifyVerdictAudit(samplePayload, hash);
    assert.equal(validResult.valid, true);

    const tampered = { ...samplePayload, score: 100, approved: false };
    const tamperedResult = verifyVerdictAudit(tampered, hash);
    assert.equal(tamperedResult.valid, false);
  });

  it("signs and recovers EIP-712 escrow verdicts accurately", async () => {
    const validator = ethers.Wallet.createRandom();
    const contractAddr = "0x3333333333333333333333333333333333333333";
    const domain = buildEscrowEip712Domain(AEVUM_TESTNET_CONFIG.chainId, contractAddr);

    const verdictHash = computeVerdictHash(samplePayload);
    const params = {
      dealId: samplePayload.dealId,
      approved: true,
      score: 96,
      verdictHash,
      reasoningURI: "ipfs://audit-sdk-1",
      sigDeadline: Math.floor(Date.now() / 1000) + 900,
    };

    const sig = await signEscrowVerdict(validator, domain, params);
    const recovered = recoverVerdictSigner(domain, params, sig);
    assert.equal(recovered.toLowerCase(), validator.address.toLowerCase());
  });

  it("decodes Vault custom errors into plain-language errors and redacts secrets", () => {
    const iface = new ethers.Interface(AGENT_VAULT_ABI);
    const revertData = iface.encodeErrorResult("ExceedsDailySpendCap", [
      80_000_000n,
      25_000_000n,
    ]);

    const decoded = decodePayGuardError({ data: revertData });
    assert.equal(decoded.code, "EXCEEDS_DAILY_CAP");
    assert.match(decoded.message, /80(\.0+)? tUSD8/);
    assert.match(decoded.message, /25(\.0+)? tUSD8/);

    const leakedText =
      "Error calling RPC with Bearer secretToken123 and private_key=0xabcdef123456";
    const redacted = redactSensitiveText(leakedText);
    assert.equal(redacted.includes("secretToken123"), false);
    assert.equal(redacted.includes("0xabcdef123456"), false);
  });

  it("fails fast on deterministic reverts and retries transient RPC failures", async () => {
    let deterministicAttempts = 0;
    await assert.rejects(async () => {
      await withRetry(
        async () => {
          deterministicAttempts++;
          const err = new Error("execution reverted: SessionKeyInactive") as Error & {
            code: string;
          };
          err.code = "CALL_EXCEPTION";
          throw err;
        },
        { maxAttempts: 3, baseDelayMs: 5 }
      );
    });
    assert.equal(deterministicAttempts, 1);

    let transientAttempts = 0;
    const ok = await withRetry(
      async () => {
        transientAttempts++;
        if (transientAttempts < 2) {
          throw new Error("ETIMEDOUT connecting to rpc-test.qday.info");
        }
        return "ok";
      },
      { maxAttempts: 3, baseDelayMs: 5 }
    );
    assert.equal(ok, "ok");
    assert.equal(transientAttempts, 2);
  });

  it("serves MCP tools/list and executes read-only MCP tool calls via JSON-RPC", async () => {
    const mcp = new AevumMcpHandler();
    const listResp = await mcp.handleRequest({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/list",
    });

    assert.ok(listResp?.result);
    const tools = (listResp.result as { tools: Array<{ name: string }> }).tools;
    assert.equal(tools.length, 6);

    const netResp = await mcp.handleRequest({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "aevum_get_network_config", arguments: {} },
    });
    const textContent = (
      netResp!.result as { content: Array<{ text: string }> }
    ).content[0].text;
    const parsedConfig = JSON.parse(textContent) as { chainId: number };
    assert.equal(parsedConfig.chainId, 44005);

    const hash = computeVerdictHash(samplePayload);
    const verifyResp = await mcp.handleRequest({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: {
        name: "aevum_verify_verdict_audit",
        arguments: { payload: samplePayload, expectedVerdictHash: hash },
      },
    });
    const verifyText = (
      verifyResp!.result as { content: Array<{ text: string }> }
    ).content[0].text;
    const verifyJson = JSON.parse(verifyText) as { valid: boolean };
    assert.equal(verifyJson.valid, true);
  });
});

