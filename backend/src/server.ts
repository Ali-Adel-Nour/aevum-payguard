import * as http from "node:http";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";
import {
  AevumPayGuardSDK,
  assertExpectedChainId,
  decodePayGuardError,
  redactSensitiveText,
} from "@aevum/agent-pay-sdk";
import { loadBackendConfig, type BackendConfig } from "./config.js";
import { evaluateDeliverable } from "./judge/aiJudge.js";
import {
  applySecurityHeaders,
  HttpPayloadError,
  isValidAddress,
  isValidBytes32,
  RateLimiter,
  readSafeJsonBody,
  sanitizeStringArray,
  verifyInternalApiKey,
} from "./security/httpSecurity.js";
import { inspectDeliverableWithFirewall } from "./security/promptFirewall.js";
import { AuditStore } from "./store/auditStore.js";

function buildSdkIfConfigured(config: BackendConfig): AevumPayGuardSDK | undefined {
  const {
    identityRegistry,
    reputationRegistry,
    validationRegistry,
    agentVault,
    escrowCourt,
  } = config.contracts;

  if (
    !ethers.isAddress(identityRegistry) ||
    !ethers.isAddress(reputationRegistry) ||
    !ethers.isAddress(agentVault) ||
    !ethers.isAddress(escrowCourt)
  ) {
    return undefined;
  }

  return new AevumPayGuardSDK({
    rpcUrl: config.rpcUrl,
    chainId: config.chainId,
    explorerUrl: config.explorerUrl,
    tusd8Address: config.tusd8Address,
    contracts: {
      identityRegistry,
      reputationRegistry,
      validationRegistry: ethers.isAddress(validationRegistry)
        ? validationRegistry
        : undefined,
      agentVault,
      escrowCourt,
    },
  });
}

function sendJson(
  res: http.ServerResponse,
  statusCode: number,
  payload: unknown
): void {
  res.statusCode = statusCode;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(payload));
}

export interface CreateServerOptions {
  auditStore?: AuditStore;
  rateLimiter?: RateLimiter;
  sdk?: AevumPayGuardSDK;
}

export function createPayGuardServer(
  config: BackendConfig,
  options: CreateServerOptions = {}
): {
  server: http.Server;
  auditStore: AuditStore;
  rateLimiter: RateLimiter;
  sdk: AevumPayGuardSDK | undefined;
} {
  const auditStore = options.auditStore ?? new AuditStore(config.auditStorePath);
  const rateLimiter =
    options.rateLimiter ?? new RateLimiter({ windowMs: 60_000, maxRequests: 120 });
  const sdk = options.sdk ?? buildSdkIfConfigured(config);

  const server = http.createServer(async (req, res) => {
    const originHeader =
      typeof req.headers.origin === "string" ? req.headers.origin : undefined;
    const originAllowed = applySecurityHeaders(
      res,
      originHeader,
      config.corsAllowedOrigins
    );

    if (req.method === "OPTIONS") {
      if (!originAllowed) {
        sendJson(res, 403, { error: "CORS origin not allowed" });
        return;
      }
      res.statusCode = 204;
      res.end();
      return;
    }

    const clientIp = req.socket.remoteAddress || "127.0.0.1";
    const rate = rateLimiter.check(clientIp);
    res.setHeader("X-RateLimit-Remaining", String(rate.remaining));
    if (!rate.allowed) {
      res.setHeader("Retry-After", String(rate.retryAfterSec));
      sendJson(res, 429, {
        error: "Rate limit exceeded. Please retry shortly.",
        retryAfterSec: rate.retryAfterSec,
      });
      return;
    }

    try {
      const parsedUrl = new URL(req.url ?? "/", "http://localhost");
      const pathname = parsedUrl.pathname;
      const method = req.method ?? "GET";

      if (method === "GET" && pathname === "/api/health") {
        sendJson(res, 200, {
          ok: true,
          service: "aevum-payguard-backend",
          chainId: config.chainId,
          rpcUrl: config.rpcUrl,
          explorerUrl: config.explorerUrl,
          tusd8Address: config.tusd8Address,
          contractsConfigured: Boolean(sdk),
          validatorConfigured: Boolean(config.validatorPrivateKey),
          llmEnabled: Boolean(config.llm.apiKey),
          internalAuthRequired: Boolean(config.internalApiKey),
        });
        return;
      }

      if (method === "POST" && pathname === "/api/firewall/scan") {
        const body = await readSafeJsonBody(req);
        if (typeof body.deliverable !== "string") {
          throw new HttpPayloadError(400, "Field 'deliverable' must be a string");
        }
        const scan = inspectDeliverableWithFirewall(body.deliverable);
        sendJson(res, 200, scan);
        return;
      }

      if (
        method === "POST" &&
        (pathname === "/api/judge" || pathname === "/api/judge-and-settle")
      ) {
        if (pathname === "/api/judge-and-settle" && config.internalApiKey) {
          const providedKey =
            typeof req.headers["x-aevum-internal-key"] === "string"
              ? req.headers["x-aevum-internal-key"]
              : undefined;
          if (!verifyInternalApiKey(providedKey, config.internalApiKey)) {
            sendJson(res, 401, {
              error: "Unauthorized: invalid or missing X-Aevum-Internal-Key",
            });
            return;
          }
        }

        const body = await readSafeJsonBody(req);

        if (!isValidBytes32(body.dealId)) {
          throw new HttpPayloadError(400, "Invalid 'dealId' (expected 32-byte 0x hex)");
        }
        if (!isValidAddress(body.buyer)) {
          throw new HttpPayloadError(400, "Invalid 'buyer' EVM address");
        }
        if (!isValidAddress(body.seller)) {
          throw new HttpPayloadError(400, "Invalid 'seller' EVM address");
        }
        const tokenAddress =
          body.token !== undefined ? body.token : config.tusd8Address;
        if (!isValidAddress(tokenAddress)) {
          throw new HttpPayloadError(400, "Invalid 'token' EVM address");
        }
        if (
          typeof body.amount !== "string" ||
          !/^\d+(?:\.\d+)?$/.test(body.amount.trim())
        ) {
          throw new HttpPayloadError(400, "Invalid 'amount' numeric string");
        }
        const criteria = sanitizeStringArray(body.acceptanceCriteria);
        if (!criteria) {
          throw new HttpPayloadError(
            400,
            "'acceptanceCriteria' must be a non-empty array of strings"
          );
        }
        if (typeof body.deliverable !== "string" || !body.deliverable.trim()) {
          throw new HttpPayloadError(400, "'deliverable' must be a non-empty string");
        }

        const mode =
          body.mode === "deterministic" || body.mode === "auto"
            ? body.mode
            : "auto";
        const reasoningURI =
          typeof body.reasoningURI === "string" ? body.reasoningURI : undefined;

        const evaluation = await evaluateDeliverable(
          {
            dealId: body.dealId,
            buyer: body.buyer,
            seller: body.seller,
            token: tokenAddress,
            amount: body.amount.trim(),
            acceptanceCriteria: criteria,
            deliverable: body.deliverable,
            reasoningURI,
            mode,
          },
          config
        );

        auditStore.saveRecord({
          dealId: body.dealId,
          canonicalPayload: evaluation.canonicalPayload,
          verdictHash: evaluation.verdictHash,
          reasoningURI: evaluation.reasoningURI,
          firewall: evaluation.firewall,
          eip712: evaluation.eip712,
          evaluatedAt: evaluation.evaluatedAt,
        });

        if (pathname === "/api/judge") {
          sendJson(res, 200, evaluation);
          return;
        }

        // /api/judge-and-settle requires deployed contracts and validator private key
        if (!sdk) {
          sendJson(res, 503, {
            error: "Contracts are not configured on backend",
            evaluation,
          });
          return;
        }
        if (!config.validatorPrivateKey) {
          sendJson(res, 503, {
            error: "AEVUM_VALIDATOR_PRIVATE_KEY is not configured for on-chain settlement",
            evaluation,
          });
          return;
        }

        await assertExpectedChainId(sdk.provider, config.chainId);
        const validatorSigner = new ethers.Wallet(
          config.validatorPrivateKey,
          sdk.provider
        );
        const settlement = await sdk.escrow.resolveEscrow(validatorSigner, {
          dealId: body.dealId,
          approved: evaluation.canonicalPayload.approved,
          score: evaluation.canonicalPayload.score,
          verdictHash: evaluation.verdictHash,
          reasoningURI: evaluation.reasoningURI,
        });

        auditStore.markSettled(body.dealId, settlement.txHash);

        sendJson(res, 200, {
          evaluation,
          settlement: {
            transactionHash: settlement.txHash,
            explorerUrl: sdk.getTxExplorerUrl(settlement.txHash),
          },
        });
        return;
      }

      if (method === "GET" && pathname === "/api/audits") {
        sendJson(res, 200, { audits: auditStore.listRecords() });
        return;
      }

      if (method === "GET" && pathname.startsWith("/api/audits/")) {
        const dealId = pathname.slice("/api/audits/".length);
        if (!isValidBytes32(dealId)) {
          throw new HttpPayloadError(400, "Invalid 'dealId' path parameter");
        }
        const record = auditStore.getRecord(dealId);
        if (!record) {
          sendJson(res, 404, { error: "Audit record not found" });
          return;
        }
        sendJson(res, 200, record);
        return;
      }

      if (method === "GET" && pathname.startsWith("/api/verify/")) {
        const dealId = pathname.slice("/api/verify/".length);
        if (!isValidBytes32(dealId)) {
          throw new HttpPayloadError(400, "Invalid 'dealId' path parameter");
        }
        const verification = auditStore.verifyRecord(dealId);
        if (!verification.found) {
          sendJson(res, 404, { error: "Audit record not found" });
          return;
        }
        sendJson(res, 200, {
          dealId,
          valid: verification.valid,
          computedHash: verification.computedHash,
          expectedHash: verification.expectedHash,
          record: verification.record,
        });
        return;
      }

      if (method === "GET" && pathname.startsWith("/api/reputation/")) {
        const agentAddress = pathname.slice("/api/reputation/".length);
        if (!isValidAddress(agentAddress)) {
          throw new HttpPayloadError(400, "Invalid agent EVM address");
        }
        if (!sdk) {
          sendJson(res, 503, { error: "Contract addresses not configured" });
          return;
        }
        const profile = await sdk.erc8004.getAgentProfile(agentAddress);
        sendJson(res, 200, profile);
        return;
      }

      if (method === "GET" && pathname.startsWith("/api/vault/")) {
        const sessionKey = pathname.slice("/api/vault/".length);
        if (!isValidAddress(sessionKey)) {
          throw new HttpPayloadError(400, "Invalid sessionKey EVM address");
        }
        if (!sdk) {
          sendJson(res, 503, { error: "Contract addresses not configured" });
          return;
        }
        const policy = await sdk.vault.getSessionPolicy(sessionKey);
        sendJson(res, 200, policy);
        return;
      }

      if (method === "POST" && pathname === "/api/decode-error") {
        const body = await readSafeJsonBody(req);
        const decoded = decodePayGuardError(body.error ?? body);
        sendJson(res, 200, decoded);
        return;
      }

      sendJson(res, 404, { error: `Route not found: ${method} ${pathname}` });
    } catch (err) {
      if (err instanceof HttpPayloadError) {
        sendJson(res, err.statusCode, { error: err.message });
        return;
      }
      const decoded = decodePayGuardError(err);
      sendJson(res, 500, {
        error: redactSensitiveText(decoded.message),
        code: decoded.code,
        title: decoded.title,
        remediation: decoded.remediation,
      });
    }
  });

  return { server, auditStore, rateLimiter, sdk };
}

const currentFile = fileURLToPath(import.meta.url);
if (
  process.argv[1] &&
  path.resolve(process.argv[1]).toLowerCase() === currentFile.toLowerCase()
) {
  const config = loadBackendConfig();
  const { server } = createPayGuardServer(config);
  server.listen(config.port, () => {
    console.log(
      `🛡️  Aevum PayGuard Backend listening on http://localhost:${config.port} (Chain ID: ${config.chainId})`
    );
  });
}

