import * as crypto from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { ethers } from "ethers";

export class HttpPayloadError extends Error {
  public readonly statusCode: number;

  constructor(statusCode: number, message: string) {
    super(message);
    this.statusCode = statusCode;
  }
}

const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function assertNoPrototypePollution(node: unknown, depth = 0): void {
  if (depth > 32 || node === null || typeof node !== "object") return;

  if (Array.isArray(node)) {
    for (const item of node) {
      assertNoPrototypePollution(item, depth + 1);
    }
    return;
  }

  const obj = node as Record<string, unknown>;
  for (const key of Object.getOwnPropertyNames(obj)) {
    if (FORBIDDEN_KEYS.has(key)) {
      throw new HttpPayloadError(
        400,
        `Rejected forbidden prototype-pollution key: ${key}`
      );
    }
    assertNoPrototypePollution(obj[key], depth + 1);
  }
}

/**
 * Applies defensive HTTP security headers and strict CORS allowlisting.
 * Never reflects untrusted Origin headers.
 */
export function applySecurityHeaders(
  res: ServerResponse,
  originHeader: string | undefined,
  allowedOrigins: string[]
): boolean {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Content-Security-Policy", "default-src 'none'");
  res.setHeader("Cross-Origin-Resource-Policy", "same-site");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Vary", "Origin");

  if (!originHeader) {
    return true;
  }

  const originAllowed =
    allowedOrigins.includes("*") || allowedOrigins.includes(originHeader);
  if (originAllowed) {
    res.setHeader("Access-Control-Allow-Origin", originHeader);
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Content-Type, X-Aevum-Internal-Key"
    );
  }
  return originAllowed;
}

/**
 * Sliding-window per-IP rate limiter protecting LLM & RPC endpoints from abuse.
 */
export class RateLimiter {
  private readonly windowMs: number;
  private readonly maxRequests: number;
  private readonly hits = new Map<string, number[]>();

  constructor(options?: { windowMs?: number; maxRequests?: number }) {
    this.windowMs = options?.windowMs ?? 60_000;
    this.maxRequests = options?.maxRequests ?? 120;
  }

  check(ip: string): {
    allowed: boolean;
    remaining: number;
    retryAfterSec: number;
  } {
    const now = Date.now();
    const cutoff = now - this.windowMs;
    const recent = (this.hits.get(ip) ?? []).filter((ts) => ts > cutoff);

    if (recent.length >= this.maxRequests) {
      this.hits.set(ip, recent);
      const oldest = recent[0] ?? now;
      const retryAfterSec = Math.max(
        1,
        Math.ceil((oldest + this.windowMs - now) / 1000)
      );
      return { allowed: false, remaining: 0, retryAfterSec };
    }

    recent.push(now);
    this.hits.set(ip, recent);

    // Opportunistic cleanup when tracking map grows
    if (this.hits.size > 1_000) {
      for (const [key, timestamps] of this.hits.entries()) {
        if (timestamps.every((ts) => ts <= cutoff)) {
          this.hits.delete(key);
        }
      }
    }

    return {
      allowed: true,
      remaining: Math.max(0, this.maxRequests - recent.length),
      retryAfterSec: 0,
    };
  }
}

/**
 * Reads an HTTP JSON request body safely with a hard byte cap and prototype-pollution guard.
 */
export async function readSafeJsonBody(
  req: IncomingMessage,
  maxBytes = 65_536
): Promise<Record<string, unknown>> {
  const rawLength = req.headers["content-length"];
  if (rawLength) {
    const declared = Number.parseInt(
      Array.isArray(rawLength) ? rawLength[0] : rawLength,
      10
    );
    if (Number.isFinite(declared) && declared > maxBytes) {
      throw new HttpPayloadError(
        413,
        `Request payload exceeds maximum limit of ${maxBytes} bytes`
      );
    }
  }

  const chunks: Buffer[] = [];
  let received = 0;

  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    received += buf.length;
    if (received > maxBytes) {
      req.destroy();
      throw new HttpPayloadError(
        413,
        `Request payload exceeds maximum limit of ${maxBytes} bytes`
      );
    }
    chunks.push(buf);
  }

  const rawText = Buffer.concat(chunks).toString("utf8").trim();
  if (!rawText) {
    return {};
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch {
    throw new HttpPayloadError(400, "Malformed JSON request body");
  }

  assertNoPrototypePollution(parsed);

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new HttpPayloadError(400, "Request body must be a JSON object");
  }

  return parsed as Record<string, unknown>;
}

/**
 * Compares internal API keys in constant time over fixed-length SHA-256 digests,
 * preventing both character timing leaks and key-length side channels.
 */
export function verifyInternalApiKey(
  providedKey: string | undefined,
  expectedKey: string
): boolean {
  if (!expectedKey) return true;
  if (!providedKey) return false;

  const a = crypto.createHash("sha256").update(providedKey, "utf8").digest();
  const b = crypto.createHash("sha256").update(expectedKey, "utf8").digest();
  return crypto.timingSafeEqual(a, b);
}

export function isValidBytes32(value: unknown): value is string {
  return typeof value === "string" && /^0x[0-9a-fA-F]{64}$/.test(value);
}

export function isValidAddress(value: unknown): value is string {
  return typeof value === "string" && ethers.isAddress(value);
}

export function sanitizeStringArray(
  value: unknown,
  maxItems = 25
): string[] | null {
  if (!Array.isArray(value) || value.length === 0 || value.length > maxItems) {
    return null;
  }
  const items: string[] = [];
  for (const item of value) {
    if (typeof item !== "string" || !item.trim() || item.length > 500) {
      return null;
    }
    items.push(item.trim());
  }
  return items;
}

