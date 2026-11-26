import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import {
  verifyVerdictAudit,
  type CanonicalVerdictPayload,
} from "@aevum/agent-pay-sdk";
import type { DetailedPromptFirewallResult } from "../security/promptFirewall.js";

export interface StoredAuditRecord {
  dealId: string;
  canonicalPayload: CanonicalVerdictPayload;
  verdictHash: string;
  reasoningURI: string;
  firewall: DetailedPromptFirewallResult;
  eip712?: {
    validator: string;
    sigDeadline: number;
    signature: string;
  };
  settlementTxHash?: string;
  evaluatedAt: string;
}

/**
 * Tamper-evident audit record persistence using atomic temp-file + rename writes.
 */
export class AuditStore {
  private readonly filePath: string;
  private readonly records = new Map<string, StoredAuditRecord>();

  constructor(filePath: string) {
    this.filePath = path.resolve(filePath);
    this.loadFromDisk();
  }

  private loadFromDisk(): void {
    try {
      if (!fs.existsSync(this.filePath)) return;
      const raw = fs.readFileSync(this.filePath, "utf8");
      if (!raw.trim()) return;
      const parsed = JSON.parse(raw) as StoredAuditRecord[];
      if (Array.isArray(parsed)) {
        for (const rec of parsed) {
          if (rec?.dealId) {
            this.records.set(rec.dealId.toLowerCase(), rec);
          }
        }
      }
    } catch {
      // Start clean if disk file is empty or unreadable
    }
  }

  private flushToDisk(): void {
    const dir = path.dirname(this.filePath);
    fs.mkdirSync(dir, { recursive: true });

    const serialized = JSON.stringify(Array.from(this.records.values()), null, 2);
    const tmpPath = `${this.filePath}.${process.pid}.${crypto
      .randomBytes(4)
      .toString("hex")}.tmp`;

    fs.writeFileSync(tmpPath, serialized, "utf8");
    fs.renameSync(tmpPath, this.filePath);
  }

  saveRecord(record: StoredAuditRecord): StoredAuditRecord {
    this.records.set(record.dealId.toLowerCase(), record);
    this.flushToDisk();
    return record;
  }

  markSettled(dealId: string, txHash: string): StoredAuditRecord | undefined {
    const existing = this.records.get(dealId.toLowerCase());
    if (!existing) return undefined;
    const updated: StoredAuditRecord = {
      ...existing,
      settlementTxHash: txHash,
    };
    this.records.set(dealId.toLowerCase(), updated);
    this.flushToDisk();
    return updated;
  }

  getRecord(dealId: string): StoredAuditRecord | undefined {
    return this.records.get(dealId.toLowerCase());
  }

  listRecords(limit = 50): StoredAuditRecord[] {
    return Array.from(this.records.values())
      .sort((a, b) => b.evaluatedAt.localeCompare(a.evaluatedAt))
      .slice(0, limit);
  }

  verifyRecord(dealId: string): {
    found: boolean;
    valid: boolean;
    computedHash?: string;
    expectedHash?: string;
    record?: StoredAuditRecord;
  } {
    const record = this.getRecord(dealId);
    if (!record) {
      return { found: false, valid: false };
    }
    const check = verifyVerdictAudit(record.canonicalPayload, record.verdictHash);
    return {
      found: true,
      valid: check.valid,
      computedHash: check.computedHash,
      expectedHash: check.expectedHash,
      record,
    };
  }
}

