import { ethers } from "ethers";
import { AEVUM_TESTNET_CONFIG } from "./constants.js";
import type {
  AgentReputationSummary,
  EscrowDealStatus,
  EscrowDealSummary,
  SessionPolicyConfig,
} from "./index.js";
import {
  AGENT_VAULT_ABI,
  ERC20_ABI,
  ESCROW_COURT_ABI,
  IDENTITY_REGISTRY_ABI,
  REPUTATION_REGISTRY_ABI,
  VALIDATION_REGISTRY_ABI,
} from "./abis.js";
import {
  assertExpectedChainId,
  assertValidAddress,
  waitForTxReceipt,
  withRetry,
} from "./resilientRpc.js";

const DECIMALS = AEVUM_TESTNET_CONFIG.stablecoin.decimals;

const DEAL_STATUS_MAP: Record<number, EscrowDealStatus | "None"> = {
  0: "None",
  1: "Funded",
  2: "Submitted",
  3: "ResolvedSuccess",
  4: "ResolvedRefund",
  5: "ExpiredRefund",
};

export interface PreflightCheckResult {
  allowed: boolean;
  willQueueForHumanApproval: boolean;
  reasons: string[];
  remainingDailyAllowance: string;
  sellerScore: number;
  requiredScore: number;
}

export class ERC8004Client {
  public readonly identityContract: ethers.Contract;
  public readonly reputationContract: ethers.Contract;
  public readonly validationContract?: ethers.Contract;

  constructor(
    addresses: {
      identityRegistry: string;
      reputationRegistry: string;
      validationRegistry?: string;
    },
    runner: ethers.ContractRunner
  ) {
    this.identityContract = new ethers.Contract(
      assertValidAddress(addresses.identityRegistry, "identityRegistry"),
      IDENTITY_REGISTRY_ABI,
      runner
    );
    this.reputationContract = new ethers.Contract(
      assertValidAddress(addresses.reputationRegistry, "reputationRegistry"),
      REPUTATION_REGISTRY_ABI,
      runner
    );
    if (addresses.validationRegistry) {
      this.validationContract = new ethers.Contract(
        assertValidAddress(addresses.validationRegistry, "validationRegistry"),
        VALIDATION_REGISTRY_ABI,
        runner
      );
    }
  }

  async getScoreByAddress(
    agentAddress: string
  ): Promise<{ score: number; totalFeedback: number }> {
    const valid = assertValidAddress(agentAddress, "agentAddress");
    const [score, totalFeedback] = await withRetry(
      () =>
        this.reputationContract.getScoreByAddress(valid) as Promise<
          [bigint, bigint]
        >
    );
    return {
      score: Number(score),
      totalFeedback: Number(totalFeedback),
    };
  }

  async getAgentProfile(agentAddress: string): Promise<AgentReputationSummary> {
    const valid = assertValidAddress(agentAddress, "agentAddress");
    const [scoreInfo, primaryAgentId] = await Promise.all([
      this.getScoreByAddress(valid),
      withRetry(
        () => this.identityContract.primaryAgentIdOf(valid) as Promise<bigint>
      ),
    ]);

    let agentURI: string | undefined;
    let positiveCount = 0;
    let negativeCount = 0;
    let totalFeedback = scoreInfo.totalFeedback;

    if (primaryAgentId > 0n) {
      const [uri, summary] = await Promise.all([
        withRetry(
          () => this.identityContract.tokenURI(primaryAgentId) as Promise<string>
        ).catch(() => undefined),
        withRetry(
          () =>
            this.reputationContract.getSummary(primaryAgentId) as Promise<
              [bigint, bigint, bigint, bigint]
            >
        ),
      ]);
      agentURI = uri;
      totalFeedback = Number(summary[1]);
      positiveCount = Number(summary[2]);
      negativeCount = Number(summary[3]);
    }

    return {
      agentAddress: valid,
      agentId: primaryAgentId > 0n ? primaryAgentId.toString() : undefined,
      agentURI,
      averageScore: scoreInfo.score,
      totalFeedback,
      positiveCount,
      negativeCount,
    };
  }

  async registerAgent(
    agentURI: string,
    signer: ethers.Signer
  ): Promise<{ agentId: string; txHash: string }> {
    const connected = this.identityContract.connect(signer) as ethers.Contract;
    const tx = (await connected.register(agentURI)) as ethers.TransactionResponse;
    const receipt = await waitForTxReceipt(tx);

    let agentId = "0";
    for (const log of receipt.logs) {
      try {
        const parsed = this.identityContract.interface.parseLog(log);
        if (parsed?.name === "AgentRegistered") {
          agentId = (parsed.args.agentId as bigint).toString();
          break;
        }
      } catch {
        // Ignore unrelated logs
      }
    }

    return { agentId, txHash: receipt.hash };
  }
}

export class AevumVaultClient {
  public readonly vaultContract: ethers.Contract;
  private readonly reputationContract?: ethers.Contract;

  constructor(
    vaultAddress: string,
    runner: ethers.ContractRunner,
    reputationRegistryAddress?: string
  ) {
    this.vaultContract = new ethers.Contract(
      assertValidAddress(vaultAddress, "vaultAddress"),
      AGENT_VAULT_ABI,
      runner
    );
    if (reputationRegistryAddress) {
      this.reputationContract = new ethers.Contract(
        assertValidAddress(reputationRegistryAddress, "reputationRegistry"),
        REPUTATION_REGISTRY_ABI,
        runner
      );
    }
  }

  async getSessionPolicy(sessionKey: string): Promise<
    SessionPolicyConfig & {
      spentInCurrentWindow: string;
      windowStart: number;
      restrictToEscrowOnly: boolean;
      remainingDailyAllowance: string;
      vaultFrozen: boolean;
    }
  > {
    const validKey = assertValidAddress(sessionKey, "sessionKey");
    const [policy, remainingRaw, frozen] = await Promise.all([
      withRetry(
        () =>
          this.vaultContract.sessionPolicies(validKey) as Promise<
            [bigint, bigint, bigint, bigint, bigint, bigint, bigint, boolean, boolean]
          >
      ),
      withRetry(
        () => this.vaultContract.getRemainingDailyAllowance(validKey) as Promise<bigint>
      ),
      withRetry(() => this.vaultContract.vaultFrozen() as Promise<boolean>),
    ]);

    return {
      sessionKey: validKey,
      maxAmountPerTx: ethers.formatUnits(policy[0], DECIMALS),
      dailySpendLimit: ethers.formatUnits(policy[1], DECIMALS),
      humanApprovalThreshold: ethers.formatUnits(policy[2], DECIMALS),
      spentInCurrentWindow: ethers.formatUnits(policy[3], DECIMALS),
      windowStart: Number(policy[4]),
      expiresAt: Number(policy[5]),
      minCounterpartyScore: Number(policy[6]),
      restrictToEscrowOnly: Boolean(policy[7]),
      active: Boolean(policy[8]),
      remainingDailyAllowance: ethers.formatUnits(remainingRaw, DECIMALS),
      vaultFrozen: Boolean(frozen),
    };
  }

  async preflightCheck(params: {
    sessionKey: string;
    sellerAddress: string;
    amountTusd8: string;
  }): Promise<PreflightCheckResult> {
    const seller = assertValidAddress(params.sellerAddress, "sellerAddress");
    const amountRaw = ethers.parseUnits(params.amountTusd8, DECIMALS);
    const policy = await this.getSessionPolicy(params.sessionKey);

    const maxPerTxRaw = ethers.parseUnits(policy.maxAmountPerTx, DECIMALS);
    const thresholdRaw = ethers.parseUnits(policy.humanApprovalThreshold, DECIMALS);
    const remainingRaw = ethers.parseUnits(policy.remainingDailyAllowance, DECIMALS);

    const reasons: string[] = [];
    const nowSec = Math.floor(Date.now() / 1000);

    if (policy.vaultFrozen) {
      reasons.push("Vault is currently frozen by owner.");
    }
    if (!policy.active) {
      reasons.push("Session key is inactive or revoked.");
    }
    if (policy.expiresAt <= nowSec) {
      reasons.push("Session key has expired.");
    }
    if (amountRaw <= 0n) {
      reasons.push("Amount must be greater than zero.");
    }
    if (amountRaw > maxPerTxRaw) {
      reasons.push(
        `Requested ${params.amountTusd8} tUSD8 exceeds maxAmountPerTx (${policy.maxAmountPerTx} tUSD8).`
      );
    }
    if (amountRaw > remainingRaw) {
      reasons.push(
        `Requested ${params.amountTusd8} tUSD8 exceeds remaining daily allowance (${policy.remainingDailyAllowance} tUSD8).`
      );
    }

    let sellerScore = 0;
    if (this.reputationContract) {
      const [score] = await withRetry(
        () => this.reputationContract!.getScoreByAddress(seller) as Promise<[bigint, bigint]>
      );
      sellerScore = Number(score);
      if (policy.minCounterpartyScore > 0 && sellerScore < policy.minCounterpartyScore) {
        reasons.push(
          `Seller ERC-8004 score (${sellerScore}/100) is below required minimum (${policy.minCounterpartyScore}/100).`
        );
      }
    }

    const willQueueForHumanApproval = thresholdRaw > 0n && amountRaw > thresholdRaw;

    return {
      allowed: reasons.length === 0,
      willQueueForHumanApproval,
      reasons,
      remainingDailyAllowance: policy.remainingDailyAllowance,
      sellerScore,
      requiredScore: policy.minCounterpartyScore,
    };
  }

  async configureSessionKey(
    ownerSigner: ethers.Signer,
    params: {
      sessionKey: string;
      maxAmountPerTxTusd8: string;
      dailySpendLimitTusd8: string;
      humanApprovalThresholdTusd8: string;
      expiresAtUnix: number;
      minCounterpartyScore: number;
      restrictToEscrowOnly: boolean;
    }
  ): Promise<{ txHash: string }> {
    const connected = this.vaultContract.connect(ownerSigner) as ethers.Contract;
    const tx = (await connected.configureSessionKey(
      assertValidAddress(params.sessionKey, "sessionKey"),
      ethers.parseUnits(params.maxAmountPerTxTusd8, DECIMALS),
      ethers.parseUnits(params.dailySpendLimitTusd8, DECIMALS),
      ethers.parseUnits(params.humanApprovalThresholdTusd8, DECIMALS),
      BigInt(params.expiresAtUnix),
      params.minCounterpartyScore,
      params.restrictToEscrowOnly
    )) as ethers.TransactionResponse;
    const receipt = await waitForTxReceipt(tx);
    return { txHash: receipt.hash };
  }

  async revokeSessionKey(
    ownerSigner: ethers.Signer,
    sessionKey: string
  ): Promise<{ txHash: string }> {
    const connected = this.vaultContract.connect(ownerSigner) as ethers.Contract;
    const tx = (await connected.revokeSessionKey(
      assertValidAddress(sessionKey, "sessionKey")
    )) as ethers.TransactionResponse;
    const receipt = await waitForTxReceipt(tx);
    return { txHash: receipt.hash };
  }

  async executeScopedEscrow(
    sessionSigner: ethers.Signer,
    params: {
      dealSalt: string;
      seller: string;
      token?: string;
      amountTusd8: string;
      durationSeconds: number;
      criteriaHash: string;
    }
  ): Promise<{
    txHash: string;
    dealIdOrRequestId: string;
    queuedForApproval: boolean;
  }> {
    const connected = this.vaultContract.connect(sessionSigner) as ethers.Contract;
    const tokenAddr = assertValidAddress(
      params.token ?? AEVUM_TESTNET_CONFIG.stablecoin.address,
      "token"
    );
    const tx = (await connected.executeScopedEscrow(
      params.dealSalt,
      assertValidAddress(params.seller, "seller"),
      tokenAddr,
      ethers.parseUnits(params.amountTusd8, DECIMALS),
      BigInt(params.durationSeconds),
      params.criteriaHash
    )) as ethers.TransactionResponse;
    const receipt = await waitForTxReceipt(tx);

    let dealIdOrRequestId = ethers.ZeroHash;
    let queuedForApproval = false;

    for (const log of receipt.logs) {
      try {
        const parsed = this.vaultContract.interface.parseLog(log);
        if (parsed?.name === "PaymentQueuedForApproval") {
          dealIdOrRequestId = parsed.args.requestId as string;
          queuedForApproval = true;
          break;
        }
        if (parsed?.name === "ScopedEscrowExecuted") {
          dealIdOrRequestId = parsed.args.dealId as string;
          queuedForApproval = false;
          break;
        }
      } catch {
        // Ignore logs from EscrowCourt or ERC20
      }
    }

    return {
      txHash: receipt.hash,
      dealIdOrRequestId,
      queuedForApproval,
    };
  }

  async approveQueuedPayment(
    ownerSigner: ethers.Signer,
    requestId: string
  ): Promise<{ txHash: string; dealId: string }> {
    const connected = this.vaultContract.connect(ownerSigner) as ethers.Contract;
    const tx = (await connected.approveQueuedPayment(
      requestId
    )) as ethers.TransactionResponse;
    const receipt = await waitForTxReceipt(tx);

    let dealId = ethers.ZeroHash;
    for (const log of receipt.logs) {
      try {
        const parsed = this.vaultContract.interface.parseLog(log);
        if (parsed?.name === "QueuedPaymentApproved") {
          dealId = parsed.args.dealId as string;
          break;
        }
      } catch {
        // Ignore non-vault logs
      }
    }

    return { txHash: receipt.hash, dealId };
  }

  async rejectQueuedPayment(
    ownerSigner: ethers.Signer,
    requestId: string,
    reason: string
  ): Promise<{ txHash: string }> {
    const connected = this.vaultContract.connect(ownerSigner) as ethers.Contract;
    const tx = (await connected.rejectQueuedPayment(
      requestId,
      reason
    )) as ethers.TransactionResponse;
    const receipt = await waitForTxReceipt(tx);
    return { txHash: receipt.hash };
  }
}

export class AevumEscrowClient {
  public readonly escrowContract: ethers.Contract;

  constructor(escrowAddress: string, runner: ethers.ContractRunner) {
    this.escrowContract = new ethers.Contract(
      assertValidAddress(escrowAddress, "escrowAddress"),
      ESCROW_COURT_ABI,
      runner
    );
  }

  async getDeal(dealId: string): Promise<
    EscrowDealSummary & {
      protocolFee: string;
      submittedAt: number;
      judgeScore: number;
      refundRecipient: string;
    }
  > {
    if (!/^0x[0-9a-fA-F]{64}$/.test(dealId)) {
      throw new Error(`Invalid dealId bytes32: ${dealId}`);
    }
    const raw = await withRetry(
      () =>
        this.escrowContract.getDeal(dealId) as Promise<{
          dealId: string;
          buyer: string;
          refundRecipient: string;
          seller: string;
          token: string;
          amount: bigint;
          protocolFee: bigint;
          deadline: bigint;
          submittedAt: bigint;
          state: bigint;
          criteriaHash: string;
          deliverableHash: string;
          verdictHash: string;
          judgeScore: bigint;
        }>
    );

    const stateCode = Number(raw.state);
    if (stateCode === 0) {
      throw new Error(`Escrow deal ${dealId} was not found on-chain.`);
    }

    const mappedStatus = DEAL_STATUS_MAP[stateCode];
    const status: EscrowDealStatus =
      mappedStatus && mappedStatus !== "None" ? mappedStatus : "Funded";

    return {
      dealId: raw.dealId,
      buyer: raw.buyer,
      refundRecipient: raw.refundRecipient,
      seller: raw.seller,
      token: raw.token,
      amount: ethers.formatUnits(raw.amount, DECIMALS),
      protocolFee: ethers.formatUnits(raw.protocolFee, DECIMALS),
      deadline: Number(raw.deadline),
      submittedAt: Number(raw.submittedAt),
      status,
      criteriaHash: raw.criteriaHash,
      deliverableHash: raw.deliverableHash || undefined,
      verdictHash:
        raw.verdictHash && raw.verdictHash !== ethers.ZeroHash
          ? raw.verdictHash
          : undefined,
      judgeScore: Number(raw.judgeScore),
    };
  }

  async computeDealId(funderAddress: string, dealSalt: string): Promise<string> {
    return withRetry(
      () =>
        this.escrowContract.computeDealId(
          assertValidAddress(funderAddress, "funderAddress"),
          dealSalt
        ) as Promise<string>
    );
  }

  async submitDeliverable(
    sellerSigner: ethers.Signer,
    dealId: string,
    deliverableHash: string
  ): Promise<{ txHash: string }> {
    const connected = this.escrowContract.connect(sellerSigner) as ethers.Contract;
    const tx = (await connected.submitDeliverable(
      dealId,
      deliverableHash
    )) as ethers.TransactionResponse;
    const receipt = await waitForTxReceipt(tx);
    return { txHash: receipt.hash };
  }

  async resolveEscrow(
    validatorSigner: ethers.Signer,
    params: {
      dealId: string;
      approved: boolean;
      score: number;
      verdictHash: string;
      reasoningURI: string;
    }
  ): Promise<{ txHash: string }> {
    const connected = this.escrowContract.connect(validatorSigner) as ethers.Contract;
    const tx = (await connected.resolveEscrow(
      params.dealId,
      params.approved,
      params.score,
      params.verdictHash,
      params.reasoningURI
    )) as ethers.TransactionResponse;
    const receipt = await waitForTxReceipt(tx);
    return { txHash: receipt.hash };
  }

  async resolveEscrowWithSig(
    relayerSigner: ethers.Signer,
    params: {
      dealId: string;
      approved: boolean;
      score: number;
      verdictHash: string;
      reasoningURI: string;
      sigDeadline: number | bigint;
      signature: string;
    }
  ): Promise<{ txHash: string }> {
    const connected = this.escrowContract.connect(relayerSigner) as ethers.Contract;
    const tx = (await connected.resolveEscrowWithSig(
      params.dealId,
      params.approved,
      params.score,
      params.verdictHash,
      params.reasoningURI,
      BigInt(params.sigDeadline),
      params.signature
    )) as ethers.TransactionResponse;
    const receipt = await waitForTxReceipt(tx);
    return { txHash: receipt.hash };
  }
}

export interface AevumSDKInitOptions {
  rpcUrl?: string;
  chainId?: number;
  explorerUrl?: string;
  tusd8Address?: string;
  contracts: {
    identityRegistry: string;
    reputationRegistry: string;
    validationRegistry?: string;
    agentVault: string;
    escrowCourt: string;
  };
}

export class AevumPayGuardSDK {
  public readonly chainId: number;
  public readonly rpcUrl: string;
  public readonly explorerUrl: string;
  public readonly tusd8Address: string;
  public readonly provider: ethers.JsonRpcProvider;
  public readonly erc8004: ERC8004Client;
  public readonly vault: AevumVaultClient;
  public readonly escrow: AevumEscrowClient;

  constructor(options: AevumSDKInitOptions) {
    this.chainId = options.chainId ?? AEVUM_TESTNET_CONFIG.chainId;
    this.rpcUrl = options.rpcUrl ?? AEVUM_TESTNET_CONFIG.rpcUrl;
    this.explorerUrl = options.explorerUrl ?? AEVUM_TESTNET_CONFIG.explorerUrl;
    this.tusd8Address = assertValidAddress(
      options.tusd8Address ?? AEVUM_TESTNET_CONFIG.stablecoin.address,
      "tusd8Address"
    );

    this.provider = new ethers.JsonRpcProvider(this.rpcUrl);
    this.erc8004 = new ERC8004Client(options.contracts, this.provider);
    this.vault = new AevumVaultClient(
      options.contracts.agentVault,
      this.provider,
      options.contracts.reputationRegistry
    );
    this.escrow = new AevumEscrowClient(
      options.contracts.escrowCourt,
      this.provider
    );
  }

  getTxExplorerUrl(txHash: string): string {
    return `${this.explorerUrl}/tx/${txHash}`;
  }

  getAddressExplorerUrl(address: string): string {
    return `${this.explorerUrl}/address/${assertValidAddress(address)}`;
  }

  async verifyChainId(): Promise<number> {
    return assertExpectedChainId(this.provider, this.chainId);
  }

  async getTusd8Balance(accountAddress: string): Promise<string> {
    const valid = assertValidAddress(accountAddress, "accountAddress");
    const token = new ethers.Contract(this.tusd8Address, ERC20_ABI, this.provider);
    const bal = await withRetry(() => token.balanceOf(valid) as Promise<bigint>);
    return ethers.formatUnits(bal, DECIMALS);
  }
}

