import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";

describe("Aevum PayGuard — Full Protocol & Safety Suite", function () {
  const DECIMALS = 6;
  const ONE_DAY = 24 * 60 * 60;
  const ONE_HOUR = 60 * 60;
  const PROTOCOL_FEE_BPS = 25; // 0.25%

  const usd = (amount: string) => ethers.parseUnits(amount, DECIMALS);

  async function deployProtocolFixture() {
    const [owner, sessionAgent, sellerGood, sellerBad, aiValidator, feeRecipient, stranger] =
      await ethers.getSigners();

    const MockTUSD8 = await ethers.getContractFactory("MockTUSD8");
    const tusd8 = await MockTUSD8.deploy();

    const IdentityRegistry = await ethers.getContractFactory("AevumIdentityRegistry");
    const identityRegistry = await IdentityRegistry.deploy();

    const ReputationRegistry = await ethers.getContractFactory("AevumReputationRegistry");
    const reputationRegistry = await ReputationRegistry.deploy(
      await identityRegistry.getAddress()
    );

    const ValidationRegistry = await ethers.getContractFactory("AevumValidationRegistry");
    const validationRegistry = await ValidationRegistry.deploy();

    const EscrowCourt = await ethers.getContractFactory("AevumEscrowCourt");
    const escrowCourt = await EscrowCourt.deploy(
      await identityRegistry.getAddress(),
      await reputationRegistry.getAddress(),
      await validationRegistry.getAddress(),
      aiValidator.address,
      feeRecipient.address,
      PROTOCOL_FEE_BPS
    );

    await reputationRegistry.setAuthorizedCourt(await escrowCourt.getAddress(), true);
    await validationRegistry.setAuthorizedRecorder(await escrowCourt.getAddress(), true);

    const AgentVault = await ethers.getContractFactory("AevumAgentVault");
    const vault = await AgentVault.deploy(
      owner.address,
      await reputationRegistry.getAddress(),
      await escrowCourt.getAddress()
    );

    // Fund vault with 500 tUSD8 from owner
    await tusd8.connect(owner).approve(await vault.getAddress(), usd("500"));
    await vault.connect(owner).depositToken(await tusd8.getAddress(), usd("500"));

    // Register good seller on ERC-8004 Identity & seed initial 90/100 reputation
    await identityRegistry.connect(sellerGood).register("ipfs://aevum-agent-good.json");
    await reputationRegistry
      .connect(stranger)
      .giveFeedback(1n, 90n, 0, "reliability", "tUSD8", ethers.id("seed-1"), "ipfs://fb-1");

    // Register bad seller on ERC-8004 Identity & seed low 30/100 reputation
    await identityRegistry.connect(sellerBad).register("ipfs://aevum-agent-bad.json");
    await reputationRegistry
      .connect(stranger)
      .giveFeedback(2n, 30n, 0, "sloppy", "tUSD8", ethers.id("seed-2"), "ipfs://fb-2");

    return {
      owner,
      sessionAgent,
      sellerGood,
      sellerBad,
      aiValidator,
      feeRecipient,
      stranger,
      tusd8,
      identityRegistry,
      reputationRegistry,
      validationRegistry,
      escrowCourt,
      vault,
    };
  }

  describe("1. ERC-8004 Identity, Reputation & Validation Registries", function () {
    it("registers agent identity, updates URI, and blocks unauthorized updates", async function () {
      const { identityRegistry, sellerGood, stranger } = await loadFixture(deployProtocolFixture);

      expect(await identityRegistry.primaryAgentIdOf(sellerGood.address)).to.equal(1n);
      expect(await identityRegistry.tokenURI(1n)).to.equal("ipfs://aevum-agent-good.json");

      await identityRegistry.connect(sellerGood).setAgentURI(1n, "ipfs://aevum-agent-good-v2.json");
      expect(await identityRegistry.tokenURI(1n)).to.equal("ipfs://aevum-agent-good-v2.json");

      await expect(
        identityRegistry.connect(stranger).setAgentURI(1n, "ipfs://hijacked.json")
      ).to.be.revertedWithCustomError(identityRegistry, "UnauthorizedAgentOperator");
    });

    it("prevents self-feedback and updates summary accurately on revocation", async function () {
      const { reputationRegistry, sellerGood, owner } = await loadFixture(deployProtocolFixture);

      await expect(
        reputationRegistry
          .connect(sellerGood)
          .giveFeedback(1n, 100n, 0, "self", "tUSD8", ethers.id("self"), "")
      ).to.be.revertedWithCustomError(reputationRegistry, "SelfFeedbackForbidden");

      await reputationRegistry
        .connect(owner)
        .giveFeedback(1n, 70n, 0, "speed", "tUSD8", ethers.id("deal-a"), "ipfs://fb-2");

      let [avg, count, pos, neg] = await reputationRegistry.getSummary(1n);
      expect(avg).to.equal(80n); // (90 + 70) / 2
      expect(count).to.equal(2n);
      expect(pos).to.equal(2n);
      expect(neg).to.equal(0n);

      await reputationRegistry.connect(owner).revokeFeedback(1n, 0n);
      [avg, count, pos, neg] = await reputationRegistry.getSummary(1n);
      expect(avg).to.equal(90n);
      expect(count).to.equal(1n);
      expect(pos).to.equal(1n);
    });

    it("enforces designated validator on ValidationRegistry", async function () {
      const { validationRegistry, aiValidator, stranger } =
        await loadFixture(deployProtocolFixture);

      await expect(
        validationRegistry.connect(stranger).requestValidation(1n, aiValidator.address, "ipfs://task")
      )
        .to.emit(validationRegistry, "ValidationRequested")
        .withArgs(1n, aiValidator.address, 1n, "ipfs://task");

      const verdictHash = ethers.id("verdict-1");
      await expect(
        validationRegistry.connect(stranger).completeValidation(1n, 95, verdictHash, "ipfs://proof")
      ).to.be.revertedWithCustomError(validationRegistry, "OnlyDesignatedValidator");

      await expect(
        validationRegistry.connect(aiValidator).completeValidation(1n, 95, verdictHash, "ipfs://proof")
      )
        .to.emit(validationRegistry, "ValidationCompleted")
        .withArgs(1n, aiValidator.address, 1n, 95, verdictHash, "ipfs://proof");

      const record = await validationRegistry.getValidation(1n);
      expect(record.completed).to.equal(true);
      expect(record.score).to.equal(95);
      expect(record.verdictHash).to.equal(verdictHash);
    });
  });

  describe("2. AevumAgentVault — Scoped Session Keys & Safety Guardrails", function () {
    it("allows owner deposit/withdraw and configures scoped session key", async function () {
      const { vault, tusd8, owner, sessionAgent, stranger } =
        await loadFixture(deployProtocolFixture);

      expect(await tusd8.balanceOf(await vault.getAddress())).to.equal(usd("500"));

      await expect(
        vault.connect(stranger).withdrawToken(await tusd8.getAddress(), usd("10"), stranger.address)
      ).to.be.revertedWithCustomError(vault, "OnlyOwner");

      await vault.connect(owner).withdrawToken(await tusd8.getAddress(), usd("50"), owner.address);
      expect(await tusd8.balanceOf(await vault.getAddress())).to.equal(usd("450"));

      const expiresAt = BigInt(await time.latest()) + BigInt(ONE_DAY);
      await vault
        .connect(owner)
        .configureSessionKey(
          sessionAgent.address,
          usd("50"),
          usd("100"),
          usd("30"),
          expiresAt,
          70,
          true
        );

      expect(await vault.getRemainingDailyAllowance(sessionAgent.address)).to.equal(usd("100"));
    });

    it("Edge Case 1 & 2: enforces per-tx limit, rolling 24h daily cap, and 24h auto-reset", async function () {
      const { vault, tusd8, owner, sessionAgent, sellerGood } =
        await loadFixture(deployProtocolFixture);

      const expiresAt = BigInt(await time.latest()) + BigInt(ONE_DAY * 3);
      await vault.connect(owner).configureSessionKey(
        sessionAgent.address,
        usd("40"), // maxAmountPerTx = 40 tUSD8
        usd("60"), // dailySpendLimit = 60 tUSD8
        usd("40"), // humanApprovalThreshold = 40 tUSD8
        expiresAt,
        70,
        true
      );

      const tusd8Addr = await tusd8.getAddress();

      // Exceeds maxAmountPerTx (45 > 40)
      await expect(
        vault
          .connect(sessionAgent)
          .executeScopedEscrow(ethers.id("salt-over-tx"), sellerGood.address, tusd8Addr, usd("45"), ONE_HOUR, "ipfs://c1")
      ).to.be.revertedWithCustomError(vault, "ExceedsMaxPerTx");

      // Spend 35 tUSD8 -> succeeds (remaining = 25)
      await vault
        .connect(sessionAgent)
        .executeScopedEscrow(ethers.id("salt-1"), sellerGood.address, tusd8Addr, usd("35"), ONE_HOUR, "ipfs://c1");
      expect(await vault.getRemainingDailyAllowance(sessionAgent.address)).to.equal(usd("25"));

      // Try spending another 30 tUSD8 -> exceeds remaining 25
      await expect(
        vault
          .connect(sessionAgent)
          .executeScopedEscrow(ethers.id("salt-2"), sellerGood.address, tusd8Addr, usd("30"), ONE_HOUR, "ipfs://c2")
      ).to.be.revertedWithCustomError(vault, "ExceedsDailySpendCap");

      // Advance 24 hours + 1 second -> rolling daily cap automatically resets
      await time.increase(ONE_DAY + 1);
      expect(await vault.getRemainingDailyAllowance(sessionAgent.address)).to.equal(usd("60"));

      await expect(
        vault
          .connect(sessionAgent)
          .executeScopedEscrow(ethers.id("salt-3"), sellerGood.address, tusd8Addr, usd("30"), ONE_HOUR, "ipfs://c3")
      ).to.emit(vault, "ScopedEscrowExecuted");
    });

    it("Edge Case 3: blocks low-reputation or unregistered sellers on-chain via ERC-8004 gate", async function () {
      const { vault, tusd8, owner, sessionAgent, sellerBad, stranger } =
        await loadFixture(deployProtocolFixture);

      const expiresAt = BigInt(await time.latest()) + BigInt(ONE_DAY);
      await vault
        .connect(owner)
        .configureSessionKey(sessionAgent.address, usd("50"), usd("100"), 0, expiresAt, 70, true);

      const tusd8Addr = await tusd8.getAddress();

      // sellerBad has score 30 < 70
      await expect(
        vault
          .connect(sessionAgent)
          .executeScopedEscrow(ethers.id("bad-1"), sellerBad.address, tusd8Addr, usd("10"), ONE_HOUR, "ipfs://c")
      )
        .to.be.revertedWithCustomError(vault, "CounterpartyReputationTooLow")
        .withArgs(30, 70);

      // stranger is unregistered (score 0 < 70)
      await expect(
        vault
          .connect(sessionAgent)
          .executeScopedEscrow(ethers.id("unreg-1"), stranger.address, tusd8Addr, usd("10"), ONE_HOUR, "ipfs://c")
      )
        .to.be.revertedWithCustomError(vault, "CounterpartyReputationTooLow")
        .withArgs(0, 70);
    });

    it("Edge Case 4 & 5: enforces session expiration, instant Kill-Switch revocation, and vault freeze", async function () {
      const { vault, tusd8, owner, sessionAgent, sellerGood } =
        await loadFixture(deployProtocolFixture);

      const tusd8Addr = await tusd8.getAddress();
      const expiresAt = BigInt(await time.latest()) + 3600n;
      await vault
        .connect(owner)
        .configureSessionKey(sessionAgent.address, usd("50"), usd("100"), 0, expiresAt, 70, true);

      // Emergency Vault Freeze blocks execution immediately
      await vault.connect(owner).setVaultFrozen(true);
      await expect(
        vault
          .connect(sessionAgent)
          .executeScopedEscrow(ethers.id("frozen"), sellerGood.address, tusd8Addr, usd("10"), ONE_HOUR, "ipfs://c")
      ).to.be.revertedWithCustomError(vault, "VaultIsFrozen");
      await vault.connect(owner).setVaultFrozen(false);

      // Instant Kill-Switch revokes session key in 1 tx
      await expect(vault.connect(owner).revokeSessionKey(sessionAgent.address))
        .to.emit(vault, "SessionKeyRevoked")
        .withArgs(sessionAgent.address);

      await expect(
        vault
          .connect(sessionAgent)
          .executeScopedEscrow(ethers.id("revoked"), sellerGood.address, tusd8Addr, usd("10"), ONE_HOUR, "ipfs://c")
      ).to.be.revertedWithCustomError(vault, "SessionKeyInactive");

      // Re-issue with short expiry and test SessionKeyExpired
      const nextExp = BigInt(await time.latest()) + 120n;
      await vault
        .connect(owner)
        .configureSessionKey(sessionAgent.address, usd("50"), usd("100"), 0, nextExp, 70, true);
      await time.increase(125);

      await expect(
        vault
          .connect(sessionAgent)
          .executeScopedEscrow(ethers.id("expired"), sellerGood.address, tusd8Addr, usd("10"), ONE_HOUR, "ipfs://c")
      ).to.be.revertedWithCustomError(vault, "SessionKeyExpired");
    });

    it("Edge Case 6: queues high-value deals for Human-in-the-Loop approval & supports approve/reject", async function () {
      const { vault, escrowCourt, tusd8, owner, sessionAgent, sellerGood } =
        await loadFixture(deployProtocolFixture);

      const tusd8Addr = await tusd8.getAddress();
      const expiresAt = BigInt(await time.latest()) + BigInt(ONE_DAY);
      await vault.connect(owner).configureSessionKey(
        sessionAgent.address,
        usd("100"), // hard max 100
        usd("200"), // daily max 200
        usd("50"),  // human approval required above 50 tUSD8
        expiresAt,
        70,
        true
      );

      const saltApprove = ethers.id("hitl-approve");
      const tx = await vault
        .connect(sessionAgent)
        .executeScopedEscrow(saltApprove, sellerGood.address, tusd8Addr, usd("75"), ONE_HOUR, "ipfs://big-task");
      const receipt = await tx.wait();

      const queuedLog = receipt!.logs
        .map((l) => {
          try {
            return vault.interface.parseLog(l);
          } catch {
            return null;
          }
        })
        .find((parsed) => parsed?.name === "PaymentQueuedForApproval");

      expect(queuedLog).to.not.be.undefined;
      const requestId = queuedLog!.args.requestId as string;

      // Funds have NOT moved yet
      expect(await tusd8.balanceOf(await vault.getAddress())).to.equal(usd("500"));
      let req = await vault.getQueuedRequest(requestId);
      expect(req.status).to.equal(1n); // Pending

      // Human owner approves -> funds lock in AevumEscrowCourt
      const expectedDealId = await escrowCourt.computeDealId(await vault.getAddress(), saltApprove);
      await expect(vault.connect(owner).approveQueuedPayment(requestId))
        .to.emit(vault, "QueuedPaymentApproved")
        .withArgs(requestId, expectedDealId);

      expect(await tusd8.balanceOf(await vault.getAddress())).to.equal(usd("425"));
      expect(await tusd8.balanceOf(await escrowCourt.getAddress())).to.equal(usd("75"));

      // Test Human rejection path
      const saltReject = ethers.id("hitl-reject");
      const tx2 = await vault
        .connect(sessionAgent)
        .executeScopedEscrow(saltReject, sellerGood.address, tusd8Addr, usd("80"), ONE_HOUR, "ipfs://bad-task");
      const receipt2 = await tx2.wait();
      const queuedLog2 = receipt2!.logs
        .map((l) => {
          try {
            return vault.interface.parseLog(l);
          } catch {
            return null;
          }
        })
        .find((parsed) => parsed?.name === "PaymentQueuedForApproval");
      const requestId2 = queuedLog2!.args.requestId as string;

      await expect(vault.connect(owner).rejectQueuedPayment(requestId2, "Too expensive"))
        .to.emit(vault, "QueuedPaymentRejected")
        .withArgs(requestId2, "Too expensive");

      req = await vault.getQueuedRequest(requestId2);
      expect(req.status).to.equal(3n); // Rejected
      expect(await tusd8.balanceOf(await vault.getAddress())).to.equal(usd("425"));
    });

    it("Edge Case 7: enforces restrictToEscrowOnly and executes scoped direct micro-pay when enabled", async function () {
      const { vault, tusd8, owner, sessionAgent, sellerGood } =
        await loadFixture(deployProtocolFixture);

      const tusd8Addr = await tusd8.getAddress();
      const expiresAt = BigInt(await time.latest()) + BigInt(ONE_DAY);

      // Escrows-only enabled
      await vault
        .connect(owner)
        .configureSessionKey(sessionAgent.address, usd("20"), usd("50"), 0, expiresAt, 70, true);

      await expect(
        vault.connect(sessionAgent).executeScopedDirectPay(sellerGood.address, tusd8Addr, usd("5"), "api-call")
      ).to.be.revertedWithCustomError(vault, "DirectPaymentNotAllowed");

      // Reconfigure allowing direct micro-payments
      await vault
        .connect(owner)
        .configureSessionKey(sessionAgent.address, usd("20"), usd("50"), 0, expiresAt, 70, false);

      await expect(
        vault.connect(sessionAgent).executeScopedDirectPay(sellerGood.address, tusd8Addr, usd("5"), "api-call")
      ).to.changeTokenBalances(tusd8, [vault, sellerGood], [-usd("5"), usd("5")]);
    });
  });

  describe("3. AevumEscrowCourt — Settlement, EIP-712 Signatures, Refunds & FOT Safety", function () {
    it("Happy Path (PASS): settles tUSD8 with 0.25% fee and updates ERC-8004 Reputation & Validation", async function () {
      const {
        vault,
        escrowCourt,
        reputationRegistry,
        validationRegistry,
        tusd8,
        owner,
        sessionAgent,
        sellerGood,
        aiValidator,
        feeRecipient,
      } = await loadFixture(deployProtocolFixture);

      const tusd8Addr = await tusd8.getAddress();
      const expiresAt = BigInt(await time.latest()) + BigInt(ONE_DAY);
      await vault
        .connect(owner)
        .configureSessionKey(sessionAgent.address, usd("100"), usd("200"), 0, expiresAt, 70, true);

      const dealSalt = ethers.id("happy-deal-1");
      const amount = usd("100");
      await vault
        .connect(sessionAgent)
        .executeScopedEscrow(dealSalt, sellerGood.address, tusd8Addr, amount, ONE_HOUR, "ipfs://rubric-1");

      const dealId = await escrowCourt.computeDealId(await vault.getAddress(), dealSalt);

      await expect(escrowCourt.connect(sellerGood).submitDeliverable(dealId, "ipfs://deliverable-1"))
        .to.emit(escrowCourt, "DeliverableSubmitted")
        .withArgs(dealId, sellerGood.address, "ipfs://deliverable-1");

      const verdictHash = ethers.id("canonical-verdict-pass");
      const expectedFee = (amount * BigInt(PROTOCOL_FEE_BPS)) / 10_000n; // 0.25 tUSD8 = 250000
      const expectedSellerPayout = amount - expectedFee;

      await expect(
        escrowCourt
          .connect(aiValidator)
          .resolveEscrow(dealId, true, 96, verdictHash, "ipfs://audit-1")
      ).to.changeTokenBalances(
        tusd8,
        [escrowCourt, sellerGood, feeRecipient],
        [-amount, expectedSellerPayout, expectedFee]
      );

      const deal = await escrowCourt.getDeal(dealId);
      expect(deal.state).to.equal(3n); // ResolvedSuccess
      expect(deal.verdictHash).to.equal(verdictHash);
      expect(deal.judgeScore).to.equal(96n);

      // Seller's ERC-8004 Reputation updated from [90] to (90 + 96)/2 = 93
      const [newScore, totalFb] = await reputationRegistry.getScoreByAddress(sellerGood.address);
      expect(newScore).to.equal(93n);
      expect(totalFb).to.equal(2n);

      // Validation proof recorded
      const valRec = await validationRegistry.getValidation(1n);
      expect(valRec.completed).to.equal(true);
      expect(valRec.verdictHash).to.equal(verdictHash);
      expect(valRec.score).to.equal(96n);
    });

    it("Prompt-Injection / Failure Path (FAIL): refunds 100% of tUSD8 back to Vault & slashes seller score", async function () {
      const {
        vault,
        escrowCourt,
        reputationRegistry,
        tusd8,
        owner,
        sessionAgent,
        sellerGood,
        aiValidator,
      } = await loadFixture(deployProtocolFixture);

      const tusd8Addr = await tusd8.getAddress();
      const expiresAt = BigInt(await time.latest()) + BigInt(ONE_DAY);
      await vault
        .connect(owner)
        .configureSessionKey(sessionAgent.address, usd("100"), usd("200"), 0, expiresAt, 70, true);

      const dealSalt = ethers.id("injection-deal");
      const amount = usd("50");
      await vault
        .connect(sessionAgent)
        .executeScopedEscrow(dealSalt, sellerGood.address, tusd8Addr, amount, ONE_HOUR, "ipfs://rubric-inj");

      const dealId = await escrowCourt.computeDealId(await vault.getAddress(), dealSalt);
      await escrowCourt
        .connect(sellerGood)
        .submitDeliverable(dealId, "ipfs://malicious-prompt-injection-payload");

      const verdictHash = ethers.id("canonical-verdict-injection-caught");
      await expect(
        escrowCourt
          .connect(aiValidator)
          .resolveEscrow(dealId, false, 0, verdictHash, "ipfs://audit-injection")
      ).to.changeTokenBalances(tusd8, [escrowCourt, vault], [-amount, amount]);

      const deal = await escrowCourt.getDeal(dealId);
      expect(deal.state).to.equal(4n); // ResolvedRefund

      // Seller's ERC-8004 score dropped from 90 to (90 + 0)/2 = 45
      const [newScore, totalFb] = await reputationRegistry.getScoreByAddress(sellerGood.address);
      expect(newScore).to.equal(45n);
      expect(totalFb).to.equal(2n);
    });

    it("verifies off-chain EIP-712 typed signature resolution (resolveEscrowWithSig)", async function () {
      const { escrowCourt, tusd8, owner, sellerGood, aiValidator, stranger } =
        await loadFixture(deployProtocolFixture);

      const tusd8Addr = await tusd8.getAddress();
      const dealSalt = ethers.id("eip712-deal");
      const amount = usd("20");

      await tusd8.connect(owner).approve(await escrowCourt.getAddress(), amount);
      await escrowCourt
        .connect(owner)
        .createEscrow(dealSalt, sellerGood.address, tusd8Addr, amount, ONE_HOUR, "ipfs://rubric-sig");

      const dealId = await escrowCourt.computeDealId(owner.address, dealSalt);
      await escrowCourt.connect(sellerGood).submitDeliverable(dealId, "ipfs://work-sig");

      const verdictHash = ethers.id("sig-verdict");
      const reasoningURI = "ipfs://sig-reasoning";
      const sigDeadline = BigInt(await time.latest()) + 600n;
      const networkInfo = await ethers.provider.getNetwork();

      const domain = {
        name: "AevumEscrowCourt",
        version: "1",
        chainId: networkInfo.chainId,
        verifyingContract: await escrowCourt.getAddress(),
      };

      const types = {
        Verdict: [
          { name: "dealId", type: "bytes32" },
          { name: "approved", type: "bool" },
          { name: "score", type: "uint8" },
          { name: "verdictHash", type: "bytes32" },
          { name: "reasoningURIHash", type: "bytes32" },
          { name: "sigDeadline", type: "uint256" },
        ],
      };

      const value = {
        dealId,
        approved: true,
        score: 88,
        verdictHash,
        reasoningURIHash: ethers.keccak256(ethers.toUtf8Bytes(reasoningURI)),
        sigDeadline,
      };

      // Reject signature from non-validator
      const badSig = await stranger.signTypedData(domain, types, value);
      await expect(
        escrowCourt
          .connect(stranger)
          .resolveEscrowWithSig(dealId, true, 88, verdictHash, reasoningURI, sigDeadline, badSig)
      ).to.be.revertedWithCustomError(escrowCourt, "InvalidValidatorSignature");

      // Valid AI Validator signature relayed by stranger
      const validSig = await aiValidator.signTypedData(domain, types, value);
      await expect(
        escrowCourt
          .connect(stranger)
          .resolveEscrowWithSig(dealId, true, 88, verdictHash, reasoningURI, sigDeadline, validSig)
      ).to.emit(escrowCourt, "EscrowResolved");
    });

    it("supports trustless expired refunds for both seller ghosting and validator timeout", async function () {
      const { vault, escrowCourt, tusd8, owner, sessionAgent, sellerGood } =
        await loadFixture(deployProtocolFixture);

      const tusd8Addr = await tusd8.getAddress();
      const expiresAt = BigInt(await time.latest()) + BigInt(ONE_DAY * 3);
      await vault
        .connect(owner)
        .configureSessionKey(sessionAgent.address, usd("50"), usd("200"), 0, expiresAt, 70, true);

      // Case A: Seller never submits before deadline
      const saltA = ethers.id("ghost-seller");
      await vault
        .connect(sessionAgent)
        .executeScopedEscrow(saltA, sellerGood.address, tusd8Addr, usd("20"), ONE_HOUR, "ipfs://c-a");
      const dealIdA = await escrowCourt.computeDealId(await vault.getAddress(), saltA);

      await expect(escrowCourt.connect(owner).claimExpiredRefund(dealIdA)).to.be.revertedWithCustomError(
        escrowCourt,
        "DeadlineNotPassed"
      );

      await time.increase(ONE_HOUR + 1);
      await expect(escrowCourt.connect(owner).claimExpiredRefund(dealIdA)).to.changeTokenBalances(
        tusd8,
        [escrowCourt, vault],
        [-usd("20"), usd("20")]
      );

      // Case B: Seller submits, but AI Validator ghosts past ORACLE_TIMEOUT (24h)
      const saltB = ethers.id("ghost-oracle");
      await vault
        .connect(sessionAgent)
        .executeScopedEscrow(saltB, sellerGood.address, tusd8Addr, usd("25"), ONE_HOUR, "ipfs://c-b");
      const dealIdB = await escrowCourt.computeDealId(await vault.getAddress(), saltB);
      await escrowCourt.connect(sellerGood).submitDeliverable(dealIdB, "ipfs://work-b");

      await time.increase(ONE_HOUR + 10);
      await expect(escrowCourt.connect(owner).claimExpiredRefund(dealIdB)).to.be.revertedWithCustomError(
        escrowCourt,
        "OracleGracePeriodNotPassed"
      );

      await time.increase(ONE_DAY);
      await expect(escrowCourt.connect(owner).claimExpiredRefund(dealIdB)).to.changeTokenBalances(
        tusd8,
        [escrowCourt, vault],
        [-usd("25"), usd("25")]
      );
    });

    it("handles Fee-On-Transfer (FOT) tokens accurately using balance deltas", async function () {
      const { escrowCourt, tusd8, owner, sellerGood, aiValidator, stranger } =
        await loadFixture(deployProtocolFixture);

      // Enable 1% (100 bps) fee-on-transfer to stranger as feeSink
      await tusd8.connect(owner).setTransferFee(100, stranger.address);

      const tusd8Addr = await tusd8.getAddress();
      const dealSalt = ethers.id("fot-deal");
      const requestedAmount = usd("100");

      await tusd8.connect(owner).approve(await escrowCourt.getAddress(), requestedAmount);
      await escrowCourt
        .connect(owner)
        .createEscrow(dealSalt, sellerGood.address, tusd8Addr, requestedAmount, ONE_HOUR, "ipfs://fot");

      const dealId = await escrowCourt.computeDealId(owner.address, dealSalt);
      const deal = await escrowCourt.getDeal(dealId);
      // Actual amount locked after 1% FOT is 99 tUSD8
      expect(deal.amount).to.equal(usd("99"));

      await escrowCourt.connect(sellerGood).submitDeliverable(dealId, "ipfs://fot-work");
      await escrowCourt
        .connect(aiValidator)
        .resolveEscrow(dealId, true, 90, ethers.id("fot-verdict"), "ipfs://fot-proof");

      // Escrow contract holds zero leftover tokens
      expect(await tusd8.balanceOf(await escrowCourt.getAddress())).to.equal(0n);
      expect(await tusd8.balanceOf(sellerGood.address)).to.be.gt(0n);
    });
  });

  describe("4. Security Audit Remediation & Regression Tests", function () {
    it("HIGH-01 Fix: blocks unauthorized callers on recordAddressFeedback and recordDirectValidation", async function () {
      const { reputationRegistry, validationRegistry, sellerGood, stranger } =
        await loadFixture(deployProtocolFixture);

      await expect(
        reputationRegistry
          .connect(stranger)
          .recordAddressFeedback(
            sellerGood.address,
            stranger.address,
            0,
            "sybil-attack",
            "tUSD8",
            ethers.id("fake"),
            ""
          )
      ).to.be.revertedWithCustomError(reputationRegistry, "UnauthorizedCourt");

      await expect(
        validationRegistry
          .connect(stranger)
          .recordDirectValidation(
            1n,
            sellerGood.address,
            100,
            ethers.id("fake-verdict"),
            "ipfs://task",
            "ipfs://fake"
          )
      ).to.be.revertedWithCustomError(validationRegistry, "OnlyDesignatedValidator");
    });

    it("HIGH-02 Fix: enforces HITL daily cap deduction, seller reputation re-check, and 24h approval TTL", async function () {
      const { vault, tusd8, reputationRegistry, owner, sessionAgent, sellerGood, stranger } =
        await loadFixture(deployProtocolFixture);

      const tusd8Addr = await tusd8.getAddress();
      const expiresAt = BigInt(await time.latest()) + BigInt(ONE_DAY * 3);
      await vault.connect(owner).configureSessionKey(
        sessionAgent.address,
        usd("100"), // maxAmountPerTx
        usd("120"), // dailySpendLimit
        usd("50"),  // humanApprovalThreshold
        expiresAt,
        70,         // minCounterpartyScore
        true
      );

      // 1. Queue 75 tUSD8 -> succeeds and preserves cap until approval
      const tx1 = await vault
        .connect(sessionAgent)
        .executeScopedEscrow(ethers.id("hitl-cap-1"), sellerGood.address, tusd8Addr, usd("75"), ONE_HOUR, "ipfs://h1");
      const r1 = await tx1.wait();
      const reqId1 = r1!.logs
        .map((l) => {
          try {
            return vault.interface.parseLog(l);
          } catch {
            return null;
          }
        })
        .find((p) => p?.name === "PaymentQueuedForApproval")!.args.requestId as string;

      // Approving deducts 75 from daily allowance -> 45 remaining
      await vault.connect(owner).approveQueuedPayment(reqId1);
      expect(await vault.getRemainingDailyAllowance(sessionAgent.address)).to.equal(usd("45"));

      // Trying to queue 60 tUSD8 (> 45 remaining) now fails immediately
      await expect(
        vault
          .connect(sessionAgent)
          .executeScopedEscrow(ethers.id("hitl-cap-2"), sellerGood.address, tusd8Addr, usd("60"), ONE_HOUR, "ipfs://h2")
      ).to.be.revertedWithCustomError(vault, "ExceedsDailySpendCap");

      // Advance 24h to refresh cap, then queue 70 tUSD8
      await time.increase(ONE_DAY + 1);
      const tx2 = await vault
        .connect(sessionAgent)
        .executeScopedEscrow(ethers.id("hitl-rep-drop"), sellerGood.address, tusd8Addr, usd("70"), ONE_HOUR, "ipfs://h3");
      const r2 = await tx2.wait();
      const reqId2 = r2!.logs
        .map((l) => {
          try {
            return vault.interface.parseLog(l);
          } catch {
            return null;
          }
        })
        .find((p) => p?.name === "PaymentQueuedForApproval")!.args.requestId as string;

      // Seller reputation drops below 70 while queued
      await reputationRegistry
        .connect(stranger)
        .giveFeedback(1n, -100n, 0, "slashed", "tUSD8", ethers.id("slash-1"), "ipfs://slash");

      await expect(vault.connect(owner).approveQueuedPayment(reqId2)).to.be.revertedWithCustomError(
        vault,
        "CounterpartyReputationTooLow"
      );

      // Re-boost reputation and verify 24h TTL expiry on queued request
      await reputationRegistry
        .connect(owner)
        .giveFeedback(1n, 100n, 0, "recovered", "tUSD8", ethers.id("rec-1"), "ipfs://rec");
      await reputationRegistry
        .connect(owner)
        .giveFeedback(1n, 100n, 0, "recovered", "tUSD8", ethers.id("rec-2"), "ipfs://rec");

      await time.increase(ONE_DAY + 1);
      await expect(vault.connect(owner).approveQueuedPayment(reqId2)).to.be.revertedWithCustomError(
        vault,
        "ApprovalRequestExpired"
      );
    });

    it("MED-01 Fix: enforces Soulbound ERC-8004 identity NFTs (blocks transfers)", async function () {
      const { identityRegistry, sellerGood, stranger } = await loadFixture(deployProtocolFixture);

      await expect(
        identityRegistry.connect(sellerGood).transferFrom(sellerGood.address, stranger.address, 1n)
      ).to.be.revertedWithCustomError(identityRegistry, "AgentIdentitySoulbound");
    });

    it("MED-02 Fix: measures ORACLE_TIMEOUT from submission time on long-duration deals", async function () {
      const { vault, escrowCourt, tusd8, owner, sessionAgent, sellerGood } =
        await loadFixture(deployProtocolFixture);

      const tusd8Addr = await tusd8.getAddress();
      const expiresAt = BigInt(await time.latest()) + BigInt(ONE_DAY * 10);
      await vault
        .connect(owner)
        .configureSessionKey(sessionAgent.address, usd("50"), usd("100"), 0, expiresAt, 70, true);

      const salt = ethers.id("long-deal-early-submit");
      const sevenDays = 7 * ONE_DAY;
      await vault
        .connect(sessionAgent)
        .executeScopedEscrow(salt, sellerGood.address, tusd8Addr, usd("30"), sevenDays, "ipfs://7d");

      const dealId = await escrowCourt.computeDealId(await vault.getAddress(), salt);
      await escrowCourt.connect(sellerGood).submitDeliverable(dealId, "ipfs://early-work");

      // Only 24h + 1s after submission (well before the 7-day deal deadline), buyer can recover funds
      await time.increase(ONE_DAY + 1);
      await expect(escrowCourt.connect(owner).claimExpiredRefund(dealId)).to.changeTokenBalances(
        tusd8,
        [escrowCourt, vault],
        [-usd("30"), usd("30")]
      );
    });

    it("MED-03 Fix: preserves spentInCurrentWindow when reconfiguring session key mid-day", async function () {
      const { vault, tusd8, owner, sessionAgent, sellerGood } =
        await loadFixture(deployProtocolFixture);

      const tusd8Addr = await tusd8.getAddress();
      const expiresAt = BigInt(await time.latest()) + BigInt(ONE_DAY * 2);
      await vault
        .connect(owner)
        .configureSessionKey(sessionAgent.address, usd("50"), usd("100"), 0, expiresAt, 70, true);

      await vault
        .connect(sessionAgent)
        .executeScopedEscrow(ethers.id("midday-1"), sellerGood.address, tusd8Addr, usd("40"), ONE_HOUR, "ipfs://m1");
      expect(await vault.getRemainingDailyAllowance(sessionAgent.address)).to.equal(usd("60"));

      // Reconfigure threshold/minScore mid-day -> spent (40) must be preserved
      await vault
        .connect(owner)
        .configureSessionKey(sessionAgent.address, usd("50"), usd("100"), usd("25"), expiresAt, 80, true);
      expect(await vault.getRemainingDailyAllowance(sessionAgent.address)).to.equal(usd("60"));
    });

    it("LOW-01 Fix: enforces two-step ownership transfer across core contracts", async function () {
      const { vault, escrowCourt, owner, stranger, sellerGood } =
        await loadFixture(deployProtocolFixture);

      await expect(vault.connect(owner).transferOwnership(stranger.address))
        .to.emit(vault, "OwnershipTransferStarted")
        .withArgs(owner.address, stranger.address);

      await expect(vault.connect(sellerGood).acceptOwnership()).to.be.revertedWithCustomError(
        vault,
        "OnlyPendingOwner"
      );

      await expect(vault.connect(stranger).acceptOwnership())
        .to.emit(vault, "OwnershipTransferred")
        .withArgs(owner.address, stranger.address);
      expect(await vault.owner()).to.equal(stranger.address);

      await escrowCourt.connect(owner).transferOwnership(stranger.address);
      await escrowCourt.connect(stranger).acceptOwnership();
      expect(await escrowCourt.owner()).to.equal(stranger.address);
    });
  });
});

