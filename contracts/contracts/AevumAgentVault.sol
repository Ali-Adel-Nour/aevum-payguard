// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "./ERC8004Registries.sol";
import "./AevumEscrowCourt.sol";

/**
 * @title AevumAgentVault
 * @notice Smart Account Treasury & Scoped Session Key Policy Engine for autonomous agents.
 *         Enforces per-transaction spend limits, rolling 24-hour tUSD8 spend caps,
 *         session expiration, on-chain ERC-8004 seller reputation gating, a Human-in-the-Loop
 *         approval queue for high-value spends, and an instant Kill-Switch / Emergency Freeze.
 */
contract AevumAgentVault is ReentrancyGuard {
    using SafeERC20 for IERC20;

    enum ApprovalStatus {
        None,
        Pending,
        Approved,
        Rejected
    }

    struct SessionPolicy {
        uint128 maxAmountPerTx;
        uint128 dailySpendLimit;
        uint128 humanApprovalThreshold;
        uint128 spentInCurrentWindow;
        uint64 windowStart;
        uint64 expiresAt;
        uint8 minCounterpartyScore;
        bool restrictToEscrowOnly;
        bool active;
    }

    struct QueuedPaymentRequest {
        bytes32 requestId;
        address sessionKey;
        bytes32 dealSalt;
        address seller;
        address token;
        uint256 amount;
        uint256 durationSeconds;
        string criteriaHash;
        uint64 createdAt;
        ApprovalStatus status;
    }

    uint256 public constant APPROVAL_REQUEST_TTL = 24 hours;

    address public owner;
    address public pendingOwner;
    AevumReputationRegistry public immutable reputationRegistry;
    AevumEscrowCourt public immutable escrowCourt;
    bool public vaultFrozen;

    uint256 private _requestNonce;
    mapping(address => SessionPolicy) public sessionPolicies;
    mapping(bytes32 => QueuedPaymentRequest) private _queuedRequests;

    error OnlyOwner();
    error OnlyPendingOwner();
    error InvalidAddress();
    error InvalidAmount();
    error InvalidPolicy();
    error VaultIsFrozen();
    error SessionKeyInactive();
    error SessionKeyExpired();
    error ExceedsMaxPerTx(uint256 requested, uint256 maxAllowed);
    error ExceedsDailySpendCap(uint256 requested, uint256 remainingAllowance);
    error CounterpartyReputationTooLow(uint8 actualScore, uint8 requiredScore);
    error DirectPaymentNotAllowed();
    error RequestNotFound(bytes32 requestId);
    error RequestNotPending();
    error ApprovalRequestExpired();

    event VaultDeposited(address indexed depositor, address indexed token, uint256 amount);
    event VaultWithdrawn(address indexed to, address indexed token, uint256 amount);
    event SessionKeyConfigured(
        address indexed sessionKey,
        uint128 maxAmountPerTx,
        uint128 dailySpendLimit,
        uint128 humanApprovalThreshold,
        uint64 expiresAt,
        uint8 minCounterpartyScore,
        bool restrictToEscrowOnly
    );
    event SessionKeyRevoked(address indexed sessionKey);
    event VaultFreezeUpdated(bool frozen);
    event ScopedEscrowExecuted(
        address indexed sessionKey,
        bytes32 indexed dealId,
        address indexed seller,
        address token,
        uint256 amount
    );
    event ScopedDirectPaymentExecuted(
        address indexed sessionKey,
        address indexed seller,
        address token,
        uint256 amount,
        string paymentMemo
    );
    event PaymentQueuedForApproval(
        bytes32 indexed requestId,
        address indexed sessionKey,
        address indexed seller,
        address token,
        uint256 amount,
        bytes32 dealSalt
    );
    event QueuedPaymentApproved(bytes32 indexed requestId, bytes32 indexed dealId);
    event QueuedPaymentRejected(bytes32 indexed requestId, string reason);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    constructor(address _owner, address _reputationRegistry, address _escrowCourt) {
        if (_owner == address(0) || _reputationRegistry == address(0) || _escrowCourt == address(0)) {
            revert InvalidAddress();
        }
        owner = _owner;
        reputationRegistry = AevumReputationRegistry(_reputationRegistry);
        escrowCourt = AevumEscrowCourt(_escrowCourt);
    }

    /**
     * @notice Deposits tUSD8 (or any ERC-20) into the Smart Vault treasury.
     */
    function depositToken(address token, uint256 amount) external nonReentrant {
        if (token == address(0)) revert InvalidAddress();
        if (amount == 0) revert InvalidAmount();

        uint256 beforeBal = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        uint256 actualReceived = IERC20(token).balanceOf(address(this)) - beforeBal;
        if (actualReceived == 0) revert InvalidAmount();

        emit VaultDeposited(msg.sender, token, actualReceived);
    }

    /**
     * @notice Allows the human vault owner to withdraw funds at any time.
     */
    function withdrawToken(address token, uint256 amount, address to) external onlyOwner nonReentrant {
        if (token == address(0) || to == address(0)) revert InvalidAddress();
        if (amount == 0) revert InvalidAmount();

        IERC20(token).safeTransfer(to, amount);
        emit VaultWithdrawn(to, token, amount);
    }

    /**
     * @notice Issues or updates a least-privilege scoped session key for an AI agent.
     */
    function configureSessionKey(
        address sessionKey,
        uint128 maxAmountPerTx,
        uint128 dailySpendLimit,
        uint128 humanApprovalThreshold,
        uint64 expiresAt,
        uint8 minCounterpartyScore,
        bool restrictToEscrowOnly
    ) external onlyOwner {
        if (sessionKey == address(0) || sessionKey == owner) revert InvalidAddress();
        if (maxAmountPerTx == 0 || dailySpendLimit < maxAmountPerTx) revert InvalidPolicy();
        if (expiresAt <= block.timestamp) revert InvalidPolicy();
        if (minCounterpartyScore > 100) revert InvalidPolicy();

        SessionPolicy storage existing = sessionPolicies[sessionKey];
        bool windowStillActive = existing.windowStart != 0 &&
            block.timestamp < uint256(existing.windowStart) + 24 hours;
        uint128 preservedSpent = windowStillActive ? existing.spentInCurrentWindow : 0;
        uint64 preservedWindowStart = windowStillActive
            ? existing.windowStart
            : uint64(block.timestamp);

        sessionPolicies[sessionKey] = SessionPolicy({
            maxAmountPerTx: maxAmountPerTx,
            dailySpendLimit: dailySpendLimit,
            humanApprovalThreshold: humanApprovalThreshold,
            spentInCurrentWindow: preservedSpent,
            windowStart: preservedWindowStart,
            expiresAt: expiresAt,
            minCounterpartyScore: minCounterpartyScore,
            restrictToEscrowOnly: restrictToEscrowOnly,
            active: true
        });

        emit SessionKeyConfigured(
            sessionKey,
            maxAmountPerTx,
            dailySpendLimit,
            humanApprovalThreshold,
            expiresAt,
            minCounterpartyScore,
            restrictToEscrowOnly
        );
    }

    /**
     * @notice Instant Kill-Switch: revokes an agent's session key in a single transaction.
     */
    function revokeSessionKey(address sessionKey) external onlyOwner {
        sessionPolicies[sessionKey].active = false;
        emit SessionKeyRevoked(sessionKey);
    }

    /**
     * @notice Emergency circuit-breaker freezing or unfreezing all autonomous vault activity.
     */
    function setVaultFrozen(bool frozen) external onlyOwner {
        vaultFrozen = frozen;
        emit VaultFreezeUpdated(frozen);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert InvalidAddress();
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert OnlyPendingOwner();
        address previousOwner = owner;
        owner = pendingOwner;
        pendingOwner = address(0);
        emit OwnershipTransferred(previousOwner, owner);
    }

    /**
     * @notice Executes an escrow-protected tUSD8 payment from the agent's scoped session key.
     *         If the amount exceeds `humanApprovalThreshold` (when > 0), queues the request
     *         for explicit human review instead of spending immediately.
     */
    function executeScopedEscrow(
        bytes32 dealSalt,
        address seller,
        address token,
        uint256 amount,
        uint256 durationSeconds,
        string calldata criteriaHash
    ) external nonReentrant returns (bytes32 dealIdOrRequestId, bool queuedForApproval) {
        SessionPolicy storage policy = _validateSessionAndCounterparty(msg.sender, seller, token, amount);

        if (amount > policy.maxAmountPerTx) {
            revert ExceedsMaxPerTx(amount, policy.maxAmountPerTx);
        }

        if (policy.humanApprovalThreshold > 0 && amount > policy.humanApprovalThreshold) {
            _checkDailyAllowanceAvailable(policy, amount);

            bytes32 requestId = keccak256(
                abi.encode(block.chainid, address(this), msg.sender, dealSalt, _requestNonce++)
            );
            _queuedRequests[requestId] = QueuedPaymentRequest({
                requestId: requestId,
                sessionKey: msg.sender,
                dealSalt: dealSalt,
                seller: seller,
                token: token,
                amount: amount,
                durationSeconds: durationSeconds,
                criteriaHash: criteriaHash,
                createdAt: uint64(block.timestamp),
                status: ApprovalStatus.Pending
            });

            emit PaymentQueuedForApproval(requestId, msg.sender, seller, token, amount, dealSalt);
            return (requestId, true);
        }

        _consumeDailyAllowance(policy, amount);
        bytes32 dealId = _fundEscrow(dealSalt, seller, token, amount, durationSeconds, criteriaHash);

        emit ScopedEscrowExecuted(msg.sender, dealId, seller, token, amount);
        return (dealId, false);
    }

    /**
     * @notice Executes an instant micro-payment when `restrictToEscrowOnly` is false.
     */
    function executeScopedDirectPay(
        address seller,
        address token,
        uint256 amount,
        string calldata paymentMemo
    ) external nonReentrant {
        SessionPolicy storage policy = _validateSessionAndCounterparty(msg.sender, seller, token, amount);
        if (policy.restrictToEscrowOnly) revert DirectPaymentNotAllowed();
        if (amount > policy.maxAmountPerTx) {
            revert ExceedsMaxPerTx(amount, policy.maxAmountPerTx);
        }
        if (policy.humanApprovalThreshold > 0 && amount > policy.humanApprovalThreshold) {
            revert ExceedsMaxPerTx(amount, policy.humanApprovalThreshold);
        }

        _consumeDailyAllowance(policy, amount);
        IERC20(token).safeTransfer(seller, amount);

        emit ScopedDirectPaymentExecuted(msg.sender, seller, token, amount, paymentMemo);
    }

    /**
     * @notice Approves a queued high-value escrow payment as the human vault owner.
     */
    function approveQueuedPayment(bytes32 requestId) external onlyOwner nonReentrant returns (bytes32 dealId) {
        if (vaultFrozen) revert VaultIsFrozen();
        QueuedPaymentRequest storage req = _queuedRequests[requestId];
        if (req.status == ApprovalStatus.None) revert RequestNotFound(requestId);
        if (req.status != ApprovalStatus.Pending) revert RequestNotPending();
        if (block.timestamp > uint256(req.createdAt) + APPROVAL_REQUEST_TTL) {
            revert ApprovalRequestExpired();
        }

        SessionPolicy storage policy = sessionPolicies[req.sessionKey];
        if (policy.minCounterpartyScore > 0) {
            (uint8 sellerScore, ) = reputationRegistry.getScoreByAddress(req.seller);
            if (sellerScore < policy.minCounterpartyScore) {
                revert CounterpartyReputationTooLow(sellerScore, policy.minCounterpartyScore);
            }
        }

        _consumeDailyAllowance(policy, req.amount);

        req.status = ApprovalStatus.Approved;
        dealId = _fundEscrow(
            req.dealSalt,
            req.seller,
            req.token,
            req.amount,
            req.durationSeconds,
            req.criteriaHash
        );

        emit QueuedPaymentApproved(requestId, dealId);
    }

    /**
     * @notice Rejects a queued high-value escrow payment as the human vault owner.
     */
    function rejectQueuedPayment(bytes32 requestId, string calldata reason) external onlyOwner {
        QueuedPaymentRequest storage req = _queuedRequests[requestId];
        if (req.status == ApprovalStatus.None) revert RequestNotFound(requestId);
        if (req.status != ApprovalStatus.Pending) revert RequestNotPending();

        req.status = ApprovalStatus.Rejected;
        emit QueuedPaymentRejected(requestId, reason);
    }

    /**
     * @notice Returns the remaining tUSD8 spend capacity in the current 24h window.
     */
    function getRemainingDailyAllowance(address sessionKey) external view returns (uint256) {
        SessionPolicy storage policy = sessionPolicies[sessionKey];
        if (!policy.active || vaultFrozen || block.timestamp > policy.expiresAt) {
            return 0;
        }
        if (block.timestamp >= policy.windowStart + 24 hours) {
            return policy.dailySpendLimit;
        }
        return policy.dailySpendLimit > policy.spentInCurrentWindow
            ? policy.dailySpendLimit - policy.spentInCurrentWindow
            : 0;
    }

    function getQueuedRequest(bytes32 requestId) external view returns (QueuedPaymentRequest memory) {
        return _queuedRequests[requestId];
    }

    function _validateSessionAndCounterparty(
        address sessionKey,
        address seller,
        address token,
        uint256 amount
    ) internal view returns (SessionPolicy storage policy) {
        if (vaultFrozen) revert VaultIsFrozen();
        policy = sessionPolicies[sessionKey];
        if (!policy.active) revert SessionKeyInactive();
        if (block.timestamp > policy.expiresAt) revert SessionKeyExpired();
        if (amount == 0) revert InvalidAmount();
        if (token == address(0) || seller == address(0) || seller == address(this) || seller == owner) {
            revert InvalidAddress();
        }

        if (policy.minCounterpartyScore > 0) {
            (uint8 sellerScore, ) = reputationRegistry.getScoreByAddress(seller);
            if (sellerScore < policy.minCounterpartyScore) {
                revert CounterpartyReputationTooLow(sellerScore, policy.minCounterpartyScore);
            }
        }
    }

    function _checkDailyAllowanceAvailable(SessionPolicy storage policy, uint256 amount) internal view {
        uint256 remaining;
        if (block.timestamp >= uint256(policy.windowStart) + 24 hours) {
            remaining = policy.dailySpendLimit;
        } else {
            remaining = policy.dailySpendLimit > policy.spentInCurrentWindow
                ? policy.dailySpendLimit - policy.spentInCurrentWindow
                : 0;
        }
        if (amount > remaining) {
            revert ExceedsDailySpendCap(amount, remaining);
        }
    }

    function _consumeDailyAllowance(SessionPolicy storage policy, uint256 amount) internal {
        if (block.timestamp >= policy.windowStart + 24 hours) {
            policy.windowStart = uint64(block.timestamp);
            policy.spentInCurrentWindow = 0;
        }

        uint256 remaining = policy.dailySpendLimit > policy.spentInCurrentWindow
            ? policy.dailySpendLimit - policy.spentInCurrentWindow
            : 0;
        if (amount > remaining) {
            revert ExceedsDailySpendCap(amount, remaining);
        }

        policy.spentInCurrentWindow += uint128(amount);
    }

    function _fundEscrow(
        bytes32 dealSalt,
        address seller,
        address token,
        uint256 amount,
        uint256 durationSeconds,
        string memory criteriaHash
    ) internal returns (bytes32 dealId) {
        IERC20(token).forceApprove(address(escrowCourt), amount);
        dealId = escrowCourt.createEscrowFor(
            owner,
            dealSalt,
            seller,
            token,
            amount,
            durationSeconds,
            criteriaHash
        );
        IERC20(token).forceApprove(address(escrowCourt), 0);
    }
}

