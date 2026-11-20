// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./ERC8004Registries.sol";

/**
 * @title AevumEscrowCourt
 * @notice Conditional tUSD8 SLA Escrow supporting Vault-backed funding, Fee-On-Transfer
 *         balance-delta safety, AI Validator settlement (direct or EIP-712 signature),
 *         configurable protocol fees, atomic ERC-8004 logging, and trustless timeout refunds.
 */
contract AevumEscrowCourt is ReentrancyGuard, EIP712 {
    using SafeERC20 for IERC20;

    enum DealState {
        None,
        Funded,
        Submitted,
        ResolvedSuccess,
        ResolvedRefund,
        ExpiredRefund
    }

    struct EscrowDeal {
        bytes32 dealId;
        address buyer;
        address refundRecipient;
        address seller;
        address token;
        uint256 amount;
        uint256 protocolFee;
        uint256 deadline;
        uint64 submittedAt;
        DealState state;
        string criteriaHash;
        string deliverableHash;
        bytes32 verdictHash;
        uint8 judgeScore;
    }

    uint256 public constant ORACLE_TIMEOUT = 24 hours;
    uint256 public constant MAX_DURATION = 365 days;
    uint16 public constant MAX_FEE_BPS = 500; // 5.00%

    bytes32 public constant VERDICT_TYPEHASH =
        keccak256(
            "Verdict(bytes32 dealId,bool approved,uint8 score,bytes32 verdictHash,bytes32 reasoningURIHash,uint256 sigDeadline)"
        );

    AevumIdentityRegistry public immutable identityRegistry;
    AevumReputationRegistry public immutable reputationRegistry;
    AevumValidationRegistry public immutable validationRegistry;

    address public owner;
    address public pendingOwner;
    address public aiValidator;
    address public feeRecipient;
    uint16 public protocolFeeBps;

    mapping(bytes32 => EscrowDeal) private _deals;

    error OnlyOwner();
    error OnlyPendingOwner();
    error InvalidAddress();
    error FeeTooHigh();
    error DealAlreadyExists();
    error DealNotFound();
    error InvalidSeller();
    error InvalidAmount();
    error InvalidDuration();
    error InvalidState();
    error OnlySeller();
    error DeadlinePassed();
    error InvalidDeliverable();
    error UnauthorizedValidator();
    error InvalidScore();
    error InvalidVerdictHash();
    error SignatureExpired();
    error InvalidValidatorSignature();
    error UnauthorizedRefundCaller();
    error DeadlineNotPassed();
    error OracleGracePeriodNotPassed();

    event EscrowCreated(
        bytes32 indexed dealId,
        address indexed buyer,
        address indexed seller,
        address refundRecipient,
        address token,
        uint256 amount,
        uint256 protocolFee,
        uint256 deadline,
        string criteriaHash
    );
    event DeliverableSubmitted(bytes32 indexed dealId, address indexed seller, string deliverableHash);
    event EscrowResolved(
        bytes32 indexed dealId,
        bool indexed approved,
        uint8 score,
        uint256 sellerPayout,
        uint256 protocolFee,
        bytes32 verdictHash,
        string reasoningURI
    );
    event EscrowRefunded(bytes32 indexed dealId, address indexed recipient, uint256 amount, string reason);
    event ValidatorUpdated(address indexed oldValidator, address indexed newValidator);
    event ProtocolFeeUpdated(uint16 newFeeBps, address indexed newFeeRecipient);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    constructor(
        address _identityRegistry,
        address _reputationRegistry,
        address _validationRegistry,
        address _aiValidator,
        address _feeRecipient,
        uint16 _protocolFeeBps
    ) EIP712("AevumEscrowCourt", "1") {
        if (
            _identityRegistry == address(0) ||
            _reputationRegistry == address(0) ||
            _validationRegistry == address(0) ||
            _aiValidator == address(0) ||
            _feeRecipient == address(0)
        ) {
            revert InvalidAddress();
        }
        if (_protocolFeeBps > MAX_FEE_BPS) revert FeeTooHigh();

        owner = msg.sender;
        identityRegistry = AevumIdentityRegistry(_identityRegistry);
        reputationRegistry = AevumReputationRegistry(_reputationRegistry);
        validationRegistry = AevumValidationRegistry(_validationRegistry);
        aiValidator = _aiValidator;
        feeRecipient = _feeRecipient;
        protocolFeeBps = _protocolFeeBps;
    }

    /**
     * @notice Computes front-running resistant dealId namespaced to chainId, contract, and funder.
     */
    function computeDealId(address funder, bytes32 dealSalt) public view returns (bytes32) {
        return keccak256(abi.encode(block.chainid, address(this), funder, dealSalt));
    }

    /**
     * @notice Creates and funds an escrow directly from the buyer's wallet.
     */
    function createEscrow(
        bytes32 dealSalt,
        address seller,
        address token,
        uint256 amount,
        uint256 durationSeconds,
        string calldata criteriaHash
    ) external nonReentrant returns (bytes32 dealId) {
        return _createEscrow(msg.sender, msg.sender, dealSalt, seller, token, amount, durationSeconds, criteriaHash);
    }

    /**
     * @notice Creates and funds an escrow on behalf of a buyer owner (used by AevumAgentVault).
     *         Refunds return directly to `msg.sender` (the Vault), while `buyerOwner` retains
     *         governance and reputation attribution.
     */
    function createEscrowFor(
        address buyerOwner,
        bytes32 dealSalt,
        address seller,
        address token,
        uint256 amount,
        uint256 durationSeconds,
        string calldata criteriaHash
    ) external nonReentrant returns (bytes32 dealId) {
        if (buyerOwner == address(0)) revert InvalidAddress();
        return _createEscrow(buyerOwner, msg.sender, dealSalt, seller, token, amount, durationSeconds, criteriaHash);
    }

    /**
     * @notice Allows the designated seller to submit work before the deadline.
     */
    function submitDeliverable(bytes32 dealId, string calldata deliverableHash) external {
        EscrowDeal storage deal = _deals[dealId];
        if (deal.state == DealState.None) revert DealNotFound();
        if (msg.sender != deal.seller) revert OnlySeller();
        if (deal.state != DealState.Funded) revert InvalidState();
        if (block.timestamp > deal.deadline) revert DeadlinePassed();
        if (bytes(deliverableHash).length == 0) revert InvalidDeliverable();

        deal.state = DealState.Submitted;
        deal.submittedAt = uint64(block.timestamp);
        deal.deliverableHash = deliverableHash;

        emit DeliverableSubmitted(dealId, msg.sender, deliverableHash);
    }

    /**
     * @notice Direct settlement called by the authorized AI Validator wallet.
     */
    function resolveEscrow(
        bytes32 dealId,
        bool approved,
        uint8 score,
        bytes32 verdictHash,
        string calldata reasoningURI
    ) external nonReentrant {
        if (msg.sender != aiValidator) revert UnauthorizedValidator();
        _resolve(dealId, approved, score, verdictHash, reasoningURI, msg.sender);
    }

    /**
     * @notice Meta-transaction settlement using an EIP-712 typed signature from the AI Validator.
     */
    function resolveEscrowWithSig(
        bytes32 dealId,
        bool approved,
        uint8 score,
        bytes32 verdictHash,
        string calldata reasoningURI,
        uint256 sigDeadline,
        bytes calldata signature
    ) external nonReentrant {
        if (block.timestamp > sigDeadline) revert SignatureExpired();

        bytes32 structHash = keccak256(
            abi.encode(
                VERDICT_TYPEHASH,
                dealId,
                approved,
                score,
                verdictHash,
                keccak256(bytes(reasoningURI)),
                sigDeadline
            )
        );
        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(digest, signature);
        if (signer != aiValidator) revert InvalidValidatorSignature();

        _resolve(dealId, approved, score, verdictHash, reasoningURI, signer);
    }

    /**
     * @notice Trustless refund if the seller misses the deadline, or if the AI Validator
     *         fails to resolve within `ORACLE_TIMEOUT` (24 hours) after the deadline.
     */
    function claimExpiredRefund(bytes32 dealId) external nonReentrant {
        EscrowDeal storage deal = _deals[dealId];
        if (deal.state == DealState.None) revert DealNotFound();
        if (msg.sender != deal.buyer && msg.sender != deal.refundRecipient) {
            revert UnauthorizedRefundCaller();
        }

        if (deal.state == DealState.Funded) {
            if (block.timestamp <= deal.deadline) revert DeadlineNotPassed();
        } else if (deal.state == DealState.Submitted) {
            if (block.timestamp <= uint256(deal.submittedAt) + ORACLE_TIMEOUT) {
                revert OracleGracePeriodNotPassed();
            }
        } else {
            revert InvalidState();
        }

        deal.state = DealState.ExpiredRefund;
        IERC20(deal.token).safeTransfer(deal.refundRecipient, deal.amount);

        emit EscrowRefunded(dealId, deal.refundRecipient, deal.amount, "EXPIRED");
    }

    function updateValidator(address newValidator) external onlyOwner {
        if (newValidator == address(0)) revert InvalidAddress();
        address old = aiValidator;
        aiValidator = newValidator;
        emit ValidatorUpdated(old, newValidator);
    }

    function updateProtocolFee(uint16 newFeeBps, address newFeeRecipient) external onlyOwner {
        if (newFeeBps > MAX_FEE_BPS) revert FeeTooHigh();
        if (newFeeRecipient == address(0)) revert InvalidAddress();
        protocolFeeBps = newFeeBps;
        feeRecipient = newFeeRecipient;
        emit ProtocolFeeUpdated(newFeeBps, newFeeRecipient);
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

    function getDeal(bytes32 dealId) external view returns (EscrowDeal memory) {
        return _deals[dealId];
    }

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    function _createEscrow(
        address buyerOwner,
        address refundRecipient,
        bytes32 dealSalt,
        address seller,
        address token,
        uint256 amount,
        uint256 durationSeconds,
        string calldata criteriaHash
    ) internal returns (bytes32 dealId) {
        if (seller == address(0) || seller == buyerOwner || seller == refundRecipient) {
            revert InvalidSeller();
        }
        if (token == address(0)) revert InvalidAddress();
        if (amount == 0) revert InvalidAmount();
        if (durationSeconds == 0 || durationSeconds > MAX_DURATION) revert InvalidDuration();

        dealId = computeDealId(msg.sender, dealSalt);
        if (_deals[dealId].state != DealState.None) revert DealAlreadyExists();

        uint256 balanceBefore = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        uint256 actualReceived = IERC20(token).balanceOf(address(this)) - balanceBefore;
        if (actualReceived == 0) revert InvalidAmount();

        uint256 fee = (actualReceived * protocolFeeBps) / 10_000;
        uint256 deadline = block.timestamp + durationSeconds;

        _deals[dealId] = EscrowDeal({
            dealId: dealId,
            buyer: buyerOwner,
            refundRecipient: refundRecipient,
            seller: seller,
            token: token,
            amount: actualReceived,
            protocolFee: fee,
            deadline: deadline,
            submittedAt: 0,
            state: DealState.Funded,
            criteriaHash: criteriaHash,
            deliverableHash: "",
            verdictHash: bytes32(0),
            judgeScore: 0
        });

        emit EscrowCreated(
            dealId,
            buyerOwner,
            seller,
            refundRecipient,
            token,
            actualReceived,
            fee,
            deadline,
            criteriaHash
        );
    }

    function _resolve(
        bytes32 dealId,
        bool approved,
        uint8 score,
        bytes32 verdictHash,
        string calldata reasoningURI,
        address validatorUsed
    ) internal {
        EscrowDeal storage deal = _deals[dealId];
        if (deal.state == DealState.None) revert DealNotFound();
        if (deal.state != DealState.Submitted) revert InvalidState();
        if (score > 100) revert InvalidScore();
        if (verdictHash == bytes32(0)) revert InvalidVerdictHash();

        deal.verdictHash = verdictHash;
        deal.judgeScore = score;

        uint256 sellerPayout = 0;
        uint256 feePaid = 0;

        if (approved) {
            deal.state = DealState.ResolvedSuccess;
            feePaid = deal.protocolFee;
            sellerPayout = deal.amount - feePaid;

            if (feePaid > 0) {
                IERC20(deal.token).safeTransfer(feeRecipient, feePaid);
            }
            IERC20(deal.token).safeTransfer(deal.seller, sellerPayout);
        } else {
            deal.state = DealState.ResolvedRefund;
            IERC20(deal.token).safeTransfer(deal.refundRecipient, deal.amount);
            emit EscrowRefunded(dealId, deal.refundRecipient, deal.amount, "REJECTED_BY_AI_JUDGE");
        }

        uint256 sellerAgentId = identityRegistry.primaryAgentIdOf(deal.seller);
        validationRegistry.recordDirectValidation(
            sellerAgentId,
            validatorUsed,
            score,
            verdictHash,
            deal.criteriaHash,
            reasoningURI
        );
        reputationRegistry.recordAddressFeedback(
            deal.seller,
            deal.buyer,
            score,
            approved ? "escrow-pass" : "escrow-fail",
            "tUSD8",
            dealId,
            reasoningURI
        );

        emit EscrowResolved(dealId, approved, score, sellerPayout, feePaid, verdictHash, reasoningURI);
    }
}

