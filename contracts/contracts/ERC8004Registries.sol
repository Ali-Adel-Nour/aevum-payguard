// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "./interfaces/IERC8004Registries.sol";

/**
 * @title AevumIdentityRegistry
 * @notice ERC-8004 compliant ERC-721 identity registry storing portable AgentCards.
 */
contract AevumIdentityRegistry is ERC721URIStorage, IAevumIdentityRegistry {
    uint256 private _nextAgentId = 1;
    mapping(address => uint256) public override primaryAgentIdOf;

    error EmptyAgentURI();
    error UnauthorizedAgentOperator();
    error AgentDoesNotExist(uint256 agentId);
    error AgentIdentitySoulbound();

    constructor() ERC721("Aevum Agent Identity", "AEVUM-ID") {}

    /**
     * @inheritdoc IAevumIdentityRegistry
     */
    function register(string calldata agentURI) external override returns (uint256 agentId) {
        if (bytes(agentURI).length == 0) revert EmptyAgentURI();

        agentId = _nextAgentId++;
        _safeMint(msg.sender, agentId);
        _setTokenURI(agentId, agentURI);

        if (primaryAgentIdOf[msg.sender] == 0) {
            primaryAgentIdOf[msg.sender] = agentId;
        }

        emit AgentRegistered(agentId, msg.sender, agentURI);
    }

    /**
     * @notice Sets the caller's primary agent NFT ID for address-based lookups.
     */
    function setPrimaryAgentId(uint256 agentId) external {
        address owner = _ownerOf(agentId);
        if (owner == address(0)) revert AgentDoesNotExist(agentId);
        if (owner != msg.sender) revert UnauthorizedAgentOperator();

        primaryAgentIdOf[msg.sender] = agentId;
    }

    /**
     * @inheritdoc IAevumIdentityRegistry
     */
    function setAgentURI(uint256 agentId, string calldata agentURI) external override {
        if (_ownerOf(agentId) == address(0)) revert AgentDoesNotExist(agentId);
        if (!isAuthorizedOrOwner(msg.sender, agentId)) revert UnauthorizedAgentOperator();
        if (bytes(agentURI).length == 0) revert EmptyAgentURI();

        _setTokenURI(agentId, agentURI);
        emit AgentURIUpdated(agentId, agentURI);
    }

    /**
     * @inheritdoc IAevumIdentityRegistry
     */
    function isAuthorizedOrOwner(address spender, uint256 agentId) public view override returns (bool) {
        address owner = _ownerOf(agentId);
        return owner != address(0) && _isAuthorized(owner, spender, agentId);
    }

    function _update(address to, uint256 tokenId, address auth) internal override returns (address) {
        address currentOwner = _ownerOf(tokenId);
        if (currentOwner != address(0) && to != address(0)) revert AgentIdentitySoulbound();

        address previousOwner = super._update(to, tokenId, auth);

        if (previousOwner != address(0) && primaryAgentIdOf[previousOwner] == tokenId) {
            primaryAgentIdOf[previousOwner] = 0;
        }
        if (to != address(0) && primaryAgentIdOf[to] == 0) {
            primaryAgentIdOf[to] = tokenId;
        }

        return previousOwner;
    }
}

/**
 * @title AevumReputationRegistry
 * @notice ERC-8004 compliant Reputation Registry supporting structured feedback,
 *         self-feedback prevention, revocation, and normalized score queries.
 */
contract AevumReputationRegistry is IAevumReputationRegistry {
    struct ReputationSummary {
        int256 totalNormalizedScore;
        uint256 activeCount;
        uint256 positiveCount;
        uint256 negativeCount;
    }

    struct AddressReputation {
        int256 totalScore;
        uint256 count;
    }

    IAevumIdentityRegistry public immutable identityRegistry;
    address public owner;
    address public pendingOwner;
    mapping(address => bool) public authorizedCourts;

    mapping(uint256 => ReputationSummary) private _summaries;
    mapping(uint256 => mapping(address => Feedback[])) private _feedbacks;
    mapping(uint256 => mapping(address => mapping(uint256 => bool))) private _feedbackIsPositive;
    mapping(uint256 => mapping(address => mapping(uint256 => address))) private _feedbackTargetAddress;
    mapping(address => AddressReputation) private _addressStats;

    error InvalidRegistry();
    error OnlyOwner();
    error OnlyPendingOwner();
    error InvalidAddress();
    error UnauthorizedCourt();
    error SelfFeedbackForbidden();
    error InvalidAgentId();
    error InvalidFeedbackIndex();
    error FeedbackAlreadyRevoked();
    error InvalidScoreValue();

    event AuthorizedCourtUpdated(address indexed court, bool allowed);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    constructor(address _identityRegistry) {
        if (_identityRegistry == address(0)) revert InvalidRegistry();
        owner = msg.sender;
        identityRegistry = IAevumIdentityRegistry(_identityRegistry);
    }

    function setAuthorizedCourt(address court, bool allowed) external onlyOwner {
        if (court == address(0)) revert InvalidAddress();
        authorizedCourts[court] = allowed;
        emit AuthorizedCourtUpdated(court, allowed);
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
     * @inheritdoc IAevumReputationRegistry
     */
    function giveFeedback(
        uint256 agentId,
        int128 value,
        uint8 valueDecimals,
        string calldata tag1,
        string calldata tag2,
        bytes32 dealId,
        string calldata /* feedbackURI */
    ) external override {
        address agentOwner = identityRegistry.ownerOf(agentId);
        if (agentOwner == msg.sender) revert SelfFeedbackForbidden();

        int256 normalized = _normalizeScore(value, valueDecimals);
        bool isPositive = normalized > 0;

        _recordAgentFeedback(
            agentId,
            agentOwner,
            msg.sender,
            value,
            valueDecimals,
            normalized,
            isPositive,
            tag1,
            tag2,
            dealId
        );
    }

    /**
     * @notice Records 0-100 escrow settlement feedback for a seller address (and its primary agentId if registered).
     */
    function recordAddressFeedback(
        address agentAddress,
        address reviewer,
        uint8 score,
        string calldata tag1,
        string calldata tag2,
        bytes32 dealId,
        string calldata /* feedbackURI */
    ) external {
        if (!authorizedCourts[msg.sender]) revert UnauthorizedCourt();
        if (agentAddress == address(0) || reviewer == address(0)) revert InvalidAgentId();
        if (agentAddress == reviewer || agentAddress == msg.sender) revert SelfFeedbackForbidden();
        if (score > 100) revert InvalidScoreValue();

        int256 signedScore = int256(uint256(score));
        bool isPositive = score >= 50;

        uint256 agentId = identityRegistry.primaryAgentIdOf(agentAddress);
        if (agentId != 0) {
            _recordAgentFeedback(
                agentId,
                agentAddress,
                reviewer,
                int128(uint128(score)),
                0,
                signedScore,
                isPositive,
                tag1,
                tag2,
                dealId
            );
        } else {
            _addressStats[agentAddress].totalScore += signedScore;
            _addressStats[agentAddress].count += 1;
            emit FeedbackGiven(0, reviewer, int128(uint128(score)), tag1, tag2, dealId);
        }
    }

    /**
     * @inheritdoc IAevumReputationRegistry
     */
    function revokeFeedback(uint256 agentId, uint256 feedbackIndex) external override {
        Feedback[] storage list = _feedbacks[agentId][msg.sender];
        if (feedbackIndex >= list.length) revert InvalidFeedbackIndex();

        Feedback storage fb = list[feedbackIndex];
        if (fb.isRevoked) revert FeedbackAlreadyRevoked();

        fb.isRevoked = true;
        int256 normalized = _normalizeScore(fb.value, fb.valueDecimals);

        ReputationSummary storage summary = _summaries[agentId];
        summary.totalNormalizedScore -= normalized;
        summary.activeCount -= 1;

        if (_feedbackIsPositive[agentId][msg.sender][feedbackIndex]) {
            summary.positiveCount -= 1;
        } else {
            summary.negativeCount -= 1;
        }

        address targetAddr = _feedbackTargetAddress[agentId][msg.sender][feedbackIndex];
        if (targetAddr != address(0) && _addressStats[targetAddr].count > 0) {
            _addressStats[targetAddr].totalScore -= normalized;
            _addressStats[targetAddr].count -= 1;
        }

        emit FeedbackRevoked(agentId, msg.sender, feedbackIndex);
    }

    /**
     * @inheritdoc IAevumReputationRegistry
     */
    function getSummary(uint256 agentId)
        external
        view
        override
        returns (
            int128 averageScore,
            uint256 count,
            uint256 positiveCount,
            uint256 negativeCount
        )
    {
        ReputationSummary storage summary = _summaries[agentId];
        count = summary.activeCount;
        positiveCount = summary.positiveCount;
        negativeCount = summary.negativeCount;
        if (count > 0) {
            averageScore = int128(summary.totalNormalizedScore / int256(count));
        }
    }

    /**
     * @inheritdoc IAevumReputationRegistry
     */
    function getScoreByAddress(address agent) external view override returns (uint8 score, uint256 totalFeedback) {
        AddressReputation storage stats = _addressStats[agent];
        if (stats.count > 0) {
            int256 avg = stats.totalScore / int256(stats.count);
            return (_clampScore(avg), stats.count);
        }

        uint256 agentId = identityRegistry.primaryAgentIdOf(agent);
        if (agentId != 0 && _summaries[agentId].activeCount > 0) {
            ReputationSummary storage summary = _summaries[agentId];
            int256 avg = summary.totalNormalizedScore / int256(summary.activeCount);
            return (_clampScore(avg), summary.activeCount);
        }

        return (0, 0);
    }

    /**
     * @inheritdoc IAevumReputationRegistry
     */
    function readFeedback(
        uint256 agentId,
        address client,
        uint256 index
    ) external view override returns (Feedback memory) {
        Feedback[] storage list = _feedbacks[agentId][client];
        if (index >= list.length) revert InvalidFeedbackIndex();
        return list[index];
    }

    function _recordAgentFeedback(
        uint256 agentId,
        address targetAddress,
        address reviewer,
        int128 rawValue,
        uint8 valueDecimals,
        int256 normalized,
        bool isPositive,
        string calldata tag1,
        string calldata tag2,
        bytes32 dealId
    ) internal {
        uint256 idx = _feedbacks[agentId][reviewer].length;
        _feedbacks[agentId][reviewer].push(
            Feedback({
                value: rawValue,
                valueDecimals: valueDecimals,
                isRevoked: false,
                tag1: tag1,
                tag2: tag2,
                dealId: dealId
            })
        );
        _feedbackIsPositive[agentId][reviewer][idx] = isPositive;
        _feedbackTargetAddress[agentId][reviewer][idx] = targetAddress;

        ReputationSummary storage summary = _summaries[agentId];
        summary.totalNormalizedScore += normalized;
        summary.activeCount += 1;
        if (isPositive) {
            summary.positiveCount += 1;
        } else {
            summary.negativeCount += 1;
        }

        _addressStats[targetAddress].totalScore += normalized;
        _addressStats[targetAddress].count += 1;

        emit FeedbackGiven(agentId, reviewer, rawValue, tag1, tag2, dealId);
    }

    function _normalizeScore(int128 value, uint8 valueDecimals) internal pure returns (int256) {
        if (valueDecimals > 18) revert InvalidScoreValue();
        int256 divisor = int256(10 ** valueDecimals);
        int256 normalized = int256(value) / divisor;
        if (normalized < -100 || normalized > 100) revert InvalidScoreValue();
        return normalized;
    }

    function _clampScore(int256 avg) internal pure returns (uint8) {
        if (avg <= 0) return 0;
        if (avg >= 100) return 100;
        return uint8(uint256(avg));
    }
}

/**
 * @title AevumValidationRegistry
 * @notice ERC-8004 compliant Validation Registry storing AI Judge verdict hashes & proofs.
 */
contract AevumValidationRegistry is IAevumValidationRegistry {
    uint256 private _nextRequestId = 1;
    address public owner;
    address public pendingOwner;
    mapping(address => bool) public authorizedRecorders;
    mapping(uint256 => ValidationRecord) private _validations;

    error OnlyOwner();
    error OnlyPendingOwner();
    error InvalidAddress();
    error InvalidValidator();
    error ValidationNotFound(uint256 requestId);
    error OnlyDesignatedValidator();
    error ValidationAlreadyCompleted();
    error InvalidValidationScore();

    event AuthorizedRecorderUpdated(address indexed recorder, bool allowed);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function setAuthorizedRecorder(address recorder, bool allowed) external onlyOwner {
        if (recorder == address(0)) revert InvalidAddress();
        authorizedRecorders[recorder] = allowed;
        emit AuthorizedRecorderUpdated(recorder, allowed);
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
     * @inheritdoc IAevumValidationRegistry
     */
    function requestValidation(
        uint256 agentId,
        address validator,
        string calldata taskDataURI
    ) external override returns (uint256 requestId) {
        if (validator == address(0)) revert InvalidValidator();

        requestId = _nextRequestId++;
        _validations[requestId] = ValidationRecord({
            agentId: agentId,
            validator: validator,
            score: 0,
            verdictHash: bytes32(0),
            taskDataURI: taskDataURI,
            evidenceURI: "",
            completed: false
        });

        emit ValidationRequested(agentId, validator, requestId, taskDataURI);
    }

    /**
     * @inheritdoc IAevumValidationRegistry
     */
    function completeValidation(
        uint256 requestId,
        uint8 score,
        bytes32 verdictHash,
        string calldata evidenceURI
    ) external override {
        ValidationRecord storage rec = _validations[requestId];
        if (rec.validator == address(0)) revert ValidationNotFound(requestId);
        if (msg.sender != rec.validator) revert OnlyDesignatedValidator();
        if (rec.completed) revert ValidationAlreadyCompleted();
        if (score > 100) revert InvalidValidationScore();

        rec.score = score;
        rec.verdictHash = verdictHash;
        rec.evidenceURI = evidenceURI;
        rec.completed = true;

        emit ValidationCompleted(rec.agentId, rec.validator, requestId, score, verdictHash, evidenceURI);
    }

    /**
     * @inheritdoc IAevumValidationRegistry
     */
    function recordDirectValidation(
        uint256 agentId,
        address validator,
        uint8 score,
        bytes32 verdictHash,
        string calldata taskDataURI,
        string calldata evidenceURI
    ) external override returns (uint256 requestId) {
        if (msg.sender != validator && !authorizedRecorders[msg.sender]) {
            revert OnlyDesignatedValidator();
        }
        if (validator == address(0)) revert InvalidValidator();
        if (score > 100) revert InvalidValidationScore();

        requestId = _nextRequestId++;
        _validations[requestId] = ValidationRecord({
            agentId: agentId,
            validator: validator,
            score: score,
            verdictHash: verdictHash,
            taskDataURI: taskDataURI,
            evidenceURI: evidenceURI,
            completed: true
        });

        emit ValidationRequested(agentId, validator, requestId, taskDataURI);
        emit ValidationCompleted(agentId, validator, requestId, score, verdictHash, evidenceURI);
    }

    /**
     * @inheritdoc IAevumValidationRegistry
     */
    function getValidation(uint256 requestId) external view override returns (ValidationRecord memory) {
        if (_validations[requestId].validator == address(0)) revert ValidationNotFound(requestId);
        return _validations[requestId];
    }
}

