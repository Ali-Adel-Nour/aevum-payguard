// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC721/IERC721.sol";

/**
 * @title IAevumIdentityRegistry
 * @notice ERC-8004 compliant portable AI Agent Identity Registry (ERC-721 AgentCard).
 */
interface IAevumIdentityRegistry is IERC721 {
    event AgentRegistered(uint256 indexed agentId, address indexed owner, string agentURI);
    event AgentURIUpdated(uint256 indexed agentId, string agentURI);

    /**
     * @notice Registers a new autonomous agent, minting an ERC-721 identity passport.
     * @param agentURI URI pointing to the agent's JSON AgentCard metadata.
     * @return agentId Newly minted agent token ID.
     */
    function register(string calldata agentURI) external returns (uint256 agentId);

    /**
     * @notice Updates the metadata URI for an existing agent identity.
     * @param agentId The agent's ERC-721 token ID.
     * @param agentURI New metadata URI.
     */
    function setAgentURI(uint256 agentId, string calldata agentURI) external;

    /**
     * @notice Returns true if spender owns or is approved to act for agentId.
     */
    function isAuthorizedOrOwner(address spender, uint256 agentId) external view returns (bool);

    /**
     * @notice Resolves the primary registered agentId for an address (0 if unregistered).
     */
    function primaryAgentIdOf(address owner) external view returns (uint256);
}

/**
 * @title IAevumReputationRegistry
 * @notice ERC-8004 compliant Reputation Registry for scoring autonomous agent interactions.
 */
interface IAevumReputationRegistry {
    struct Feedback {
        int128 value;
        uint8 valueDecimals;
        bool isRevoked;
        string tag1;
        string tag2;
        bytes32 dealId;
    }

    event FeedbackGiven(
        uint256 indexed agentId,
        address indexed client,
        int128 value,
        string tag1,
        string tag2,
        bytes32 indexed dealId
    );

    event FeedbackRevoked(uint256 indexed agentId, address indexed client, uint256 feedbackIndex);

    /**
     * @notice Submits structured reputation feedback for an agent.
     */
    function giveFeedback(
        uint256 agentId,
        int128 value,
        uint8 valueDecimals,
        string calldata tag1,
        string calldata tag2,
        bytes32 dealId,
        string calldata feedbackURI
    ) external;

    /**
     * @notice Revokes a previously submitted feedback item by index.
     */
    function revokeFeedback(uint256 agentId, uint256 feedbackIndex) external;

    /**
     * @notice Returns aggregated reputation metrics for an agentId.
     */
    function getSummary(uint256 agentId)
        external
        view
        returns (
            int128 averageScore,
            uint256 count,
            uint256 positiveCount,
            uint256 negativeCount
        );

    /**
     * @notice Convenience view resolving an agent address's normalized 0-100 score.
     */
    function getScoreByAddress(address agent) external view returns (uint8 score, uint256 totalFeedback);

    /**
     * @notice Reads an individual feedback record left by a client.
     */
    function readFeedback(
        uint256 agentId,
        address client,
        uint256 index
    ) external view returns (Feedback memory);
}

/**
 * @title IAevumValidationRegistry
 * @notice ERC-8004 compliant Validation Registry for recording AI Judge verdict proofs.
 */
interface IAevumValidationRegistry {
    struct ValidationRecord {
        uint256 agentId;
        address validator;
        uint8 score;
        bytes32 verdictHash;
        string taskDataURI;
        string evidenceURI;
        bool completed;
    }

    event ValidationRequested(
        uint256 indexed agentId,
        address indexed validator,
        uint256 indexed requestId,
        string taskDataURI
    );

    event ValidationCompleted(
        uint256 indexed agentId,
        address indexed validator,
        uint256 indexed requestId,
        uint8 score,
        bytes32 verdictHash,
        string evidenceURI
    );

    /**
     * @notice Requests an independent validation check from a designated validator.
     */
    function requestValidation(
        uint256 agentId,
        address validator,
        string calldata taskDataURI
    ) external returns (uint256 requestId);

    /**
     * @notice Completes a pending validation request with score, canonical hash, and evidence URI.
     */
    function completeValidation(
        uint256 requestId,
        uint8 score,
        bytes32 verdictHash,
        string calldata evidenceURI
    ) external;

    /**
     * @notice Atomically records a completed validation directly (used by authorized escrow courts).
     */
    function recordDirectValidation(
        uint256 agentId,
        address validator,
        uint8 score,
        bytes32 verdictHash,
        string calldata taskDataURI,
        string calldata evidenceURI
    ) external returns (uint256 requestId);

    /**
     * @notice Reads a validation record by requestId.
     */
    function getValidation(uint256 requestId) external view returns (ValidationRecord memory);
}

