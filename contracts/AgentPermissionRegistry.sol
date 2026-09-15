// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title AgentPermissionRegistry
 * @notice Decentralized permission enforcement for autonomous AI agents.
 *         Stores per-agent, per-action permissions on-chain and emits
 *         tamper-proof audit events for every policy decision.
 */
contract AgentPermissionRegistry {
    address public owner;

    // agentId => actionType => permitted
    mapping(bytes32 => mapping(bytes32 => bool)) private permissions;

    // Track total decisions for analytics
    uint256 public totalDecisions;
    uint256 public totalDenials;

    event PermissionSet(
        bytes32 indexed agentId,
        bytes32 indexed actionType,
        bool permitted,
        uint256 timestamp
    );

    event DecisionLogged(
        bytes32 indexed agentId,
        bytes32 indexed actionType,
        bool permitted,
        bytes32 requestHash,
        uint256 timestamp,
        address caller
    );

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "AgentPermissionRegistry: Not authorized");
        _;
    }

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    /**
     * @notice Set or update a permission for an agent-action pair.
     * @param agentId    keccak256 hash of the agent identifier string
     * @param actionType keccak256 hash of the action type string
     * @param permitted  true = ALLOW, false = DENY
     */
    function setPermission(
        bytes32 agentId,
        bytes32 actionType,
        bool permitted
    ) external onlyOwner {
        permissions[agentId][actionType] = permitted;
        emit PermissionSet(agentId, actionType, permitted, block.timestamp);
    }

    /**
     * @notice Batch-set permissions for efficiency at setup time.
     */
    function batchSetPermissions(
        bytes32[] calldata agentIds,
        bytes32[] calldata actionTypes,
        bool[] calldata permittedFlags
    ) external onlyOwner {
        require(
            agentIds.length == actionTypes.length &&
            actionTypes.length == permittedFlags.length,
            "Array length mismatch"
        );
        for (uint256 i = 0; i < agentIds.length; i++) {
            permissions[agentIds[i]][actionTypes[i]] = permittedFlags[i];
            emit PermissionSet(agentIds[i], actionTypes[i], permittedFlags[i], block.timestamp);
        }
    }

    /**
     * @notice Read-only permission check (view call — no gas cost as eth_call).
     * @return True if the action is permitted for this agent.
     */
    function checkPermission(
        bytes32 agentId,
        bytes32 actionType
    ) external view returns (bool) {
        return permissions[agentId][actionType];
    }

    /**
     * @notice Write an immutable audit record of a policy decision.
     * @param requestHash keccak256(agentId, actionType, timestamp, payload)
     */
    function logDecision(
        bytes32 agentId,
        bytes32 actionType,
        bool permitted,
        bytes32 requestHash
    ) external {
        totalDecisions++;
        if (!permitted) totalDenials++;
        emit DecisionLogged(
            agentId,
            actionType,
            permitted,
            requestHash,
            block.timestamp,
            msg.sender
        );
    }

    /**
     * @notice Transfer contract ownership (admin key rotation).
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    /**
     * @notice Get analytics summary.
     */
    function getStats() external view returns (uint256 decisions, uint256 denials) {
        return (totalDecisions, totalDenials);
    }
}
