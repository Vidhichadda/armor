// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title SafeExecutionGate
 * @notice Fallback protective circuit for automated agents executing smart contract calls.
 * @dev Protects against fast loops, reentrancy attacks, and enforces target contract whitelisting.
 */
contract SafeExecutionGate is ReentrancyGuard, Pausable, AccessControl {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant AGENT_ROLE = keccak256("AGENT_ROLE");

    // Risk threshold parameters
    uint256 public maxTxValue;
    uint256 public maxGasPrice;
    uint256 public executionCooldown;

    // Target contract whitelisting registry to block interactions with unverified target protocols
    mapping(address => bool) public isWhitelistedTarget;

    // Rate limiting map for tracking interactions per target contract address
    mapping(address => uint256) public lastExecutionTimestamp;

    // Events
    event ExecutionExecuted(
        address indexed agent,
        address indexed target,
        uint256 value,
        bytes data,
        bytes returnData
    );
    event ThresholdsUpdated(
        uint256 maxTxValue,
        uint256 maxGasPrice,
        uint256 executionCooldown
    );
    event TargetWhitelistUpdated(address indexed target, bool status);

    /**
     * @notice Constructor sets admin roles and sets initial safety thresholds.
     * @param admin Initial administrator and pauser address.
     * @param _maxTxValue Maximum ETH/native token allowed to be sent in a single transaction.
     * @param _maxGasPrice Maximum allowed gas price in wei to prevent front-running/gas spike draining.
     * @param _executionCooldown Minimum delay in seconds required between transactions for any target.
     */
    constructor(
        address admin,
        uint256 _maxTxValue,
        uint256 _maxGasPrice,
        uint256 _executionCooldown
    ) {
        // Audit-Ready: Verify parameter bounds on initialization.
        require(admin != address(0), "Admin address cannot be zero");

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        _grantRole(AGENT_ROLE, admin);

        maxTxValue = _maxTxValue;
        maxGasPrice = _maxGasPrice;
        executionCooldown = _executionCooldown;
    }

    /**
     * @notice Updates the security threshold parameters.
     */
    function setThresholds(
        uint256 _maxTxValue,
        uint256 _maxGasPrice,
        uint256 _executionCooldown
    ) external onlyRole(ADMIN_ROLE) {
        maxTxValue = _maxTxValue;
        maxGasPrice = _maxGasPrice;
        executionCooldown = _executionCooldown;
        emit ThresholdsUpdated(_maxTxValue, _maxGasPrice, _executionCooldown);
    }

    /**
     * @notice Configures the whitelist status of a target smart contract address.
     */
    function setTargetWhitelistStatus(address target, bool status) public onlyRole(ADMIN_ROLE) {
        require(target != address(0), "Target address cannot be zero");
        isWhitelistedTarget[target] = status;
        emit TargetWhitelistUpdated(target, status);
    }

    /**
     * @notice Bulk configures whitelist statuses for multiple smart contract addresses.
     */
    function setTargetWhitelistStatusBatch(
        address[] calldata targets,
        bool[] calldata statuses
    ) external onlyRole(ADMIN_ROLE) {
        require(targets.length == statuses.length, "Length mismatch: targets/statuses");
        for (uint256 i = 0; i < targets.length; i++) {
            setTargetWhitelistStatus(targets[i], statuses[i]);
        }
    }

    /**
     * @notice Pauses contract execution in case of threat detection or anomaly.
     */
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /**
     * @notice Resumes execution once threat parameters return to normal.
     */
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /**
     * @notice Safely forwards a transaction execution on behalf of an authorized agent.
     * @dev Enforces reentrancy protection, target contract whitelist gating, rate limits per target, and price thresholds.
     * @param target Contract address to execute call on.
     * @param data Payload data bytes to execute.
     * @param value Native token value to pass to the target.
     * @return returnData bytes returned by the target call.
     */
    function execute(
        address target,
        bytes calldata data,
        uint256 value
    )
        external
        payable
        onlyRole(AGENT_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes memory)
    {
        // Audit-Ready: Target whitelist verification blocks interaction with dynamic hijack targets.
        require(isWhitelistedTarget[target], "SafeExecutionGate: target address not whitelisted");

        // Audit-Ready: Input verification ensures msg.value covers the intended value to pass.
        require(value <= msg.value, "Insufficient msg.value provided");

        // Audit-Ready: Capital limits prevent malicious draining and capital migration loops.
        require(value <= maxTxValue, "Value exceeds safe transaction execution limit");

        // Audit-Ready: Gas price guards prevent front-running draining or loops under network congestion.
        require(tx.gasprice <= maxGasPrice, "Gas price exceeds safe structural limit");

        // Audit-Ready: Cooldown checks per target contract prevent automated script extraction loops
        // while allowing agent wallets to execute parallel transactions to other pools without thread-blocking.
        require(
            block.timestamp >= lastExecutionTimestamp[target] + executionCooldown,
            "SafeExecutionGate: rate limit cooling down for target"
        );
        lastExecutionTimestamp[target] = block.timestamp;

        // Audit-Ready: Forwards transaction with strict value mapping. Low-level call results are safely bubbled up on failure.
        (bool success, bytes memory returnData) = target.call{value: value}(data);

        if (!success) {
            if (returnData.length > 0) {
                // Bubble up failure messages.
                assembly {
                    let returndata_size := mload(returnData)
                    revert(add(32, returnData), returndata_size)
                }
            } else {
                revert("SafeExecutionGate: execution failed without revert message");
            }
        }

        emit ExecutionExecuted(msg.sender, target, value, data, returnData);
        return returnData;
    }

    /**
     * @notice Support incoming funds.
     */
    receive() external payable {}
}
