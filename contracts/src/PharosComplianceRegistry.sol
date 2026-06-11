// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title PharosComplianceRegistry
 * @notice On-chain registry tracking RWA compliance profiles for automated agent validation.
 * @dev Employs AccessControl to restrict write permissions to designated administrator roles.
 *      Optimized to use bytes32 keys for gas efficiency instead of dynamic strings.
 */
contract PharosComplianceRegistry is AccessControl {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    struct ComplianceProfile {
        bool isCleared;
        string restrictionCode;
        uint256 verificationTimestamp;
    }

    // Mapping of user address => RWA Asset Class identifier hash => compliance details
    // Audit-Ready: Mapping using bytes32 is highly gas-optimized compared to string storage lookups.
    mapping(address => mapping(bytes32 => ComplianceProfile)) private _complianceProfiles;

    // Events
    event ComplianceUpdated(
        address indexed user,
        bytes32 indexed assetClass,
        bool isCleared,
        string restrictionCode,
        uint256 timestamp
    );

    /**
     * @notice Constructor initializes deployer with DEFAULT_ADMIN_ROLE and ADMIN_ROLE.
     * @param admin Initial administrator wallet.
     */
    constructor(address admin) {
        // Audit-Ready: Access control initialization uses internal grant rules, preventing uninitialized state vulnerability.
        require(admin != address(0), "Admin address cannot be zero");
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
    }

    /**
     * @notice Updates the compliance profile of a user wallet for a specific RWA asset class.
     * @param user The address of the user or agent.
     * @param assetClass Keccak256 hash or bytes32 representation of the asset class (e.g., keccak256("US_DEBT")).
     * @param isCleared Boolean indicating if the user is cleared to trade or transact in the asset class.
     * @param restrictionCode Code string explaining any restrictions or clearance levels (e.g., "KYC_PASS", "US_ONLY", "NONE").
     */
    function setComplianceStatus(
        address user,
        bytes32 assetClass,
        bool isCleared,
        string memory restrictionCode
    ) public onlyRole(ADMIN_ROLE) {
        // Audit-Ready: Standard validation prevents dirty address write vulnerabilities.
        require(user != address(0), "User address cannot be zero");
        require(assetClass != bytes32(0), "Asset class cannot be empty");

        _complianceProfiles[user][assetClass] = ComplianceProfile({
            isCleared: isCleared,
            restrictionCode: restrictionCode,
            verificationTimestamp: block.timestamp
        });

        // Audit-Ready: Emitting indexable events facilitates off-chain telemetry tracking and telemetry audits.
        emit ComplianceUpdated(user, assetClass, isCleared, restrictionCode, block.timestamp);
    }

    /**
     * @notice Updates compliance profiles for multiple users and asset classes in a single batch transaction.
     * @dev Optimizes network overhead and gas costs during bulk onboarding of agent wallets.
     */
    function setComplianceStatusBatch(
        address[] calldata users,
        bytes32[] calldata assetClasses,
        bool[] calldata isClearances,
        string[] calldata restrictionCodes
    ) external onlyRole(ADMIN_ROLE) {
        // Audit-Ready: Length constraints prevent out-of-bounds array operations and index out-of-sync writes.
        require(users.length == assetClasses.length, "Length mismatch: users/assetClasses");
        require(users.length == isClearances.length, "Length mismatch: users/isClearances");
        require(users.length == restrictionCodes.length, "Length mismatch: users/restrictionCodes");

        for (uint256 i = 0; i < users.length; i++) {
            setComplianceStatus(users[i], assetClasses[i], isClearances[i], restrictionCodes[i]);
        }
    }

    /**
     * @notice Optimization query checking wallet status.
     * @param user The address of the user or agent.
     * @param assetClass Bytes32 representation of the RWA class.
     * @return isCleared Whether the wallet is verified.
     * @return restrictionCode Code denoting clearance status or constraints.
     * @return verificationTimestamp The block timestamp when the profile was last modified.
     */
    function checkWalletStatus(address user, bytes32 assetClass)
        external
        view
        returns (
            bool isCleared,
            string memory restrictionCode,
            uint256 verificationTimestamp
        )
    {
        // Audit-Ready: View function operates only on storage reads. Avoids state manipulation/reentrancy risks.
        ComplianceProfile memory profile = _complianceProfiles[user][assetClass];
        return (profile.isCleared, profile.restrictionCode, profile.verificationTimestamp);
    }
}
