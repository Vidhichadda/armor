// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/PharosComplianceRegistry.sol";
import "../src/SafeExecutionGate.sol";

/**
 * @title DeployScript
 * @notice Forge script to deploy the compliance registry and safe execution gate on Pharos L1.
 */
contract DeployScript is Script {
    function run() external {
        // Audit-Ready: Fetch deployer keys securely from environment variables instead of hardcoding.
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address admin = vm.addr(deployerPrivateKey);

        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy Compliance Registry with admin capabilities.
        PharosComplianceRegistry registry = new PharosComplianceRegistry(admin);

        // 2. Deploy Safe Execution Gate
        // Set limits: Max transaction native value = 5 ETH, Max gas price = 150 Gwei, Cooldown = 30 seconds.
        uint256 maxTxValue = 5 * 1e18; // 5 ETH
        uint256 maxGasPrice = 150 * 1e9; // 150 Gwei
        uint256 cooldown = 30; // 30 seconds

        SafeExecutionGate gate = new SafeExecutionGate(
            admin,
            maxTxValue,
            maxGasPrice,
            cooldown
        );

        // 3. Pre-whitelist the Compliance Registry as an executable target for agents
        gate.setTargetWhitelistStatus(address(registry), true);

        vm.stopBroadcast();
    }
}
