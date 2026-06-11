import { ethers } from "ethers";
import * as dotenv from "dotenv";

// Load environment variables
dotenv.config();

const CHAIN_ID = 688689;

/**
 * Audit-Ready: Standardizes logging to stderr (console.error) to ensure process.stdout
 * remains completely clean for JSON-RPC messages used in standard MCP communication.
 */
export function logError(message: string, error?: any) {
  console.error(`[PharosRpc ERROR] ${message}:`, error ? (error.stack || error.message || error) : "");
}

export function logInfo(message: string) {
  console.error(`[PharosRpc INFO] ${message}`);
}

let activeProvider: ethers.JsonRpcProvider | null = null;
let activeRpcUrl: string | null = null;

/**
 * Automatically resolves and caches a responsive JSON-RPC provider.
 * Cycles through the primary RPC and fallback endpoints with a strict 5-second timeout.
 */
export async function getProvider(): Promise<ethers.JsonRpcProvider> {
  if (activeProvider) {
    return activeProvider;
  }

  // Compile full list of fallback RPC nodes
  const rpcs: string[] = [
    process.env.PHAROS_RPC_URL || "https://atlantic.dplabs-internal.com"
  ];

  if (process.env.PHAROS_FALLBACK_RPCS) {
    const fallbacks = process.env.PHAROS_FALLBACK_RPCS.split(",").map(r => r.trim()).filter(Boolean);
    rpcs.push(...fallbacks);
  }

  // Try to connect to each node sequentially
  for (const rpc of rpcs) {
    try {
      logInfo(`Probing node endpoint: ${rpc}`);
      
      // Audit-Ready: Ethers v6 FetchRequest timeout prevents connection hang exploits.
      const req = new ethers.FetchRequest(rpc);
      req.timeout = 5000; // 5 seconds limit

      const network = ethers.Network.from(CHAIN_ID);
      const testProvider = new ethers.JsonRpcProvider(req, network, {
        staticNetwork: true,
      });

      // Verification check: Perform a lightweight block number query
      await testProvider.getBlockNumber();

      logInfo(`Node endpoint verified responsive: ${rpc}`);
      activeProvider = testProvider;
      activeRpcUrl = rpc;
      return activeProvider;
    } catch (error: any) {
      logError(`Node probe failed or timed out for: ${rpc}`, error);
    }
  }

  throw new Error("Fatal: All configured Pharos Atlantic RPC endpoints are unresponsive or timed out.");
}

/**
 * Resets the provider cache if a node failure is detected at runtime.
 */
export function markProviderFailed() {
  if (activeRpcUrl) {
    logError(`Active node ${activeRpcUrl} failed at runtime. Invalidating cache for failover.`);
  }
  activeProvider = null;
  activeRpcUrl = null;
}

/**
 * Queries the PharosComplianceRegistry smart contract status for a given wallet address and asset class.
 * Auto-retry structure fallback automatically routes to alternative nodes.
 */
export async function queryComplianceRegistry(
  walletAddress: string,
  assetClassString: string
): Promise<{ isCleared: boolean; restrictionCode: string; verificationTimestamp: bigint }> {
  const registryAddress = process.env.COMPLIANCE_REGISTRY_ADDRESS;
  if (!registryAddress || registryAddress === "0x0000000000000000000000000000000000000000") {
    const errorMsg = "COMPLIANCE_REGISTRY_ADDRESS is not configured in env";
    logError(errorMsg);
    throw new Error(errorMsg);
  }

  if (!ethers.isAddress(walletAddress)) {
    throw new Error(`Invalid EVM address format: ${walletAddress}`);
  }

  // Audit-Ready: Compute bytes32 keccak256 hash of the asset class string.
  // Using bytes32 instead of raw string in smart contracts maximizes lookup speed and optimizes gas.
  const assetClassBytes32 = ethers.id(assetClassString);

  const abi = [
    "function checkWalletStatus(address user, bytes32 assetClass) external view returns (bool isCleared, string memory restrictionCode, uint256 verificationTimestamp)"
  ];

  try {
    const prov = await getProvider();
    const contract = new ethers.Contract(registryAddress, abi, prov);
    const result = await contract.checkWalletStatus(walletAddress, assetClassBytes32);
    return {
      isCleared: result[0],
      restrictionCode: result[1],
      verificationTimestamp: result[2]
    };
  } catch (error: any) {
    logError(`Registry query failed on primary provider, clearing cache and retrying`, error);
    markProviderFailed();
    
    // Failover: Retry once with next available node
    try {
      const prov = await getProvider();
      const contract = new ethers.Contract(registryAddress, abi, prov);
      const result = await contract.checkWalletStatus(walletAddress, assetClassBytes32);
      return {
        isCleared: result[0],
        restrictionCode: result[1],
        verificationTimestamp: result[2]
      };
    } catch (retryError: any) {
      logError(`Failover query failed for user=${walletAddress} asset=${assetClassString}`, retryError);
      throw retryError;
    }
  }
}

/**
 * Retrieves bytecode from the Pharos Atlantic RPC endpoint with failover recovery.
 */
export async function getContractBytecode(contractAddress: string): Promise<string> {
  if (!ethers.isAddress(contractAddress)) {
    throw new Error(`Invalid EVM address format for bytecode retrieval: ${contractAddress}`);
  }

  try {
    const prov = await getProvider();
    const code = await prov.getCode(contractAddress);
    return code;
  } catch (error: any) {
    logError(`Bytecode fetch failed on primary provider, clearing cache and retrying`, error);
    markProviderFailed();

    try {
      const prov = await getProvider();
      const code = await prov.getCode(contractAddress);
      return code;
    } catch (retryError: any) {
      logError(`Failover bytecode query failed for address=${contractAddress}`, retryError);
      throw retryError;
    }
  }
}
