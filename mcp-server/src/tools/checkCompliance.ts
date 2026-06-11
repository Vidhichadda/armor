import { queryComplianceRegistry, logInfo, logError } from "../pharosRpc.js";

interface CheckComplianceArgs {
  wallet_address: string;
  asset_identifier: string;
}

/**
 * Handles compliance verification. Calls the PharosComplianceRegistry contract via RPC eth_call,
 * parses results, and presents them in a structured text layout for AI parsing.
 */
export async function checkComplianceHandler(args: CheckComplianceArgs) {
  const { wallet_address, asset_identifier } = args;

  // Audit-Ready: Standard validation checks on parameters prior to network call.
  if (!wallet_address || !asset_identifier) {
    throw new Error("Missing required parameters: wallet_address and asset_identifier");
  }

  logInfo(`Checking compliance status for wallet: ${wallet_address}, asset: ${asset_identifier}`);

  try {
    const { isCleared, restrictionCode, verificationTimestamp } = await queryComplianceRegistry(
      wallet_address,
      asset_identifier
    );

    const timeFormatted = verificationTimestamp > 0n 
      ? new Date(Number(verificationTimestamp) * 1000).toISOString()
      : "No Verification History";

    const report = [
      `### Pharos L1 Compliance Status Report`,
      `- **Wallet Address:** \`${wallet_address}\``,
      `- **RWA Asset Class:** \`${asset_identifier}\``,
      `- **Clearance Status:** ${isCleared ? "🟢 CLEARED (Active)" : "🔴 BLOCKED / NOT CLEARED"}`,
      `- **Restriction Code:** \`${restrictionCode || "NONE"}\``,
      `- **Last Verified At:** ${timeFormatted}`,
      `\n**Evaluation:** The agent wallet \`${wallet_address}\` is ${isCleared ? "authorized" : "unauthorized"} to interact with contracts tagged as \`${asset_identifier}\` under restriction rule \`${restrictionCode || "NONE"}\`.`
    ].join("\n");

    return {
      content: [
        {
          type: "text",
          text: report
        }
      ]
    };
  } catch (error: any) {
    logError(`checkCompliance tool failed for wallet=${wallet_address}`, error);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            status: "error",
            wallet: wallet_address,
            asset: asset_identifier,
            message: error.message || String(error)
          }, null, 2)
        }
      ],
      isError: true
    };
  }
}
