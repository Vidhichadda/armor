import { checkComplianceHandler } from "./tools/checkCompliance.js";
import { analyzePoolRiskHandler } from "./tools/analyzePoolRisk.js";
import { generateInvoiceHandler } from "./tools/generateInvoice.js";
import { logError } from "./pharosRpc.js";

/**
 * Centrally registered list of tool schemas offered by the Pharos Autonomous Guardian server.
 */
export const TOOLS = [
  {
    name: "check_compliance",
    description: "Queries the PharosComplianceRegistry smart contract on Chain ID 688689 to verify if a user wallet has RWA compliance clearance for a specific asset class.",
    inputSchema: {
      type: "object" as const,
      properties: {
        wallet_address: {
          type: "string",
          description: "The target EVM wallet address to verify compliance for (e.g., '0x123...').",
          pattern: "^0x[a-fA-F0-9]{40}$"
        },
        asset_identifier: {
          type: "string",
          description: "The asset class code to check (e.g., 'US_DEBT', 'REAL_ESTATE', 'COMMODITIES')."
        }
      },
      required: ["wallet_address", "asset_identifier"]
    }
  },
  {
    name: "analyze_pool_risk",
    description: "Fetches on-chain bytecode of a contract and executes a simulated telemetry analysis against known exploit patterns, vulnerabilities, backdoors, and reentrancy loops.",
    inputSchema: {
      type: "object" as const,
      properties: {
        contract_address: {
          type: "string",
          description: "The EVM address of the smart contract/pool to analyze (e.g., '0x123...').",
          pattern: "^0x[a-fA-F0-9]{40}$"
        }
      },
      required: ["contract_address"]
    }
  },
  {
    name: "generate_x402_invoice",
    description: "Generates a structured JSON payload conforming to Anvita Flow's native HTTP 402 Pay-Per-Call schema to enable automated micro-payment settling for agent calls.",
    inputSchema: {
      type: "object" as const,
      properties: {
        amount_in_pros: {
          type: "string",
          description: "The micro-payment fee amount represented in PROS token units (e.g., '0.05')."
        },
        developer_wallet: {
          type: "string",
          description: "The developer's EVM wallet address to receive settling payments.",
          pattern: "^0x[a-fA-F0-9]{40}$"
        }
      },
      required: ["amount_in_pros", "developer_wallet"]
    }
  }
];

/**
 * Global router executing tools and packaging output into LLM-friendly formats.
 * Prevents the application from crashing by capturing all runtime exceptions.
 */
export async function handleToolCall(name: string, args: any) {
  try {
    switch (name) {
      case "check_compliance":
        return await checkComplianceHandler(args);
      case "analyze_pool_risk":
        return await analyzePoolRiskHandler(args);
      case "generate_x402_invoice":
        return await generateInvoiceHandler(args);
      default:
        throw new Error(`Tool not found: ${name}`);
    }
  } catch (error: any) {
    logError(`Error executing tool: ${name}`, error);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            status: "error",
            message: error.message || String(error)
          }, null, 2)
        }
      ],
      isError: true
    };
  }
}
