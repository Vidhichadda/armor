import { getContractBytecode, logInfo, logError } from "../pharosRpc.js";

interface AnalyzePoolRiskArgs {
  contract_address: string;
}

interface ThreatMetric {
  vulnerabilityClass: string;
  detected: boolean;
  score: number;
  description: string;
}

interface Instruction {
  opcode: number;
  pc: number;
  name: string;
  pushData?: string;
}

/**
 * Disassembles raw EVM bytecode into an array of instructions.
 * Audit-Ready: Skips push data payload bytes sequentially, isolating actual executing instructions
 * from parameter addresses or hashes. This avoids false positives.
 */
function disassembleBytecode(bytecodeHex: string): Instruction[] {
  const instructions: Instruction[] = [];
  const hex = bytecodeHex.startsWith("0x") ? bytecodeHex.substring(2) : bytecodeHex;
  
  let i = 0;
  while (i < hex.length) {
    const pc = i / 2;
    const byteStr = hex.substring(i, i + 2);
    if (byteStr.length < 2) break; // incomplete byte
    
    const byte = parseInt(byteStr, 16);
    let name = "OTHER";
    let pushData: string | undefined;
    let skipBytes = 1;

    // Isolate executable opcodes of interest
    if (byte === 0xff) {
      name = "SELFDESTRUCT";
    } else if (byte === 0xf4) {
      name = "DELEGATECALL";
    } else if (byte === 0xf1) {
      name = "CALL";
    } else if (byte === 0xf2) {
      name = "CALLCODE";
    } else if (byte === 0xf5) {
      name = "CREATE2";
    } else if (byte === 0xf0) {
      name = "CREATE";
    } else if (byte === 0x00) {
      name = "STOP";
    } else if (byte === 0xfe) {
      name = "INVALID";
    } else if (byte >= 0x60 && byte <= 0x7f) {
      // PUSH1 (0x60) to PUSH32 (0x7f)
      const pushSize = byte - 0x60 + 1;
      name = `PUSH${pushSize}`;
      
      const dataStart = i + 2;
      const dataEnd = dataStart + pushSize * 2;
      pushData = hex.substring(dataStart, dataEnd);
      skipBytes = 1 + pushSize;
    }
    
    instructions.push({
      opcode: byte,
      pc,
      name,
      pushData
    });
    
    i += skipBytes * 2;
  }
  
  return instructions;
}

/**
 * Performs simulated bytecode risk assessment against known threat models.
 */
export async function analyzePoolRiskHandler(args: AnalyzePoolRiskArgs) {
  const { contract_address } = args;

  if (!contract_address) {
    throw new Error("Missing required parameter: contract_address");
  }

  logInfo(`Disassembling and analyzing bytecode risk for contract: ${contract_address}`);

  try {
    const bytecode = await getContractBytecode(contract_address);

    if (bytecode === "0x" || bytecode === "0x00" || bytecode === "") {
      const eoaReport = [
        `### Pharos L1 Bytecode Risk Analysis Report`,
        `- **Target Address:** \`${contract_address}\``,
        `- **Account Type:** Externally Owned Account (EOA)`,
        `- **Risk Assessment:** 🟢 LOW RISK`,
        `\n**Summary:** The address is not a smart contract. It contains no bytecode and represents an EOA. Standard wallet operations apply. Reentrancy and contract-level backdoors are not applicable.`
      ].join("\n");

      return {
        content: [
          {
            type: "text",
            text: eoaReport
          }
        ]
      };
    }

    // Disassemble EVM bytecode to isolate instruction stream
    const instructions = disassembleBytecode(bytecode);

    // Scan instructions safely
    const hasSelfDestruct = instructions.some(inst => inst.opcode === 0xff);
    const hasDelegateCall = instructions.some(inst => inst.opcode === 0xf4);
    const hasCall = instructions.some(inst => inst.opcode === 0xf1);
    
    // Check if mint(address,uint256) (selector: 40c10f19) function signature is pushed
    const hasMintSelector = instructions.some(inst => 
      inst.pushData ? inst.pushData.toLowerCase().includes("40c10f19") : false
    );

    // Check if transferOwnership(address) (selector: f2fde38b) signature is pushed
    const hasOwnershipSelector = instructions.some(inst => 
      inst.pushData ? inst.pushData.toLowerCase().includes("f2fde38b") : false
    );

    // Compile threat matrix report
    const threatMatrix: ThreatMetric[] = [
      {
        vulnerabilityClass: "Unchecked Self-Destruct",
        detected: hasSelfDestruct,
        score: hasSelfDestruct ? 9 : 0,
        description: "Opcode 'ff' (SELFDESTRUCT) detected in the execution stream. Allows absolute termination of contract and sudden drainage of funds."
      },
      {
        vulnerabilityClass: "Arbitrary Delegatecall Hijack",
        detected: hasDelegateCall,
        score: hasDelegateCall ? 8 : 0,
        description: "Opcode 'f4' (DELEGATECALL) detected in the execution stream. Permits external code libraries to run context-hijacked state changes."
      },
      {
        vulnerabilityClass: "Direct Asset Minting Control",
        detected: hasMintSelector,
        score: hasMintSelector ? 5 : 0,
        description: "Standard function signature for 'mint(address,uint256)' detected in push data registers. Indicates potential supply expansion controls."
      },
      {
        vulnerabilityClass: "Low-Level Call Execution",
        detected: hasCall,
        score: hasCall ? 3 : 0,
        description: "Opcode 'f1' (CALL) detected in the execution stream. Used for transferring assets or message passing; can lead to reentrancy if unshielded."
      }
    ];

    // Compute risk assessment
    const maxScore = Math.max(...threatMatrix.map(t => t.score));
    let overallRisk = "🟢 LOW RISK";
    let recommendation = "🛡️ SAFE: The contract bytecode does not contain high-risk execution patterns. Safe to interact.";

    if (maxScore >= 8) {
      overallRisk = "🔴 CRITICAL RISK / THREAT FOUND";
      recommendation = "🚫 BLOCK: Extremely unsafe. Detected critical logic hijack or self-destruct vectors. Do not execute transactions.";
    } else if (maxScore >= 5) {
      overallRisk = "🟡 MEDIUM RISK / WARNING";
      recommendation = "⚠️ WARN: Contract contains owner mint capability or low-level call execution. Proceed with caution and verify owner credentials.";
    }

    const tableRows = threatMatrix.map(t => 
      `| ${t.vulnerabilityClass} | ${t.detected ? "❌ YES" : "✅ NO"} | ${t.score} / 10 | ${t.description} |`
    ).join("\n");

    const report = [
      `### Pharos L1 Bytecode Risk Analysis Report`,
      `- **Target Contract Address:** \`${contract_address}\``,
      `- **Bytecode Size:** ${Math.round((bytecode.length - 2) / 2)} bytes`,
      `- **Total Instructions Parsed:** ${instructions.length}`,
      `- **Aggregate Risk Rating:** ${overallRisk} (Score: ${maxScore}/10)`,
      `- **Guardian Recommendation:** ${recommendation}`,
      `\n#### Disassembler Threat Matrix Analysis`,
      `| Vulnerability Class | Detected | Risk Score | Description |`,
      `| :--- | :--- | :--- | :--- |`,
      tableRows,
      `\n*Audit-Ready Check: Linear disassembler successfully bypassed push-address false-positives. Verified compliance selectors: mint (${hasMintSelector ? "YES" : "NO"}), ownership (${hasOwnershipSelector ? "YES" : "NO"}).*`
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
    logError(`analyzePoolRisk tool failed for contract=${contract_address}`, error);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            status: "error",
            contract: contract_address,
            message: error.message || String(error)
          }, null, 2)
        }
      ],
      isError: true
    };
  }
}
