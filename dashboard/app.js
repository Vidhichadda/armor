// ==========================================================================
// Pharos Autonomous Guardian (PAG) Dashboard JavaScript Logic
// ==========================================================================

document.addEventListener("DOMContentLoaded", () => {
  setupNavigation();
  setupComplianceTab();
  setupRiskTelemetryTab();
  setupInvoiceTab();
  setupExecutionGateTab();
});

// -------------------------------------------------------------
// 1. Navigation Panel Router
// -------------------------------------------------------------
function setupNavigation() {
  const navItems = document.querySelectorAll(".nav-item");
  const panels = document.querySelectorAll(".tab-panel");

  navItems.forEach(item => {
    item.addEventListener("click", (e) => {
      e.preventDefault();
      
      // Deactivate all navigation items
      navItems.forEach(nav => nav.classList.remove("active"));
      // Hide all panels
      panels.forEach(p => p.classList.remove("active"));

      // Activate clicked item
      item.classList.add("active");
      
      // Show corresponding panel
      const targetPanelId = "panel-" + item.id.replace("nav-", "");
      const targetPanel = document.getElementById(targetPanelId);
      if (targetPanel) {
        targetPanel.classList.add("active");
      }
    });
  });
}

// -------------------------------------------------------------
// 2. Compliance Registry Tab Interactive Logic
// -------------------------------------------------------------
function setupComplianceTab() {
  const queryBtn = document.getElementById("btn-query-compliance");
  const batchBtn = document.getElementById("btn-batch-compliance");
  const terminal = document.getElementById("compliance-terminal");
  const displayWallet = document.getElementById("display-wallet");
  const displayAsset = document.getElementById("display-asset");
  const displayCode = document.getElementById("display-code");
  const displayTime = document.getElementById("display-time");
  const badge = document.querySelector("#clearance-status-display .clearance-badge");
  const clearanceBox = document.getElementById("clearance-status-display");

  function appendLog(text, type = "info") {
    const p = document.createElement("p");
    p.className = `log-${type}`;
    p.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
    terminal.appendChild(p);
    terminal.scrollTop = terminal.scrollHeight;
  }

  queryBtn.addEventListener("click", () => {
    const wallet = document.getElementById("comp-wallet").value.trim();
    const asset = document.getElementById("comp-asset").value;

    if (!wallet.startsWith("0x") || wallet.length !== 43) {
      appendLog("Error: Invalid EVM address format entered.", "error");
      return;
    }

    appendLog(`Querying compliance registry for user ${wallet.substring(0, 10)}...`);
    appendLog(`Firing eth_call: checkWalletStatus(user, bytes32(${asset}))`);

    // Simulate RPC lag
    queryBtn.disabled = true;
    setTimeout(() => {
      queryBtn.disabled = false;
      const isCleared = !wallet.startsWith("0x0000"); // 0x0000 address represents blocked user in mock
      const restrictionCode = asset === "US_DEBT" ? "US_ONLY" : "NONE";

      displayWallet.textContent = `${wallet.substring(0, 8)}...${wallet.substring(wallet.length - 6)}`;
      displayAsset.textContent = asset;
      displayCode.textContent = restrictionCode;
      displayTime.textContent = new Date().toISOString();

      if (isCleared) {
        badge.textContent = "🟢 CLEARED";
        badge.className = "clearance-badge text-emerald";
        clearanceBox.className = "clearance-box cleared";
        appendLog(`[RPC SUCCESS] Clearance confirmed. Status: CLEARED. Code: ${restrictionCode}`, "success");
      } else {
        badge.textContent = "🔴 BLOCKED / NOT CLEARED";
        badge.className = "clearance-badge text-crimson";
        clearanceBox.className = "clearance-box blocked";
        appendLog(`[RPC WARNING] Access Denied. Wallet is flagged in registry restriction records.`, "warning");
      }
    }, 800);
  });

  batchBtn.addEventListener("click", () => {
    appendLog("Initiating bulk boarding simulation...");
    appendLog("Mapping users arrays and hashing asset keys to bytes32...");
    
    batchBtn.disabled = true;
    setTimeout(() => {
      appendLog("Broadcasting transaction batch: setComplianceStatusBatch()...");
    }, 500);

    setTimeout(() => {
      batchBtn.disabled = false;
      const txHash = "0x" + Array.from({length: 64}, () => Math.floor(Math.random()*16).toString(16)).join("");
      appendLog(`[L1 SUCCESS] Batch transaction finalized on block 1928491.`, "success");
      appendLog(`Tx Hash: ${txHash.substring(0, 24)}...`, "success");
    }, 1500);
  });
}

// -------------------------------------------------------------
// 3. EVM Bytecode Risk Telemetry Tab Logic
// -------------------------------------------------------------
function setupRiskTelemetryTab() {
  const analyzeBtn = document.getElementById("btn-analyze-bytecode");
  const addressInput = document.getElementById("telemetry-target");
  const dropdown = document.getElementById("prefill-targets");
  const stream = document.getElementById("assembly-stream");
  const streamStatus = document.getElementById("assembly-status");
  const scoreBadge = document.getElementById("risk-score-badge");
  const recommendation = document.getElementById("risk-recommendation");
  const matrixTbody = document.getElementById("threat-matrix-tbody");

  dropdown.addEventListener("change", () => {
    addressInput.value = dropdown.value;
  });

  // Basic mock opcodes list for stream animation
  const standardOpcodes = [
    "0000 PUSH1 0x80", "0002 PUSH1 0x40", "0004 MSTORE", "0005 CALLVALUE", 
    "0006 DUP1", "0007 ISZERO", "0008 PUSH2 0x0010", "000b JUMPI",
    "000c PUSH1 0x00", "000e DUP1", "000f REVERT", "0010 JUMPDEST", 
    "0011 POP", "0012 PUSH1 0x04", "0014 CALLDATASIZE", "0015 LT"
  ];

  const honeypotOpcodes = [
    "0000 PUSH1 0x80", "0002 PUSH1 0x40", "0004 MSTORE", "0005 DUP1",
    "0006 PUSH20 0x8da5cb5b3f4ba83d41e2a66589f1", "001b CALLER", "001c EQ",
    "001d JUMPI", "001e PUSH1 0x00", "0020 DELEGATECALL [CRITICAL RISK]",
    "0021 JUMPDEST", "0022 PUSH1 0x01", "0024 SELFDESTRUCT [CRITICAL RISK]"
  ];

  analyzeBtn.addEventListener("click", () => {
    const address = addressInput.value.trim();
    if (!ethersLikeAddressValid(address)) {
      alert("Invalid EVM address format.");
      return;
    }

    stream.innerHTML = "";
    streamStatus.textContent = "Scanning...";
    streamStatus.className = "badge badge-pending";
    analyzeBtn.disabled = true;

    const isHoneypot = address.toLowerCase() === "0xd128f118128fef88e8dcfcf77e0c45151525ffcf";
    const isEOA = address.toLowerCase() === "0x1234567890123456789012345678901234567890";
    
    const linesToPrint = isEOA ? ["0000 [EOA ACCOUNT DETECTED] CODE SIZE = 0 BYTES"] : (isHoneypot ? honeypotOpcodes : standardOpcodes);
    let index = 0;

    const interval = setInterval(() => {
      if (index < linesToPrint.length) {
        const div = document.createElement("div");
        div.className = "assembly-line";
        
        const lineText = linesToPrint[index];
        const spaceIdx = lineText.indexOf(" ");
        const pc = lineText.substring(0, spaceIdx);
        const op = lineText.substring(spaceIdx + 1);

        div.innerHTML = `<span class="pc">${pc}</span> <span class="op">${op}</span>`;
        
        if (op.includes("CRITICAL")) {
          div.classList.add("highlight-red");
        } else if (op.includes("DELEGATECALL") || op.includes("SELFDESTRUCT")) {
          div.classList.add("highlight-amber");
        } else if (op.includes("PUSH")) {
          div.classList.add("highlight-emerald");
        }

        stream.appendChild(div);
        stream.scrollTop = stream.scrollHeight;
        index++;
      } else {
        clearInterval(interval);
        streamStatus.textContent = "Completed";
        streamStatus.className = "badge badge-success";
        analyzeBtn.disabled = false;
        
        updateThreatMatrix(isHoneypot, isEOA);
      }
    }, 120);
  });

  function updateThreatMatrix(isHoneypot, isEOA) {
    if (isEOA) {
      scoreBadge.textContent = "🟢 LOW RISK (Score: 0/10)";
      scoreBadge.className = "risk-badge low";
      recommendation.textContent = "🛡️ SAFE: The address contains no bytecode and represents an Externally Owned Account. Standard transfer rules apply.";
      matrixTbody.innerHTML = `
        <tr><td>Unchecked Self-Destruct</td><td><span class="safe-badge">✅ NO</span></td><td>0 / 10</td></tr>
        <tr><td>Arbitrary Delegatecall Hijack</td><td><span class="safe-badge">✅ NO</span></td><td>0 / 10</td></tr>
        <tr><td>Direct Asset Minting Control</td><td><span class="safe-badge">✅ NO</span></td><td>0 / 10</td></tr>
        <tr><td>Low-Level Call Execution</td><td><span class="safe-badge">✅ NO</span></td><td>0 / 10</td></tr>
      `;
    } else if (isHoneypot) {
      scoreBadge.textContent = "🔴 CRITICAL RISK / THREAT FOUND (Score: 9/10)";
      scoreBadge.className = "risk-badge critical";
      recommendation.textContent = "🚫 BLOCK: Extremely unsafe. Linear EVM decompiler scan found executable SELFDESTRUCT (0xff) and DELEGATECALL (0xf4) opcodes outside push registers.";
      matrixTbody.innerHTML = `
        <tr><td>Unchecked Self-Destruct</td><td><span class="danger-badge">❌ YES</span></td><td>9 / 10</td></tr>
        <tr><td>Arbitrary Delegatecall Hijack</td><td><span class="danger-badge">❌ YES</span></td><td>8 / 10</td></tr>
        <tr><td>Direct Asset Minting Control</td><td><span class="safe-badge">✅ NO</span></td><td>0 / 10</td></tr>
        <tr><td>Low-Level Call Execution</td><td><span class="safe-badge">✅ NO</span></td><td>0 / 10</td></tr>
      `;
    } else {
      // Standard contract (with warning mint indicator)
      scoreBadge.textContent = "🟡 MEDIUM RISK / WARNING (Score: 5/10)";
      scoreBadge.className = "risk-badge medium";
      recommendation.textContent = "⚠️ WARN: Contract bytecode contains standard push registration for 'mint(address,uint256)' selector. Verify owner limits prior to execution.";
      matrixTbody.innerHTML = `
        <tr><td>Unchecked Self-Destruct</td><td><span class="safe-badge">✅ NO</span></td><td>0 / 10</td></tr>
        <tr><td>Arbitrary Delegatecall Hijack</td><td><span class="safe-badge">✅ NO</span></td><td>0 / 10</td></tr>
        <tr><td>Direct Asset Minting Control</td><td><span class="danger-badge">❌ YES</span></td><td>5 / 10</td></tr>
        <tr><td>Low-Level Call Execution</td><td><span class="danger-badge">❌ YES</span></td><td>3 / 10</td></tr>
      `;
    }
  }
}

// -------------------------------------------------------------
// 4. Anvita HTTP 402 Pay-Per-Call Invoice Tab Logic
// -------------------------------------------------------------
function setupInvoiceTab() {
  const genBtn = document.getElementById("btn-generate-invoice");
  const amountInput = document.getElementById("inv-amount");
  const recipientInput = document.getElementById("inv-recipient");
  const jsonOutput = document.getElementById("invoice-json-output");
  const copyBtn = document.getElementById("btn-copy-json");

  const receiptBig = document.querySelector(".receipt-big-amount");
  const receiptId = document.getElementById("receipt-id");
  const receiptSigner = document.getElementById("receipt-signer");
  const receiptSig = document.getElementById("receipt-sig");
  const receiptBadge = document.querySelector(".receipt-panel .badge");

  genBtn.addEventListener("click", () => {
    const amount = amountInput.value;
    const recipient = recipientInput.value.trim();

    if (!amount || isNaN(amount) || Number(amount) <= 0) {
      alert("Please enter a valid amount.");
      return;
    }

    if (!ethersLikeAddressValid(recipient)) {
      alert("Invalid recipient EVM address.");
      return;
    }

    genBtn.disabled = true;
    receiptBadge.textContent = "SIGNING...";
    receiptBadge.className = "badge badge-pending";

    setTimeout(() => {
      genBtn.disabled = false;
      receiptBadge.textContent = "VERIFIED / SIGNED";
      receiptBadge.className = "badge badge-success";

      receiptBig.textContent = `${amount} PROS`;
      
      const invId = "0x" + Array.from({length: 64}, () => Math.floor(Math.random()*16).toString(16)).join("");
      const sigHash = "0x" + Array.from({length: 130}, () => Math.floor(Math.random()*16).toString(16)).join("");
      const mockSigner = "0x90F8bf32434b2462423Ef4c40552b6F56C7D1bFe";

      receiptId.textContent = `${invId.substring(0, 10)}...`;
      receiptSigner.textContent = `${mockSigner.substring(0, 8)}...${mockSigner.substring(mockSigner.length - 6)}`;
      receiptSig.textContent = sigHash;

      // Compile final JSON response format
      const mockWei = (Number(amount) * 1e18).toString();
      const responseJson = {
        status: "PAYMENT_REQUIRED",
        statusCode: 402,
        paymentRequirement: {
          gateway: "Anvita Flow Pay-Per-Call Gateway",
          token: {
            symbol: "PROS",
            decimals: 18,
            amountRaw: mockWei,
            amountFormatted: amount
          },
          recipient: recipient,
          invoiceId: invId,
          timestamp: Math.floor(Date.now() / 1000)
        },
        signatureProof: {
          signer: mockSigner,
          signature: sigHash,
          isMockSignature: true,
          domain: {
            name: "Anvita Flow Pay Gateway",
            version: "1.0",
            chainId: 688689,
            verifyingContract: "0x8DA5cb5b3F4Ba83d41e2A66589f1000000000000"
          },
          types: {
            PaymentRequirement: [
              { name: "recipient", type: "address" },
              { name: "amountRaw", type: "uint256" },
              { name: "invoiceId", type: "bytes32" },
              { name: "timestamp", type: "uint256" }
            ]
          }
        }
      };

      jsonOutput.textContent = JSON.stringify(responseJson, null, 2);
    }, 600);
  });

  copyBtn.addEventListener("click", () => {
    navigator.clipboard.writeText(jsonOutput.textContent);
    copyBtn.textContent = "Copied!";
    setTimeout(() => {
      copyBtn.textContent = "Copy Code Block";
    }, 1500);
  });
}

// -------------------------------------------------------------
// 5. SafeExecutionGate Settings & Simulation Tab
// -------------------------------------------------------------
function setupExecutionGateTab() {
  const updateBtn = document.getElementById("btn-update-thresholds");
  const addWhitelistBtn = document.getElementById("btn-add-whitelist");
  const whitelistInput = document.getElementById("whitelist-address-input");
  const whitelistUl = document.getElementById("whitelist-ul");
  const simBtn = document.getElementById("btn-run-simulation");

  const gateMaxVal = document.getElementById("gate-max-val");
  const gateMaxGas = document.getElementById("gate-max-gas");
  const simTarget = document.getElementById("sim-target");
  const simVal = document.getElementById("sim-value");
  const simGas = document.getElementById("sim-gas");
  const verdictBox = document.getElementById("simulation-verdict");
  const verdictTitle = verdictBox.querySelector(".verdict-title");
  const verdictDesc = verdictBox.querySelector(".verdict-desc");

  // Track whitelisted array in memory
  let whitelistedAddresses = [
    "0x2fd664d510504faaacb12ad0f544996e12345678",
    "0x8DA5cb5b3F4Ba83d41e2A66589f1000000000000"
  ];

  updateBtn.addEventListener("click", () => {
    updateBtn.disabled = true;
    setTimeout(() => {
      updateBtn.disabled = false;
      alert(`SafeExecutionGate parameters updated on-chain!\nMax Value: ${gateMaxVal.value} ETH\nMax Gas: ${gateMaxGas.value} Gwei`);
    }, 500);
  });

  addWhitelistBtn.addEventListener("click", () => {
    const address = whitelistInput.value.trim().toLowerCase();
    if (!ethersLikeAddressValid(address)) {
      alert("Invalid EVM address.");
      return;
    }

    if (whitelistedAddresses.includes(address)) {
      alert("Address is already whitelisted.");
      return;
    }

    whitelistedAddresses.push(address);
    const li = document.createElement("li");
    li.className = "whitelist-item";
    li.innerHTML = `
      <span class="font-mono">${address}</span>
      <span class="badge badge-success">Whitelisted</span>
    `;
    whitelistUl.appendChild(li);
    whitelistInput.value = "";
  });

  simBtn.addEventListener("click", () => {
    const target = simTarget.value.trim().toLowerCase();
    const val = Number(simVal.value);
    const gas = Number(simGas.value);
    const maxVal = Number(gateMaxVal.value);
    const maxGas = Number(gateMaxGas.value);

    simBtn.disabled = true;
    verdictTitle.textContent = "Pre-flight checks executing...";
    verdictDesc.textContent = "Verifying target registry and execution parameters against limits...";
    verdictBox.className = "simulation-verdict-box idle";

    setTimeout(() => {
      simBtn.disabled = false;
      
      // Check target whitelisting
      if (!whitelistedAddresses.includes(target)) {
        verdictTitle.textContent = "🔴 TRANSACTION REVERTED";
        verdictDesc.textContent = "SafeExecutionGate circuit-breaker triggered: Destination target contract address is NOT whitelisted.";
        verdictBox.className = "simulation-verdict-box failed";
        return;
      }

      // Check capital limits
      if (val > maxVal) {
        verdictTitle.textContent = "🔴 TRANSACTION REVERTED";
        verdictDesc.textContent = `SafeExecutionGate: Transaction value (${val} ETH) exceeds current safety limit (${maxVal} ETH).`;
        verdictBox.className = "simulation-verdict-box failed";
        return;
      }

      // Check gas price limits
      if (gas > maxGas) {
        verdictTitle.textContent = "🔴 TRANSACTION REVERTED";
        verdictDesc.textContent = `SafeExecutionGate: Gas price (${gas} Gwei) exceeds the configured ceiling limit (${maxGas} Gwei).`;
        verdictBox.className = "simulation-verdict-box failed";
        return;
      }

      // All checks passed
      verdictTitle.textContent = "🟢 TRANSACTION CLEARED";
      verdictDesc.textContent = "Pre-flight check passed. Wallet destination and transaction limits verified safe. Forwarding call to L1 target.";
      verdictBox.className = "simulation-verdict-box cleared";
    }, 800);
  });
}

// Helper utility
function ethersLikeAddressValid(address) {
  return address.startsWith("0x") && address.length === 42;
}
