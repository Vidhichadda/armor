# Pharos Autonomous Guardian (PAG) Toolset

An enterprise-grade, security-hardened **Model Context Protocol (MCP)** server and Solidity smart contract suite designed for Phase 1 of the **Pharos x Anvita Flow AI Agent Carnival Hackathon**. 

PAG provides autonomous agent architectures with real-time on-chain risk telemetry, compliance clearance gating, and HTTP 402 Pay-Per-Call invoice generation on the **Pharos Atlantic Testnet** (Chain ID: `688689`).

---

## 🌎 System Architecture & Data Flow

```text
       +---------------------------------------------+
       |             Anvita Flow Gateway             |
       +----------------------+----------------------+
                              |
                              | (JSON-RPC via Stdio)
                              v
       +----------------------+----------------------+
       |   Pharos Autonomous Guardian MCP Server     | <----+ [.env config]
       +-------+--------------+--------------+-------+
               |              |              |
               |              |              +--------------------------+
               |              v                                         v
               |    +-------------------+                     +-------------------+
               |    | analyze_pool_risk |                     | generate_invoice  |
               |    |  - Fetch Bytecode |                     |  - Create 402 map |
               |    |  - Threat Matrix  |                     |  - Off-chain hash |
               |    +-------------------+                     +-------------------+
               v
    +------------------+
    | check_compliance |
    |  - Query registry|
    +----------+-------+
               |
               | (eth_call Queries / Telemetry Read)
               v
       +-------+-------------------------------------+
       |            Pharos L1 Atlantic Testnet       |
       |             RPC: dplabs-internal            |
       +---------------------------------------------+
```

---

## 🛠️ MCP Tool Schema Specifications

### 1. `check_compliance`
Fires an on-chain `eth_call` query to check a user wallet's RWA clearance details.

*   **Input Payload Schema:**
    ```json
    {
      "wallet_address": "0xd8da6bf26964af9d7eed9e03e53415d37aa96045",
      "asset_identifier": "US_DEBT"
    }
    ```

*   **Sample Output Content:**
    ```markdown
    ### Pharos L1 Compliance Status Report
    - **Wallet Address:** `0xd8da6bf26964af9d7eed9e03e53415d37aa96045`
    - **RWA Asset Class:** `US_DEBT`
    - **Clearance Status:** 🟢 CLEARED (Active)
    - **Restriction Code:** `US_ONLY`
    - **Last Verified At:** 2026-06-11T02:30:00.000Z

    **Evaluation:** The agent wallet `0xd8da6bf26964af9d7eed9e03e53415d37aa96045` is authorized to interact with contracts tagged as `US_DEBT` under restriction rule `US_ONLY`.
    ```

### 2. `analyze_pool_risk`
Inspects contract bytecode dynamically for malicious runtime instruction signatures, backdoors, and logic control hijacks.

*   **Input Payload Schema:**
    ```json
    {
      "contract_address": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
    }
    ```

*   **Sample Output Content:**
    ```markdown
    ### Pharos L1 Bytecode Risk Analysis Report
    - **Target Contract Address:** `0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48`
    - **Bytecode Size:** 1432 bytes
    - **Aggregate Risk Rating:** 🟡 MEDIUM RISK / WARNING (Score: 5/10)
    - **Guardian Recommendation:** ⚠️ WARN: Contract contains owner mint capability or low-level call execution. Proceed with caution and verify owner credentials.

    #### Threat Matrix Analysis
    | Vulnerability Class | Detected | Risk Score | Description |
    | :--- | :--- | :--- | :--- |
    | Unchecked Self-Destruct | ✅ NO | 0 / 10 | Opcode 'ff' (SELFDESTRUCT) detected. Allows absolute termination of contract and sudden drainage of funds. |
    | Arbitrary Delegatecall Hijack | ✅ NO | 0 / 10 | Opcode 'f4' (DELEGATECALL) detected. Permits external code libraries to run context-hijacked state changes. |
    | Direct Asset Minting Control | ❌ YES | 5 / 10 | Function signature for 'mint(address,uint256)' detected. Indicates potential supply expansion manipulation. |
    | Low-Level Call Execution | ❌ YES | 3 / 10 | Opcode 'f1' (CALL) detected. Used for transferring assets or message passing; can lead to reentrancy if unshielded. |
    ```

### 3. `generate_x402_invoice`
Compiles payment payloads satisfying the Anvita Flow HTTP 402 Pay-Per-Call specification for micro-billing.

*   **Input Payload Schema:**
    ```json
    {
      "amount_in_pros": "0.05",
      "developer_wallet": "0x90F8bf32434b2462423Ef4c40552b6F56C7D1bFe"
    }
    ```

*   **Sample Output Content:**
    ```json
    {
      "status": "PAYMENT_REQUIRED",
      "statusCode": 402,
      "paymentRequirement": {
        "gateway": "Anvita Flow Pay-Per-Call Gateway",
        "token": {
          "symbol": "PROS",
          "decimals": 18,
          "amountRaw": "50000000000000000",
          "amountFormatted": "0.05"
        },
        "recipient": "0x90F8bf32434b2462423Ef4c40552b6F56C7D1bFe",
        "invoiceId": "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "timestamp": 1783849500
      },
      "settlementPayload": {
        "targetChainId": 688689,
        "targetRPC": "https://atlantic.dplabs-internal.com",
        "dataPrimitive": {
          "action": "AGENT_CALL_SETTLEMENT",
          "params": {
            "recipient": "0x90F8bf32434b2462423Ef4c40552b6F56C7D1bFe",
            "amount": "50000000000000000",
            "trackingHash": "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
          }
        },
        "rawPayload": "eyJyZWNpcGllbnQiOiIweDkwRj...NkODVhNDcwIiwidGFyZ2V0Q2hhaW4iOjY4ODY4OX0="
      }
    }
    ```

---

## 🖥️ Interactive Simulation Dashboard Portal

To facilitate recording an impressive **video demo** for the hackathon submission, we have built a beautiful, high-fidelity **Simulation Dashboard Portal** inside the repository under [dashboard/index.html](file:///c:/Users/chadd/OneDrive/Desktop/armor/pharos-autonomous-guardian/dashboard/index.html).

The portal has dedicated interface cards for:
- **Registry Control**: Query clearance profiles or simulate onboarding batch setups.
- **Decompiler & Threat Scanners**: Run scrolling decompilations of EVM bytecodes and display interactive threat assessment matrices.
- **Invoice Receipts (402)**: Compile and sign pay-per-call JSON specifications with EIP-712 proofs.
- **Execution Gating**: Add whitelisted targets and simulate transaction limits.

### How to Run:
Double-click [index.html](file:///c:/Users/chadd/OneDrive/Desktop/armor/pharos-autonomous-guardian/dashboard/index.html) to launch the portal instantly in any modern web browser. No compilation or local web servers are required.

---

## 🚀 Environment Initialization & Setup

### Local Setup
1. Clone the repository and navigate into the `mcp-server` directory.
2. Initialize configuration parameters:
   ```bash
   cp ../.env.example .env
   ```
3. Update `.env` with your contract addresses:
   *   `COMPLIANCE_REGISTRY_ADDRESS`: The deployed registry address.
4. Install packages and compile TypeScript:
   ```bash
   npm install
   npm run build
   ```
5. Run the server locally:
   ```bash
   npm start
   ```

---

## 🐳 Alibaba Cloud Container Deployment

PAG compiles into a highly optimized, lightweight Docker container suitable for deployment on Alibaba Cloud Elastic Container Instance (ECI) or Container Service for Kubernetes (ACK).

### 1. Build and Tag Container
Run this command from the root directory containing the `Dockerfile`:
```bash
docker build -t registry.cn-hangzhou.aliyuncs.com/pharos-guardians/pag-mcp:latest .
```

### 2. ECI Execution Command
Deploy an elastic, serverless container instance on Alibaba Cloud specifying standard input-output pipe configurations:
```bash
aliyun eci CreateContainerGroup \
  --RegionId cn-hangzhou \
  --SecurityGroupId sg-bp1d... \
  --VSwitchId vsw-bp1... \
  --ContainerGroupName pharos-autonomous-guardian \
  --Container.1.Name pag-mcp \
  --Container.1.Image registry.cn-hangzhou.aliyuncs.com/pharos-guardians/pag-mcp:latest \
  --Container.1.Cpu 0.5 \
  --Container.1.Memory 1.0 \
  --Container.1.EnvironmentVar.1.Key PHAROS_RPC_URL \
  --Container.1.EnvironmentVar.1.Value "https://atlantic.dplabs-internal.com" \
  --Container.1.EnvironmentVar.2.Key COMPLIANCE_REGISTRY_ADDRESS \
  --Container.1.EnvironmentVar.2.Value "0x..."
```

---

## 🔒 Security Auditing Assertions

*   **Access Control**: Critical setter methods in `PharosComplianceRegistry` are bound to custom `AccessControl` permissions (`ADMIN_ROLE`), preventing external registry poisoning.
*   **Execution Isolation**: `SafeExecutionGate` applies a dual checks structure. Reentrancy is mitigated via `ReentrancyGuard`, and automated panic switches allow immediate halting (`Pausable`) during anomaly alerts.
*   **Stdio Sanitization**: The server directs diagnostic logging strictly to `process.stderr` (`console.error`). Under no circumstance will the JSON-RPC communication channel (`process.stdout`) be polluted with Ethers runtime connection warnings or raw logs, preserving the integrity of the Stdio connection socket.
