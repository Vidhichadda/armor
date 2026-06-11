import { ethers } from "ethers";
import { logInfo, logError } from "../pharosRpc.js";

interface GenerateInvoiceArgs {
  amount_in_pros: string;
  developer_wallet: string;
}

/**
 * Handles payment invoice compilation. Compiles an EIP-712 signed HTTP 402 pay-per-call payload
 * that allows automated wallets to cryptographically verify merchant and gateway credentials.
 */
export async function generateInvoiceHandler(args: GenerateInvoiceArgs) {
  const { amount_in_pros, developer_wallet } = args;

  logInfo(`Generating HTTP 402 EIP-712 invoice: developer=${developer_wallet}, amount=${amount_in_pros} PROS`);

  try {
    // Audit-Ready: Standard parameter validation to isolate scripts from dirty parameters
    if (!amount_in_pros || isNaN(Number(amount_in_pros)) || Number(amount_in_pros) <= 0) {
      throw new Error(`Invalid invoice amount requested: ${amount_in_pros}`);
    }

    if (!developer_wallet || !ethers.isAddress(developer_wallet)) {
      throw new Error(`Invalid developer wallet format: ${developer_wallet}`);
    }

    // Convert PROS to 18 decimals base (wei)
    const amountInWei = ethers.parseEther(amount_in_pros).toString();

    // Generate a cryptographically secure off-chain invoice tracking hash
    const currentTimestamp = Date.now();
    const trackingBytes = ethers.solidityPacked(
      ["address", "uint256", "uint256"],
      [developer_wallet, amountInWei, currentTimestamp]
    );
    const trackingHash = ethers.keccak256(trackingBytes);

    // 1. Establish EIP-712 Structured Data Domain parameters
    const domain = {
      name: "Anvita Flow Pay Gateway",
      version: "1.0",
      chainId: 688689,
      verifyingContract: process.env.SAFE_EXECUTION_GATE_ADDRESS || ethers.ZeroAddress
    };

    // 2. Define data schemas for verification matching ERC-712 typed standards
    const types = {
      PaymentRequirement: [
        { name: "recipient", type: "address" },
        { name: "amountRaw", type: "uint256" },
        { name: "invoiceId", type: "bytes32" },
        { name: "timestamp", type: "uint256" }
      ]
    };

    const message = {
      recipient: developer_wallet,
      amountRaw: amountInWei,
      invoiceId: trackingHash,
      timestamp: Math.floor(currentTimestamp / 1000)
    };

    // 3. Perform cryptographic signing
    let signature = "0x";
    let signerAddress = ethers.ZeroAddress;
    let isMockSign = false;

    // Load server-side signing key from configuration environments
    const signingKey = process.env.PRIVATE_KEY || process.env.INVOICE_SIGNING_KEY;

    if (signingKey && signingKey !== "0x0000000000000000000000000000000000000000000000000000000000000000") {
      try {
        const wallet = new ethers.Wallet(signingKey);
        signature = await wallet.signTypedData(domain, types, message);
        signerAddress = wallet.address;
      } catch (e: any) {
        logError("Failed to sign invoice using primary private key", e);
      }
    }

    // Fallback: If no merchant key is provided, use a deterministic simulation key for testnet runs
    if (signature === "0x") {
      const fallbackKey = ethers.id("PHAROS_MERCHANT_FALLBACK_SIMULATION_KEY");
      const wallet = new ethers.Wallet(fallbackKey);
      signature = await wallet.signTypedData(domain, types, message);
      signerAddress = wallet.address;
      isMockSign = true;
    }

    // Compile Anvita Flow native HTTP 402 Pay-Per-Call schema representation with signature proofs
    const invoice = {
      status: "PAYMENT_REQUIRED",
      statusCode: 402,
      paymentRequirement: {
        gateway: "Anvita Flow Pay-Per-Call Gateway",
        token: {
          symbol: "PROS",
          decimals: 18,
          amountRaw: amountInWei,
          amountFormatted: amount_in_pros
        },
        recipient: developer_wallet,
        invoiceId: trackingHash,
        timestamp: message.timestamp
      },
      signatureProof: {
        signer: signerAddress,
        signature: signature,
        isMockSignature: isMockSign,
        domain: domain,
        types: types
      },
      settlementPayload: {
        targetChainId: 688689,
        targetRPC: "https://atlantic.dplabs-internal.com",
        dataPrimitive: {
          action: "AGENT_CALL_SETTLEMENT",
          params: {
            recipient: developer_wallet,
            amount: amountInWei,
            trackingHash: trackingHash
          }
        },
        rawPayload: Buffer.from(JSON.stringify({
          recipient: developer_wallet,
          amount: amountInWei,
          salt: trackingHash,
          targetChain: 688689
        })).toString("base64")
      }
    };

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(invoice, null, 2)
        }
      ]
    };
  } catch (error: any) {
    logError("Failed to generate HTTP 402 signed invoice", error);
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
