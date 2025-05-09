import { expect } from "chai";
import { ethers, network } from "hardhat";
import type { Signer } from "ethers";
import { FhevmInstance } from "fhevmjs/node";

import type { NgramFheDetector } from "../../types";
import { createInstance } from "../instance";
import { getSigners, initSigners, Signers } from "../signers";
import { debug } from "../utils";

// Constants from the contract
const LCG_MULT = 6364136223846793005n;
const LCG_INC = 1n;
const NGRAM_LEN = 4;
const H = NGRAM_LEN - 1;
const CONTRACT_SECRET_KEYS_COUNT = 3;

// Helper functions for expected value calculation in TypeScript
function _lcg_accumulate_ts(acc: bigint, data: bigint[]): bigint {
  let currentAcc = acc;
  for (const val of data) {
    currentAcc = (currentAcc + val) & 0xFFFFFFFFFFFFFFFFn;
    currentAcc = (currentAcc * LCG_MULT) & 0xFFFFFFFFFFFFFFFFn;
    currentAcc = (currentAcc + LCG_INC) & 0xFFFFFFFFFFFFFFFFn;
  }
  return currentAcc;
}

function _lsb_ts(x: bigint): bigint {
  return x & 1n;
}

function _window_g_sum_ts(ctx: bigint[], cur: bigint, watermarkParams: bigint[]): bigint {
  const encParam0 = watermarkParams[0];
  const ctxHash = _lcg_accumulate_ts(encParam0, ctx);

  let gSum = 0n;
  for (let l = 0; l < CONTRACT_SECRET_KEYS_COUNT; l++) {
    const l_bigint = BigInt(l);
    const encParamL = watermarkParams[l];

    const dataForTokHash: bigint[] = [ctxHash, cur, l_bigint];
    const tokHash = _lcg_accumulate_ts(encParamL, dataForTokHash);

    let shiftedVal: bigint;
    if (l === 0) {
      shiftedVal = tokHash;
    } else {
      shiftedVal = tokHash >> BigInt(l);
    }
    gSum = (gSum + _lsb_ts(shiftedVal)) & 0xFFFFFFFFFFFFFFFFn;
  }
  return gSum;
}

// Simplified encryption helper for the Hardhat environment
async function encryptTokens(
  tokens: bigint[],
  user: Signer,
  targetContractAddress: string,
  fhevmInstance: FhevmInstance,
): Promise<{ handles: string[]; inputProof: string }> {
  if (network.name !== "hardhat") {
    throw new Error("This simplified encryptTokens is for Hardhat network only.");
  }
  if (!fhevmInstance || typeof fhevmInstance.createEncryptedInput !== "function") {
    throw new Error("fhevmInstance is invalid or createEncryptedInput is missing.");
  }

  const userAddress = await user.getAddress();
  const inputBuilder = fhevmInstance.createEncryptedInput(targetContractAddress, userAddress);

  for (const token of tokens) {
    (inputBuilder as any).add64(token);
  }

  const encryptionResult = await (inputBuilder as any).encrypt();

  // Ensure handles are hex strings with "0x" prefix (not sure why this is needed)
  const finalHandles: string[] = encryptionResult.handles.map((rawHandle: any) => {
    if (rawHandle instanceof Uint8Array) {
      return "0x" + Buffer.from(rawHandle).toString("hex");
    } else if (typeof rawHandle === "string") {
      return rawHandle.startsWith("0x") ? rawHandle : "0x" + rawHandle;
    }
    throw new Error(`Unexpected handle type: ${typeof rawHandle}`);
  });

  return { handles: finalHandles, inputProof: encryptionResult.inputProof };
}

// Fixture to deploy and initialize the contract
async function deployNgramFheDetectorFixture(owner: Signer): Promise<NgramFheDetector> {
  const contractFactory = await ethers.getContractFactory("NgramFheDetector");
  const contract = (await contractFactory.connect(owner).deploy(await owner.getAddress())) as NgramFheDetector;
  await contract.waitForDeployment();
  return contract;
}

describe("NgramFheDetector - Debugging Watermarking Detection Contract", function () {
  let signers: Signers;
  let contract: NgramFheDetector;
  let contractAddress: string;
  let fhevm: FhevmInstance;

  // Default parameters to set in the contract
  const defaultWatermarkParams: [bigint, bigint, bigint] = [100n, 200n, 300n];

  before(async function () {
    // Initialize signers and FHEVM instance once
    await initSigners();
    signers = await getSigners();
    fhevm = await createInstance();
    if (network.name !== "hardhat") {
        console.warn("Warning: This test is designed for the Hardhat (mocked FHE) environment using debug.decrypt.");
    }
  });

  beforeEach(async function () {
    // Deploy a new contract instance and set parameters for each test
    contract = await deployNgramFheDetectorFixture(signers.alice);
    contractAddress = await contract.getAddress();
    // Set watermark parameters
    await contract.connect(signers.alice).setWatermarkParams(defaultWatermarkParams);
    expect(await contract.paramsFrozen()).to.be.true;
  });

  it("should process a single window of NGRAM_LEN tokens and verify results", async function () {
    // Prepare minimal tokens (NGRAM_LEN tokens)
    const tokensPlain: bigint[] = [10n, 20n, 30n, 40n]; // NGRAM_LEN = 4 in contract

    // Encrypt tokens for the Hardhat environment
    const { handles, inputProof } = await encryptTokens(
      tokensPlain,
      signers.alice,
      contractAddress,
      fhevm,
    );

    // Call processTokens
    let txReceipt;
    try {
      const tx = await contract.connect(signers.alice).processTokens(handles, inputProof);
      txReceipt = await tx.wait();
      console.log("processTokens transaction successful. Gas used:", txReceipt?.gasUsed.toString());
    } catch (error: any) {
      console.error("processTokens transaction reverted!");
      console.error("Error message:", error.message);
      if (error.data) {
        console.error("Revert data:", error.data);
      }
      // fails here if processTokens reverts.
      expect.fail(`processTokens reverted unexpectedly: ${error.message}`);
    }

    // If processTokens succeeded, proceed to verify the results

    // Calculate expected values using TypeScript helper functions
    const windowsCount = tokensPlain.length - H; // Should be 1 for this test case
    const expectedDenom = BigInt(windowsCount * CONTRACT_SECRET_KEYS_COUNT);

    let expectedTotalG = 0n;
    // Loop for each window (only one window in this case)
    for (let i = 0; i < windowsCount; i++) {
      const context = tokensPlain.slice(i, i + H);
      const currentToken = tokensPlain[i + H];
      expectedTotalG = (expectedTotalG + _window_g_sum_ts(context, currentToken, defaultWatermarkParams)) & 0xFFFFFFFFFFFFFFFFn;
    }
    const expectedFlag = (expectedTotalG * 2n) > expectedDenom;

    // Get and decrypt actual values from the contract
    const actualEncryptedTotalGHandle = await contract.getEncryptedTotalG();
    const actualTotalG = await debug.decrypt64(actualEncryptedTotalGHandle);

    const actualEncryptedFlagHandle = await contract.getEncryptedFlag();
    const actualFlag = await debug.decryptBool(actualEncryptedFlagHandle);

    const actualPlaintextDenom = await contract.getPlaintextDenom();

    // Asserts
    expect(actualPlaintextDenom).to.equal(expectedDenom, "PlaintextDenom mismatch");
    expect(actualTotalG).to.equal(expectedTotalG, "EncryptedTotalG mismatch after decryption");
    expect(actualFlag).to.equal(expectedFlag, "EncryptedFlag mismatch after decryption");

    console.log("Test for single window completed successfully.");
    console.log(`Expected Denom: ${expectedDenom}, Actual Denom: ${actualPlaintextDenom}`);
    console.log(`Expected TotalG: ${expectedTotalG}, Actual TotalG (decrypted): ${actualTotalG}`);
    console.log(`Expected Flag: ${expectedFlag}, Actual Flag (decrypted): ${actualFlag}`);
  });
});