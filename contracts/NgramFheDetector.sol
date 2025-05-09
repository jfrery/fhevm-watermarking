// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.24;

import "fhevm/lib/TFHE.sol";
import "fhevm/config/ZamaFHEVMConfig.sol";
import {Ownable2Step, Ownable} from "@openzeppelin/contracts/access/Ownable2Step.sol";

/**
 * @title N-gram watermark detector (FHE)
 * @author Zama
 * @notice Evaluates an N-gram watermark over encrypted token streams.
 */
contract NgramFheDetector is SepoliaZamaFHEVMConfig, Ownable2Step {
    // LCG constants for hashing
    uint64 public constant LCG_MULT = 6_364_136_223_846_793_005;
    uint64 public constant LCG_INC = 1;

    // N-gram parameters
    uint8 public constant NGRAM_LEN = 4;
    uint8 public constant H = NGRAM_LEN - 1; // Context size (e.g., 3 for 4-grams)
    uint8 public constant SECRET_KEYS_COUNT = 3; // Number of secret keys for watermarking

    // Watermark parameters set by the owner
    uint64[SECRET_KEYS_COUNT] public wmParams;
    bool public paramsFrozen; // Parameters can only be set once

    // Results of the watermark detection
    euint64 public encryptedTotalG; // Encrypted sum of g values
    ebool public encryptedFlag; // Encrypted flag: (2 * totalG > plaintextDenom)
    uint64 public plaintextDenom; // Plaintext denominator: windows * SECRET_KEYS_COUNT

    event WatermarkParamsSet(uint64[SECRET_KEYS_COUNT] params);
    event TokensProcessed(address indexed caller, uint64 calculatedDenom, euint64 totalGValue, ebool flagValue);

    constructor(address initialOwner) Ownable(initialOwner) {}

    /**
     * @notice Sets the watermark parameters. Can only be called once by the owner.
     * @param _params The array of secret keys for watermarking.
     */
    function setWatermarkParams(uint64[SECRET_KEYS_COUNT] calldata _params) external onlyOwner {
        require(!paramsFrozen, "NgramFheDetector: Params already set");
        wmParams = _params;
        paramsFrozen = true;
        emit WatermarkParamsSet(_params);
    }

    /**
     * @notice Computes the least significant bit (LSB) of an encrypted unsigned 64-bit integer.
     * @param x The encrypted integer.
     * @return Encrypted LSB of x.
     */
    function _lsb(euint64 x) internal returns (euint64) {
        // Equivalent to x % 2 or x & 1
        return TFHE.and(x, TFHE.asEuint64(1));
    }

    /**
     * @notice Accumulates values using a Linear Congruential Generator (LCG) based hash.
     * @param acc The initial accumulator (encrypted).
     * @param data An array of encrypted data to accumulate.
     * @return The final accumulated hash (encrypted).
     */
    function _lcgAccumulate(euint64 acc, euint64[] memory data) internal returns (euint64) {
        euint64 currentAcc = acc;
        for (uint256 i = 0; i < data.length; ++i) {
            currentAcc = TFHE.add(currentAcc, data[i]);
            currentAcc = TFHE.mul(currentAcc, LCG_MULT);
            currentAcc = TFHE.add(currentAcc, LCG_INC);
        }
        return currentAcc;
    }

    /**
     * @notice Computes the sum of g_l(ctx, cur) for a single window.
     * @param ctx The encrypted context tokens.
     * @param cur The encrypted current token.
     * @return The sum g (encrypted).
     */
    function _calculateWindowGSum(euint64[] memory ctx, euint64 cur) internal returns (euint64) {
        // Initialize context hash with the first watermark parameter
        euint64 ctxHash = _lcgAccumulate(TFHE.asEuint64(wmParams[0]), ctx);
        euint64 gSum = TFHE.asEuint64(0);

        for (uint8 l = 0; l < SECRET_KEYS_COUNT; ++l) {
            euint64[] memory dataForTokHash = new euint64[](3);
            dataForTokHash[0] = ctxHash;
            dataForTokHash[1] = cur;
            dataForTokHash[2] = TFHE.asEuint64(uint64(l)); // Encrypt the loop index l

            // Calculate token hash with the l-th watermark parameter
            euint64 tokHash = _lcgAccumulate(TFHE.asEuint64(wmParams[l]), dataForTokHash);

            euint64 shiftedValue;
            if (l == 0) {
                shiftedValue = tokHash;
            } else {
                shiftedValue = TFHE.shr(tokHash, l);
            }
            gSum = TFHE.add(gSum, _lsb(shiftedValue));
        }
        return gSum;
    }

    /**
     * @notice Processes a stream of encrypted tokens to detect a watermark.
     * @param encryptedTokensHandles Handles to the encrypted tokens.
     * @param proof Verification proof for the encrypted inputs.
     */
    function processTokens(einput[] calldata encryptedTokensHandles, bytes calldata proof) external {
        require(paramsFrozen, "NgramFheDetector: Watermark parameters not set yet");
        require(encryptedTokensHandles.length >= NGRAM_LEN, "NgramFheDetector: Input token stream is too short");
        require(proof.length != 0, "NgramFheDetector: Missing input proof");

        euint64[] memory tokens = new euint64[](encryptedTokensHandles.length);
        for (uint256 k = 0; k < encryptedTokensHandles.length; ++k) {
            tokens[k] = TFHE.asEuint64(encryptedTokensHandles[k], proof);
        }

        uint256 windowsCount = tokens.length - H;
        plaintextDenom = uint64(windowsCount * SECRET_KEYS_COUNT);

        if (windowsCount == 0) {
            encryptedTotalG = TFHE.asEuint64(0);
            encryptedFlag = TFHE.asEbool(false);
            emit TokensProcessed(msg.sender, plaintextDenom, encryptedTotalG, encryptedFlag);
            return;
        }

        // Compute sum of g over all windows
        euint64 totalGAccumulator = TFHE.asEuint64(0);
        for (uint256 i = 0; i < windowsCount; ++i) {
            euint64[] memory context = new euint64[](H);
            for (uint256 j = 0; j < H; ++j) {
                context[j] = tokens[i + j];
            }
            euint64 currentToken = tokens[i + H];
            totalGAccumulator = TFHE.add(totalGAccumulator, _calculateWindowGSum(context, currentToken));
        }

        encryptedTotalG = totalGAccumulator;

        // Calculate flag: (2 * totalG > denom)
        euint64 twiceTotalG = TFHE.mul(encryptedTotalG, uint64(2));
        encryptedFlag = TFHE.gt(twiceTotalG, TFHE.asEuint64(plaintextDenom));

        emit TokensProcessed(msg.sender, plaintextDenom, encryptedTotalG, encryptedFlag);
    }

    function getEncryptedTotalG() external view returns (euint64) {
        return encryptedTotalG;
    }

    function getEncryptedFlag() external view returns (ebool) {
        return encryptedFlag;
    }

    function getPlaintextDenom() external view returns (uint64) {
        return plaintextDenom;
    }
}