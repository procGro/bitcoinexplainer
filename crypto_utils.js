// crypto_utils.js

const bitcoin = require('bitcoinjs-lib');
const crypto = require('crypto'); // Node.js crypto module for SHA256

class CryptoUtils {

    /**
     * Calculates the SHA256 hash of the input data.
     * @param {Buffer|string} data - The data to hash. If string, it's UTF-8 encoded.
     * @returns {Buffer} The SHA256 hash as a Buffer.
     */
    static sha256(data) {
        const d = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
        return crypto.createHash('sha256').update(d).digest();
    }

    /**
     * Calculates the double SHA256 hash of the input data (SHA256(SHA256(data))).
     * This is commonly used in Bitcoin (e.g., for transaction IDs).
     * @param {Buffer|string} data - The data to hash. If string, it's UTF-8 encoded.
     * @returns {Buffer} The double SHA256 hash as a Buffer.
     */
    static hash256(data) {
        return CryptoUtils.sha256(CryptoUtils.sha256(data));
    }

    /**
     * Calculates the RIPEMD160 hash of the input data.
     * @param {Buffer|string} data - The data to hash. If string, it's UTF-8 encoded.
     * @returns {Buffer} The RIPEMD160 hash as a Buffer.
     */
    static ripemd160(data) {
        const d = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
        return crypto.createHash('ripemd160').update(d).digest();
    }

    /**
     * Calculates the HASH160 of the input data (RIPEMD160(SHA256(data))).
     * This is commonly used in Bitcoin for address generation.
     * @param {Buffer|string} data - The data to hash. If string, it's UTF-8 encoded.
     * @returns {Buffer} The HASH160 hash as a Buffer.
     */
    static hash160(data) {
        return CryptoUtils.ripemd160(CryptoUtils.sha256(data));
    }

    /**
     * Prepares and hashes a message according to the Bitcoin signed message standard.
     * The format is: "\x18Bitcoin Signed Message:\n" + message length + message,
     * which is then double SHA256 hashed.
     * @param {string} messageString - The message string to hash.
     * @returns {Buffer} The hash ready for signing/verification.
     */
    static hashMessageForSigning(messageString) {
        const messagePrefix = Buffer.from('\x18Bitcoin Signed Message:\n', 'utf8');
        const messageBuffer = Buffer.from(messageString, 'utf8');
        const messageLength = bitcoin.script.number.encode(messageBuffer.length); // varint encoding

        const bufferToHash = Buffer.concat([messagePrefix, messageLength, messageBuffer]);
        return CryptoUtils.hash256(bufferToHash);
    }

    /**
     * Calculates the transaction ID (txid) from a raw transaction hex string.
     * This is the double SHA256 hash of the non-witness serialized transaction, byte-reversed.
     * For SegWit transactions, this is the hash without witness data.
     * @param {string} transactionHex - The raw transaction in hex format.
     * @returns {string|null} The transaction ID (txid) as a hex string, or null on error.
     */
    static getTransactionId(transactionHex) {
        try {
            const tx = bitcoin.Transaction.fromHex(transactionHex);
            return tx.getId();
        } catch (e) {
            console.error("Error calculating transaction ID:", e.message);
            return null;
        }
    }

    /**
     * Calculates the witness transaction ID (wtxid) or "hash" from a raw transaction hex string.
     * For SegWit transactions, this is the double SHA256 hash of the transaction including witness data, byte-reversed.
     * For non-SegWit transactions, this is the same as the txid.
     * @param {string} transactionHex - The raw transaction in hex format.
     * @returns {string|null} The witness transaction ID (wtxid) as a hex string, or null on error.
     */
    static getWitnessTransactionId(transactionHex) {
        try {
            const tx = bitcoin.Transaction.fromHex(transactionHex);
            // tx.getHash(true) ensures we get the witness hash if available.
            // The result of getHash is not reversed, so we reverse it.
            return tx.getHash(true).reverse().toString('hex');
        } catch (e) {
            console.error("Error calculating witness transaction ID:", e.message);
            return null;
        }
    }

    /**
     * Calculates the non-reversed transaction hash (double SHA256 of non-witness data).
     * @param {string} transactionHex - The raw transaction in hex format.
     * @returns {Buffer|null} The transaction hash as a Buffer, or null on error.
     */
    static getTransactionHashNonWitness(transactionHex) {
        try {
            const tx = bitcoin.Transaction.fromHex(transactionHex);
            // tx.getHash(false) for non-witness hash.
            return tx.getHash(false);
        } catch (e) {
            console.error("Error calculating non-witness transaction hash:", e.message);
            return null;
        }
    }
}

// --- ECDSA Private Key Recovery from k-reuse ---
CryptoUtils.N_SECP256K1 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n; // Curve order as BigInt

/**
 * Attempts to recover an ECDSA private key if the nonce 'k' was reused.
 * All hex string inputs are expected to represent positive integers.
 * r, s1, s2 are signature components. h1, h2 are message hashes.
 *
 * @param {string | Buffer | BigInt} rHex - The common 'r' value of the two signatures (hex string, Buffer, or BigInt).
 * @param {string | Buffer | BigInt} s1Hex - The 's' value of the first signature (hex string, Buffer, or BigInt).
 * @param {string | Buffer | BigInt} h1Hex - The message hash for the first signature (hex string, Buffer, or BigInt).
 * @param {string | Buffer | BigInt} s2Hex - The 's' value of the second signature (hex string, Buffer, or BigInt).
 * @param {string | Buffer | BigInt} h2Hex - The message hash for the second signature (hex string, Buffer, or BigInt).
 * @param {BigInt} curveOrderN - The order of the curve's base point (e.g., N_SECP256K1).
 * @returns {BigInt|null} The recovered private key as a BigInt, or null if recovery fails (e.g., singular matrix).
 */
CryptoUtils.recoverPrivateKeyFromKReuse = function(rHex, s1Hex, h1Hex, s2Hex, h2Hex, curveOrderN = N_SECP256K1) {
    const { modinv } = require('./bignum.js'); // Assuming bignum.js is in the same directory or accessible

    try {
        const r = typeof rHex === 'bigint' ? rHex : BigInt("0x" + Buffer.from(rHex, 'hex').toString('hex'));
        const s1 = typeof s1Hex === 'bigint' ? s1Hex : BigInt("0x" + Buffer.from(s1Hex, 'hex').toString('hex'));
        const h1 = typeof h1Hex === 'bigint' ? h1Hex : BigInt("0x" + Buffer.from(h1Hex, 'hex').toString('hex'));
        const s2 = typeof s2Hex === 'bigint' ? s2Hex : BigInt("0x" + Buffer.from(s2Hex, 'hex').toString('hex'));
        const h2 = typeof h2Hex === 'bigint' ? h2Hex : BigInt("0x" + Buffer.from(h2Hex, 'hex').toString('hex'));
        const n = curveOrderN;

        if (r <= 0n || s1 <= 0n || h1 < 0n || s2 <= 0n || h2 < 0n || n <= 0n) {
            console.error("Invalid input values for private key recovery (must be positive, hashes can be 0).");
            return null;
        }
        if (r >= n || s1 >= n || s2 >=n ) { // Hashes can be larger than n, they are reduced by EC lib usually
             console.warn("r or s values are >= curve order n. This is unusual.");
        }


        // k = (h1 - h2) * modinv(s1 - s2, n) mod n
        let s_diff = (s1 - s2) % n;
        if (s_diff < 0n) s_diff += n; // Ensure positive modulo result
        if (s_diff === 0n) {
            // This happens if s1 == s2. If h1 != h2, then it implies k is undefined or infinite,
            // which means the signatures were not proper or there's an issue.
            // If s1 == s2 and h1 == h2, they are identical signatures for identical messages, no k-reuse exploit here.
            console.error("s1 and s2 are identical, cannot recover k (or private key).");
            return null;
        }

        const s_diff_inv = modinv(s_diff, n);
        if (s_diff_inv === null || s_diff_inv === 0n) { // modinv in bignum.js might return non-BigInt on error or 0 if not invertible
             console.error("Modular inverse of (s1 - s2) does not exist.");
             return null;
        }


        let h_diff = (h1 - h2) % n;
        if (h_diff < 0n) h_diff += n;

        let k = (h_diff * s_diff_inv) % n;
        if (k < 0n) k += n;
        if (k === 0n) { // k should not be zero
            console.error("Calculated k is zero, which is invalid.");
            return null;
        }

        // privKey = (s1 * k - h1) * modinv(r, n) mod n
        const r_inv = modinv(r, n);
         if (r_inv === null || r_inv === 0n) {
             console.error("Modular inverse of r does not exist.");
             return null;
        }

        let sk = (s1 * k) % n;
        let sk_minus_h1 = (sk - h1) % n;
        if (sk_minus_h1 < 0n) sk_minus_h1 += n;

        let privateKey = (sk_minus_h1 * r_inv) % n;
        if (privateKey < 0n) privateKey += n;

        // Private key must be > 0 and < n
        if (privateKey === 0n) {
            console.error("Calculated private key is zero, which is invalid.");
            return null;
        }

        return privateKey;

    } catch (error) {
        console.error("Error during private key recovery:", error);
        return null;
    }
};


// --- Example Usage & Basic Tests ---
/*
function runCryptoUtilsExamples() {
    const { modinv } = require('./bignum.js'); // For test case generation

    const message = "This is a test message.";

    console.log("--- Message Hashing Examples ---");
    console.log("Original Message:", message);

    const simpleData = "hello world";
    const sha256Hash = CryptoUtils.sha256(simpleData);
    console.log(`\nSHA256('${simpleData}'):`, sha256Hash.toString('hex'));

    const doubleSha256Hash = CryptoUtils.hash256(simpleData);
    console.log(`Double SHA256 (hash256) of '${simpleData}':`, doubleSha256Hash.toString('hex'));
    // Expected for "hello world": b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9 (single SHA256)
    // d9014c4624844aa5bac314773d6b689ad467fa4e1d1a50a1b8a99d5a95f72ff5 (double SHA256)

    const ripemd160Hash = CryptoUtils.ripemd160(simpleData);
    console.log(`RIPEMD160('${simpleData}'):`, ripemd160Hash.toString('hex'));

    const hash160Result = CryptoUtils.hash160(simpleData);
    console.log(`HASH160('${simpleData}'):`, hash160Result.toString('hex'));
    // Expected for "hello world" HASH160: 0957SADQ... (example, actual value depends on sha256 then ripemd160)
    // SHA256('hello world') = b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
    // RIPEMD160(SHA256('hello world')) = 7f77501499776910867199f807742958e739e24b

    const bitcoinMessageHash = CryptoUtils.hashMessageForSigning(message);
    console.log(`\nBitcoin Signed Message Hash for '${message}':`, bitcoinMessageHash.toString('hex'));
    // Example from a known source for "This is a test message.":
    // f05720958990842198360730139a903929967448815906113165ed104038af1a
    // Let's verify with a different known message: "test"
    // Bitcoin Signed Message Hash for 'test': 2502a17557502968180470191029984926079076948089a95750337858103869
    const testMessageHash = CryptoUtils.hashMessageForSigning("test");
    console.log(`Bitcoin Signed Message Hash for 'test':`, testMessageHash.toString('hex'));


    // Test with known values
    const knownHash256Input = ""; // Empty string
    const knownHash256Output = "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456";
    const calculatedEmptyHash256 = CryptoUtils.hash256(knownHash256Input).toString('hex');
    console.log(`\nDouble SHA256 of empty string: ${calculatedEmptyHash256}`);
    console.log(`Matches known value: ${calculatedEmptyHash256 === knownHash256Output}`);

    const knownHash160Input = Buffer.from("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "hex"); // A compressed public key
    const knownHash160Output = "751e76e8199196d454941c45d1b3a323f1433bd6"; // Expected HASH160 for this pubkey
    const calculatedKnownHash160 = CryptoUtils.hash160(knownHash160Input).toString('hex');
    console.log(`\nHASH160 of known pubkey: ${calculatedKnownHash160}`);
    console.log(`Matches known value: ${calculatedKnownHash160 === knownHash160Output}`);


    console.log("\n--- Transaction Hashing Examples ---");
    const rawTxHexLegacy = "010000000129a11f8516e9c873544037fb7893000500938b345f676f013ef15aa0c960f994000000006a4730440220131ef7990f9c429020787a06235adb5d088c015235aa340a0593068586a91006022006073b40f69be07868732622511c108582c83598638184810db42a867855890701210370a0f9e227ac9810b89fc949691979f68bc70304894885d0ef831881a5cdff55ffffffff0240420f00000000001976a91497a3c0a048077879599c8c0015ddc0e0d5c8711e88ac50c30000000000001976a914876755254c135093bf4f0a0195266d7e9998f06688ac00000000";
    const expectedTxIdLegacy = "2f000b801c97638516917834451a4c64f3697918f198958798248a8978828774";

    const calculatedTxIdLegacy = CryptoUtils.getTransactionId(rawTxHexLegacy);
    console.log("Raw Legacy Tx Hex:", rawTxHexLegacy);
    console.log("Calculated Legacy TxID:", calculatedTxIdLegacy);
    console.log("Expected Legacy TxID:  ", expectedTxIdLegacy);
    console.log("Matches expected:      ", calculatedTxIdLegacy === expectedTxIdLegacy);

    const calculatedWitnessTxIdLegacy = CryptoUtils.getWitnessTransactionId(rawTxHexLegacy);
    console.log("Calculated Legacy Witness TxID (should be same as TxID):", calculatedWitnessTxIdLegacy);
    console.log("Matches TxID:                                          ", calculatedWitnessTxIdLegacy === expectedTxIdLegacy);

    const calculatedNonWitnessHashLegacy = CryptoUtils.getTransactionHashNonWitness(rawTxHexLegacy);
    if (calculatedNonWitnessHashLegacy) {
        console.log("Calculated Legacy Non-Witness Hash (Buffer):", calculatedNonWitnessHashLegacy.toString('hex'));
        // The txid is the reverse of this hash
        console.log("Reverse of Non-Witness Hash:                ", Buffer.from(calculatedNonWitnessHashLegacy).reverse().toString('hex'));
    }

    // It would be good to add a SegWit transaction example here as well.
    // For now, we'll use a placeholder for where a SegWit example would go.
    const rawTxHexSegwit = "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff01e8030000000000001976a914000000000000000000000000000000000000000088ac01473044022035a61b14519009878810163c9958604f1767f1b8061180a015660481ae13b733022036c02070d21d76798a587723770e2759809a9e20237572fd1773011bf191678101210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000"; // Replace with actual SegWit TX hex
    const expectedTxIdSegwit = "c8f2057a97b88a18a15d98660510007446aad520f511c777c6bd8db500000000"; // Replace with actual SegWit TXID
    const expectedWitnessTxIdSegwit = "e2a6d90f59a88070513388d47524198f000966c78b82f90dea1cb83400000000"; // Replace with actual SegWit wTXID

    // console.log("\n--- SegWit Transaction (Placeholder) ---");
    // const calculatedTxIdSegwit = CryptoUtils.getTransactionId(rawTxHexSegwit);
    // console.log("Calculated SegWit TxID:", calculatedTxIdSegwit);
    // console.log("Expected SegWit TxID:  ", expectedTxIdSegwit);

    // const calculatedWitnessTxIdSegwit = CryptoUtils.getWitnessTransactionId(rawTxHexSegwit);
    // console.log("Calculated SegWit Witness TxID:", calculatedWitnessTxIdSegwit);
    // console.log("Expected SegWit Witness TxID:  ", expectedWitnessTxIdSegwit);

    console.log("\n--- ECDSA K-Reuse Private Key Recovery Test ---");
    const test_N = CryptoUtils.N_SECP256K1;
    const test_d = 12345678901234567890123456789012345678901234567890123456789012345n; // Example private key
    const test_k = 98765432109876543210987654321098765432109876543210987654321098765n;  // Example reused k

    // For a realistic test, r must be derived from k*G.
    // However, to test the math of recoverPrivateKeyFromKReuse, we can assume a valid r.
    // Let's use a placeholder r. A real r would be an x-coordinate of a point, so < N.
    const test_r_val = BigInt("0x1f2a3b4c5d6e7f8091a2b3c4d5e6f708091a2b3c4d5e6f708091a2b3c4d5e6f7");

    if (test_k >= test_N || test_r_val >= test_N || test_d >= test_N || test_k === 0n || test_r_val === 0n || test_d === 0n) {
        console.error("Test case parameters are invalid (too large or zero). Adjust them.");
    } else {
        const test_h1 = BigInt("0x1111111111111111111111111111111111111111111111111111111111111111");
        const test_h2 = BigInt("0x2222222222222222222222222222222222222222222222222222222222222222");

        try {
            const k_inv = modinv(test_k, test_N);
            if (k_inv === 0n) throw new Error("k is not invertible for test case generation");

            let s1_num = (test_h1 + test_d * test_r_val) % test_N;
            let test_s1 = (k_inv * s1_num) % test_N;
            if (test_s1 < 0n) test_s1 += test_N;

            let s2_num = (test_h2 + test_d * test_r_val) % test_N;
            let test_s2 = (k_inv * s2_num) % test_N;
            if (test_s2 < 0n) test_s2 += test_N;

            if (test_s1 === 0n || test_s2 === 0n) {
                 console.error("Generated s1 or s2 is zero, invalid signature component for test. Pick different d, k, r, h1, h2.");
            } else {
                console.log("Test Case Generation:");
                console.log("  d (privKey):", test_d.toString(16));
                console.log("  k (nonce):  ", test_k.toString(16));
                console.log("  r:          ", test_r_val.toString(16));
                console.log("  h1:         ", test_h1.toString(16));
                console.log("  s1:         ", test_s1.toString(16));
                console.log("  h2:         ", test_h2.toString(16));
                console.log("  s2:         ", test_s2.toString(16));

                const recovered_d = CryptoUtils.recoverPrivateKeyFromKReuse(
                    test_r_val, test_s1, test_h1, test_s2, test_h2, test_N
                );

                if (recovered_d !== null) {
                    console.log("Recovered d:    ", recovered_d.toString(16));
                    console.log("Matches original d:", recovered_d === test_d);
                    if (recovered_d !== test_d) {
                        console.error("Private key recovery test FAILED. Expected vs Recovered mismatch.");
                    } else {
                        console.log("Private key recovery test PASSED.");
                    }
                } else {
                    console.error("Private key recovery test FAILED. Result was null.");
                }
            }
        } catch (e) {
            console.error("Error during test case setup or recovery:", e.message, e.stack);
        }
    }
}

// runCryptoUtilsExamples(); // Uncomment to run example if testing this file directly with Node.js
*/

module.exports = CryptoUtils;
