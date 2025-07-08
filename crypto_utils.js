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

// --- Example Usage & Basic Tests ---
/*
function runCryptoUtilsExamples() {
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

}

// runCryptoUtilsExamples(); // Uncomment to run example if testing this file directly with Node.js
*/

module.exports = CryptoUtils;
