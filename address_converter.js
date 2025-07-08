// address_converter.js

const bitcoin = require('bitcoinjs-lib');

class AddressConverter {
    constructor(network = bitcoin.networks.bitcoin) { // Default to mainnet
        this.network = network;
    }

    /**
     * Sets the network for address generation.
     * @param {string} networkName - 'bitcoin' (mainnet) or 'testnet'.
     */
    setNetwork(networkName) {
        if (networkName === 'testnet') {
            this.network = bitcoin.networks.testnet;
        } else if (networkName === 'regtest') {
            this.network = bitcoin.networks.regtest;
        }
        else {
            this.network = bitcoin.networks.bitcoin; // Default to mainnet
        }
    }

    /**
     * Converts a public key to a P2PKH (Pay-to-PubkeyHash) address.
     * Example: 1Addresses...
     * @param {Buffer} pubkeyBuffer - The public key as a Buffer.
     * @returns {string|null} The P2PKH address or null if error.
     */
    pubkeyToP2PKH(pubkeyBuffer) {
        try {
            const { address } = bitcoin.payments.p2pkh({ pubkey: pubkeyBuffer, network: this.network });
            return address;
        } catch (e) {
            console.error("Error converting to P2PKH:", e.message);
            return null;
        }
    }

    /**
     * Converts a public key to a P2WPKH (Pay-to-Witness-PubkeyHash) SegWit address.
     * Example: bc1qAddresses... (mainnet) or tb1qAddresses... (testnet)
     * @param {Buffer} pubkeyBuffer - The public key as a Buffer.
     * @returns {string|null} The P2WPKH address or null if error.
     */
    pubkeyToP2WPKH(pubkeyBuffer) {
        try {
            const { address } = bitcoin.payments.p2wpkh({ pubkey: pubkeyBuffer, network: this.network });
            return address;
        } catch (e) {
            console.error("Error converting to P2WPKH:", e.message);
            return null;
        }
    }

    /**
     * Converts a redeem script to a P2SH (Pay-to-Script-Hash) address.
     * Example: 3Addresses...
     * @param {Buffer} redeemScriptBuffer - The redeem script as a Buffer.
     * @returns {string|null} The P2SH address or null if error.
     */
    scriptToP2SH(redeemScriptBuffer) {
        try {
            const { address } = bitcoin.payments.p2sh({ redeem: { output: redeemScriptBuffer, network: this.network }, network: this.network });
            return address;
        } catch (e) {
            console.error("Error converting to P2SH:", e.message);
            return null;
        }
    }

    /**
     * Converts a witness script to a P2WSH (Pay-to-Witness-Script-Hash) SegWit address.
     * Example: bc1qAddresses... (mainnet) or tb1qAddresses... (testnet)
     * @param {Buffer} witnessScriptBuffer - The witness script as a Buffer.
     * @returns {string|null} The P2WSH address or null if error.
     */
    scriptToP2WSH(witnessScriptBuffer) {
        try {
            const { address } = bitcoin.payments.p2wsh({ redeem: { output: witnessScriptBuffer, network: this.network }, network: this.network });
            return address;
        } catch (e) {
            console.error("Error converting to P2WSH:", e.message);
            return null;
        }
    }

    /**
     * Decodes a Bitcoin address to its constituent parts.
     * @param {string} addressString - The Bitcoin address.
     * @returns {object|null} An object containing address details (hash, version, prefix, type) or null if error.
     */
    decodeAddress(addressString) {
        try {
            let decoded;
            // Try Bech32 decoding first (for SegWit addresses)
            try {
                decoded = bitcoin.address.fromBech32(addressString);
                return {
                    prefix: decoded.prefix,
                    type: (decoded.data.length === 20) ? 'p2wpkh' : 'p2wsh', // Heuristic based on hash length
                    hash: decoded.data, // This is the witness program
                    network: (decoded.prefix === 'bc' || decoded.prefix === 'tb' || decoded.prefix === 'bcrt') ? (decoded.prefix === 'tb' ? bitcoin.networks.testnet : (decoded.prefix === 'bcrt' ? bitcoin.networks.regtest : bitcoin.networks.bitcoin) ) : null
                };
            } catch (e) {
                // If Bech32 fails, try Base58 decoding (for P2PKH/P2SH addresses)
                decoded = bitcoin.address.fromBase58Check(addressString);
                let type;
                if (decoded.version === this.network.pubKeyHash) {
                    type = 'p2pkh';
                } else if (decoded.version === this.network.scriptHash) {
                    type = 'p2sh';
                } else {
                    type = 'unknown_base58';
                }
                return {
                    version: decoded.version,
                    hash: decoded.hash,
                    type: type,
                    network: (decoded.version === bitcoin.networks.bitcoin.pubKeyHash || decoded.version === bitcoin.networks.bitcoin.scriptHash) ? bitcoin.networks.bitcoin : ((decoded.version === bitcoin.networks.testnet.pubKeyHash || decoded.version === bitcoin.networks.testnet.scriptHash) ? bitcoin.networks.testnet : null)
                };
            }
        } catch (e) {
            console.error("Error decoding address:", e.message);
            return null;
        }
    }

    /**
     * Converts a public key to a P2SH-P2WPKH (SegWit compatibility) address.
     * This wraps a P2WPKH payment in a P2SH payment.
     * @param {Buffer} pubkeyBuffer - The public key as a Buffer.
     * @returns {string|null} The P2SH-P2WPKH address or null if error.
     */
    pubkeyToP2SH_P2WPKH(pubkeyBuffer) {
        try {
            const p2wpkh = bitcoin.payments.p2wpkh({ pubkey: pubkeyBuffer, network: this.network });
            const { address } = bitcoin.payments.p2sh({ redeem: p2wpkh, network: this.network });
            return address;
        } catch (e) {
            console.error("Error converting to P2SH-P2WPKH:", e.message);
            return null;
        }
    }

     /**
     * Converts a witness script to a P2SH-P2WSH (SegWit compatibility) address.
     * This wraps a P2WSH payment in a P2SH payment.
     * @param {Buffer} witnessScriptBuffer - The witness script as a Buffer.
     * @returns {string|null} The P2SH-P2WSH address or null if error.
     */
    scriptToP2SH_P2WSH(witnessScriptBuffer) {
        try {
            const p2wsh = bitcoin.payments.p2wsh({ redeem: { output: witnessScriptBuffer, network: this.network }, network: this.network });
            const { address } = bitcoin.payments.p2sh({ redeem: p2wsh, network: this.network });
            return address;
        } catch (e) {
            console.error("Error converting to P2SH-P2WSH:", e.message);
            return null;
        }
    }

    /**
     * Extracts the underlying hash from a Bitcoin address string.
     * For P2PKH/P2SH, this is the HASH160.
     * For P2WPKH/P2WSH (Bech32), this is the witness program.
     * @param {string} addressString - The Bitcoin address.
     * @returns {Buffer|null} The hash as a Buffer, or null if decoding fails or address is invalid.
     */
    getHashFromAddress(addressString) {
        const decoded = this.decodeAddress(addressString);
        if (decoded && decoded.hash) {
            return decoded.hash;
        }
        return null;
    }
}

// --- Example Usage & Basic Tests ---
/*
async function runAddressConverterExamples() {
    const converter = new AddressConverter(); // Mainnet by default

    // Example Public Key (replace with a real one for actual use)
    // This is a compressed public key.
    const exPubKeyHex = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
    const exPubKey = Buffer.from(exPubKeyHex, 'hex');

    console.log("--- MAINNET EXAMPLES ---");
    converter.setNetwork('bitcoin');
    console.log("Public Key:", exPubKey.toString('hex'));
    console.log("P2PKH Address:", converter.pubkeyToP2PKH(exPubKey));
    console.log("P2WPKH Address:", converter.pubkeyToP2WPKH(exPubKey));
    console.log("P2SH-P2WPKH Address:", converter.pubkeyToP2SH_P2WPKH(exPubKey));


    // Example Redeem Script (e.g., for a 2-of-2 multisig)
    // OP_2 <pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG
    // For simplicity, we'll use a simple P2PK script as a redeem script for P2SH
    const p2pkScript = bitcoin.payments.p2pk({ pubkey: exPubKey }).output;
    console.log("\nRedeem Script (P2PK used as example):", p2pkScript.toString('hex'));
    console.log("P2SH Address (from P2PK script):", converter.scriptToP2SH(p2pkScript));
    // For P2WSH, the script would typically be a multisig or other complex script
    console.log("P2WSH Address (from P2PK script):", converter.scriptToP2WSH(p2pkScript)); // bc1...
    console.log("P2SH-P2WSH Address (from P2PK script):", converter.scriptToP2SH_P2WSH(p2pkScript));


    console.log("\n--- TESTNET EXAMPLES ---");
    converter.setNetwork('testnet');
    console.log("Public Key:", exPubKey.toString('hex'));
    console.log("P2PKH Address (Testnet):", converter.pubkeyToP2PKH(exPubKey)); // m... or n...
    console.log("P2WPKH Address (Testnet):", converter.pubkeyToP2WPKH(exPubKey)); // tb1q...
    console.log("P2SH-P2WPKH Address (Testnet):", converter.pubkeyToP2SH_P2WPKH(exPubKey)); // 2...

    console.log("\nRedeem Script (P2PK used as example, Testnet):", p2pkScript.toString('hex')); // Script is network-agnostic
    const testnetP2PKScript = bitcoin.payments.p2pk({ pubkey: exPubKey, network: bitcoin.networks.testnet }).output;
    console.log("P2SH Address (Testnet, from P2PK script):", converter.scriptToP2SH(testnetP2PKScript)); // 2...
    console.log("P2WSH Address (Testnet, from P2PK script):", converter.scriptToP2WSH(testnetP2PKScript)); // tb1q...
    console.log("P2SH-P2WSH Address (Testnet, from P2PK script):", converter.scriptToP2SH_P2WSH(testnetP2PKScript));


    console.log("\n--- ADDRESS DECODING EXAMPLES ---");
    const p2pkhMainnet = converter.pubkeyToP2PKH(exPubKey);
    if(p2pkhMainnet) console.log(`Decoded P2PKH (${p2pkhMainnet}):`, JSON.stringify(converter.decodeAddress(p2pkhMainnet), null, 2));

    converter.setNetwork('bitcoin'); // Ensure mainnet for bech32 mainnet address
    const p2wpkhMainnet = converter.pubkeyToP2WPKH(exPubKey);
    if(p2wpkhMainnet) console.log(`Decoded P2WPKH (${p2wpkhMainnet}):`, JSON.stringify(converter.decodeAddress(p2wpkhMainnet), null, 2));

    converter.setNetwork('testnet'); // Switch to testnet for testnet address
    const p2wpkhTestnet = converter.pubkeyToP2WPKH(exPubKey);
    if(p2wpkhTestnet) console.log(`Decoded P2WPKH Testnet (${p2wpkhTestnet}):`, JSON.stringify(converter.decodeAddress(p2wpkhTestnet), null, 2));

    const p2shTestnet = converter.scriptToP2SH(testnetP2PKScript);
     if(p2shTestnet) console.log(`Decoded P2SH Testnet (${p2shTestnet}):`, JSON.stringify(converter.decodeAddress(p2shTestnet), null, 2));

    // Example of an invalid address
    console.log("Decoded Invalid Address:", converter.decodeAddress("invalidAddressString123"));

    console.log("\n--- GET HASH FROM ADDRESS EXAMPLES ---");
    converter.setNetwork('bitcoin'); // Mainnet for these examples
    const p2pkh_main = converter.pubkeyToP2PKH(exPubKey);
    if (p2pkh_main) {
        const hash_p2pkh = converter.getHashFromAddress(p2pkh_main);
        console.log(`Hash from P2PKH ${p2pkh_main}: ${hash_p2pkh ? hash_p2pkh.toString('hex') : 'null'}`);
        // Verify against direct HASH160
        const directHash160 = require('./crypto_utils').CryptoUtils.hash160(exPubKey);
        console.log(`Direct HASH160 of pubkey:      ${directHash160.toString('hex')}`);
        console.log(`Matches direct HASH160:        ${hash_p2pkh && directHash160.equals(hash_p2pkh)}`);
    }

    const p2wpkh_main = converter.pubkeyToP2WPKH(exPubKey);
    if (p2wpkh_main) {
        const hash_p2wpkh = converter.getHashFromAddress(p2wpkh_main);
        console.log(`Hash from P2WPKH ${p2wpkh_main}: ${hash_p2wpkh ? hash_p2wpkh.toString('hex') : 'null'}`);
        // This hash is also the HASH160 of the pubkey for P2WPKH
        const directHash160 = require('./crypto_utils').CryptoUtils.hash160(exPubKey); // Re-calculate for clarity
        console.log(`Direct HASH160 of pubkey:       ${directHash160.toString('hex')}`);
        console.log(`Matches direct HASH160:         ${hash_p2wpkh && directHash160.equals(hash_p2wpkh)}`);
    }

    converter.setNetwork('testnet');
    const p2sh_test = converter.scriptToP2SH(testnetP2PKScript); // Using the P2PK script from earlier
    if (p2sh_test) {
        const hash_p2sh = converter.getHashFromAddress(p2sh_test);
        console.log(`Hash from P2SH (testnet) ${p2sh_test}: ${hash_p2sh ? hash_p2sh.toString('hex') : 'null'}`);
        // Verify against direct HASH160 of the script
        const directScriptHash160 = require('./crypto_utils').CryptoUtils.hash160(testnetP2PKScript);
        console.log(`Direct HASH160 of script:             ${directScriptHash160.toString('hex')}`);
        console.log(`Matches direct script HASH160:        ${hash_p2sh && directScriptHash160.equals(hash_p2sh)}`);
    }
}

// runAddressConverterExamples(); // Uncomment to run example if testing this file directly with Node.js
*/

module.exports = AddressConverter;
