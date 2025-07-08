// bitcoin_rpc.js

const Client = require('bitcoin-core');
const bitcoin = require('bitcoinjs-lib');

// Helper function to parse signature and public key from scriptSig (P2PKH)
// Returns { signature: Buffer, pubkey: Buffer } or null
function parseP2PKHInput(scriptSig) {
    try {
        const chunks = bitcoin.script.decompile(scriptSig);
        if (chunks && chunks.length === 2 && Buffer.isBuffer(chunks[0]) && Buffer.isBuffer(chunks[1])) {
            // chunks[0] is DER signature, chunks[1] is public key
            return { signature: chunks[0], pubkey: chunks[1] };
        }
    } catch (e) { /* console.error("P2PKH script decompilation error", e); */ }
    return null;
}

// Helper function to parse signature and public key from witness (P2WPKH)
// Returns { signature: Buffer, pubkey: Buffer } or null
function parseP2WPKHInput(witness) {
    if (witness && witness.length === 2 && Buffer.isBuffer(witness[0]) && Buffer.isBuffer(witness[1])) {
        // witness[0] is DER signature, witness[1] is public key
        return { signature: witness[0], pubkey: witness[1] };
    }
    return null;
}


class BitcoinRPC {
    constructor(options = {}) {
        let rpcHost = options.host || 'localhost';
        // If options.host already includes a protocol, use it directly.
        // Otherwise, default to http. The user can override by providing full URL in options.host.
        if (!rpcHost.includes('://')) {
            rpcHost = 'http://' + rpcHost;
        }

        this.client = new Client({
            host: rpcHost, // User can provide full URL like https://host:port/path
            network: options.network || 'mainnet',
            username: options.username,
            password: options.password,
            port: options.port || (options.network === 'regtest' ? 18443 : (options.network === 'testnet' ? 18332 : 8332)), // Port might be part of host if full URL
            timeout: options.timeout || 30000,
        });

        // Determine the bitcoinjs-lib network object based on the network string
        if (options.network === 'testnet') {
            this.bitcoinJsNetwork = bitcoin.networks.testnet;
        } else if (options.network === 'regtest') {
            this.bitcoinJsNetwork = bitcoin.networks.regtest;
        } else {
            this.bitcoinJsNetwork = bitcoin.networks.bitcoin;
        }
    }

    async getBlockchainInfo() {
        try {
            const info = await this.client.getBlockchainInfo();
            return info;
        } catch (error) {
            console.error('Error getting blockchain info:', error);
            throw error;
        }
    }

    async getBlockByHash(blockHash, verbosity = 2) { // Default to verbosity 2 for tx data
        try {
            const block = await this.client.getBlock(blockHash, verbosity);
            return block;
        } catch (error) {
            console.error(`Error getting block ${blockHash}:`, error);
            throw error;
        }
    }

    async getRawTransaction(txid, verbose = true) {
        try {
            const transaction = await this.client.getRawTransaction(txid, verbose);
            return transaction;
        } catch (error) {
            console.error(`Error getting raw transaction ${txid}:`, error);
            throw error;
        }
    }

    async findReusedSignatures(startBlockHeight, endBlockHeight) {
        console.log(`Searching for reused signatures from block ${startBlockHeight} to ${endBlockHeight}`);

        const signatureMap = new Map(); // Map<pubkeyHex, Map<rHex, Array<{sHex, messageHashHex, txid, inIndex, scriptPubKeyHex, sighashType, blockHeight}>>>
        const reusedSignaturesOutput = [];

        for (let height = startBlockHeight; height <= endBlockHeight; height++) {
            let blockData;
            try {
                const blockHash = await this.client.getBlockHash(height);
                blockData = await this.getBlockByHash(blockHash, 2); // verbosity = 2 for full transaction objects
                 if (!blockData || !blockData.tx) {
                    console.warn(`Block ${height} has no transactions or could not be fetched.`);
                    continue;
                }
            } catch (error) {
                console.error(`Error fetching block ${height} (hash or data):`, error);
                continue;
            }

            for (const txData of blockData.tx) {
                const txid = txData.txid;
                const rawTxHex = txData.hex;
                if (!rawTxHex) {
                    console.warn(`Raw hex not found for tx ${txid} in block ${height}`);
                    continue;
                }

                let tx;
                try {
                    tx = bitcoin.Transaction.fromHex(rawTxHex);
                } catch (e) {
                    console.warn(`Failed to parse tx ${txid} from hex: ${e.message}`);
                    continue;
                }

                for (let inIndex = 0; inIndex < tx.ins.length; inIndex++) {
                    const input = tx.ins[inIndex];
                    if (Buffer.compare(input.hash, Buffer.alloc(32, 0)) === 0) { // Coinbase check (tx hash is all zeros)
                        continue;
                    }

                    const prevTxid = Buffer.from(input.hash).reverse().toString('hex');
                    const prevOutIndex = input.index;

                    let prevOut = null;
                    const vinEntry = txData.vin.find(v => v.txid === prevTxid && v.vout === prevOutIndex);

                    if (vinEntry && vinEntry.prevout && vinEntry.prevout.scriptPubKey && vinEntry.prevout.scriptPubKey.hex !== undefined && vinEntry.prevout.value !== undefined) {
                         prevOut = vinEntry.prevout;
                    } else {
                        try {
                            const prevTxVerboseData = await this.getRawTransaction(prevTxid, true);
                            if (!prevTxVerboseData || !prevTxVerboseData.vout || !prevTxVerboseData.vout[prevOutIndex]) {
                                console.warn(`Could not get prevOut for ${prevTxid}:${prevOutIndex} for tx ${txid}`);
                                continue;
                            }
                            prevOut = prevTxVerboseData.vout[prevOutIndex];
                        } catch (e) {
                            console.warn(`Error fetching prevTx ${prevTxid} for input of ${txid}: ${e.message}`);
                            continue;
                        }
                    }

                    const scriptPubKeyHex = prevOut.scriptPubKey.hex;
                    const scriptPubKey = Buffer.from(scriptPubKeyHex, 'hex');
                    const value = Math.round(prevOut.value * 1e8);

                    let sigAndPubKey = null;
                    let scriptType = 'unknown';
                    const outputType = bitcoin.script.classifyOutput(scriptPubKey);

                    if (outputType === 'witnesspubkeyhash') {
                        sigAndPubKey = parseP2WPKHInput(input.witness);
                        scriptType = 'p2wpkh';
                    } else if (outputType === 'pubkeyhash') {
                        sigAndPubKey = parseP2PKHInput(input.script);
                        scriptType = 'p2pkh';
                    } else if (outputType === 'scripthash') {
                        const redeemScriptChunk = bitcoin.script.decompile(input.script).pop();
                        if (Buffer.isBuffer(redeemScriptChunk)) {
                            const redeemScript = redeemScriptChunk;
                            const redeemOutputType = bitcoin.script.classifyOutput(redeemScript);
                            if (redeemOutputType === 'witnesspubkeyhash') {
                                sigAndPubKey = parseP2WPKHInput(input.witness);
                                scriptType = 'p2sh-p2wpkh';
                            } else {
                                // console.debug(`Unsupported P2SH redeem script type: ${redeemOutputType} for ${txid}:${inIndex}`);
                            }
                        }
                    } else {
                        // console.debug(`Unsupported scriptPubKey type: ${outputType} for ${txid}:${inIndex}`);
                    }

                    if (sigAndPubKey && sigAndPubKey.signature && sigAndPubKey.pubkey) {
                        const { signature, pubkey } = sigAndPubKey;
                        const pubkeyHex = pubkey.toString('hex');

                        if (signature.length < 8 || signature.length > 80) { // Basic sanity for DER (min size, typical max)
                            // console.debug(`Invalid signature length for ${txid}:${inIndex}: ${signature.length}`);
                            continue;
                        }
                        const sighashType = signature[signature.length - 1];

                        let derSignatureOnly;
                        let decodedSigParts;
                        try {
                            derSignatureOnly = signature.slice(0, -1);
                            decodedSigParts = bitcoin.script.signature.decode(derSignatureOnly);
                        } catch (e) {
                            // console.debug(`Failed to decode DER signature for ${txid}:${inIndex}: ${e.message}, sig hex: ${signature.toString('hex')}`);
                            continue;
                        }

                        const R = decodedSigParts.r; // R value as Buffer
                        const S = decodedSigParts.s; // S value as Buffer

                        const rHex = R.toString('hex').padStart(64, '0'); // Ensure 32 bytes hex
                        const sHex = S.toString('hex').padStart(64, '0'); // Ensure 32 bytes hex


                        let messageHash;
                        try {
                            if (scriptType === 'p2wpkh' || scriptType === 'p2sh-p2wpkh') {
                                messageHash = tx.hashForWitnessV0(inIndex, scriptType === 'p2sh-p2wpkh' ? bitcoin.payments.p2wpkh({ pubkey, network: this.bitcoinJsNetwork }).output : scriptPubKey, value, sighashType);
                            } else if (scriptType === 'p2pkh') {
                                messageHash = tx.hashForSignature(inIndex, scriptPubKey, sighashType);
                            } else {
                                continue;
                            }
                        } catch (e) {
                            console.warn(`Error calculating sighash for ${txid}:${inIndex} (${scriptType}): ${e.message}`);
                            continue;
                        }
                        const messageHashHex = messageHash.toString('hex');

                        if (!signatureMap.has(pubkeyHex)) {
                            signatureMap.set(pubkeyHex, new Map());
                        }
                        const rMap = signatureMap.get(pubkeyHex);
                        if (!rMap.has(rHex)) {
                            rMap.set(rHex, []);
                        }
                        const entries = rMap.get(rHex);

                        const existingEntryForMsg = entries.find(e => e.messageHashHex === messageHashHex && e.sHex === sHex);
                        if (existingEntryForMsg) {
                            continue;
                        }

                        entries.push({
                            sHex, messageHashHex, txid, inIndex, blockHeight: height, sighashType, scriptPubKeyHex
                        });

                        if (entries.length > 1) {
                            for (let i = 0; i < entries.length; i++) {
                                for (let j = i + 1; j < entries.length; j++) {
                                    if (entries[i].messageHashHex !== entries[j].messageHashHex) {
                                        const reportKey1 = `${entries[i].txid}:${entries[i].inIndex}-${entries[j].txid}:${entries[j].inIndex}-${rHex}`;
                                        const reportKey2 = `${entries[j].txid}:${entries[j].inIndex}-${entries[i].txid}:${entries[i].inIndex}-${rHex}`;

                                        let alreadyReported = reusedSignaturesOutput.some(r => {
                                            let key = `${r.sig1.txid}:${r.sig1.inIndex}-${r.sig2.txid}:${r.sig2.inIndex}-${r.rHex}`;
                                            let keyRev = `${r.sig2.txid}:${r.sig2.inIndex}-${r.sig1.txid}:${r.sig1.inIndex}-${r.rHex}`;
                                            return key === reportKey1 || key === reportKey2 || keyRev === reportKey1 || keyRev === reportKey2;
                                        });

                                        if (!alreadyReported) {
                                            reusedSignaturesOutput.push({
                                                pubkeyHex, rHex,
                                                sig1: entries[i],
                                                sig2: entries[j],
                                                type: "k-reuse candidate"
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // Log progress more frequently if many blocks, less if few.
            const logInterval = Math.max(1, Math.min(10, Math.floor((endBlockHeight - startBlockHeight + 1) / 10)));
            if (height === startBlockHeight || (height - startBlockHeight) % logInterval === 0 || height === endBlockHeight ) {
                 console.log(`Processed block ${height}... Found ${reusedSignaturesOutput.length} potential k-reuse candidates so far.`);
            }
        }
        console.log("Signature scan complete.");
        return reusedSignaturesOutput;
    }
}

// Example Usage (primarily for testing purposes, will be removed or refactored)
/*
async function main() {
    // Configuration for a local Bitcoin Core node (regtest example)
    // Ensure your bitcoin.conf is set up with rpcuser, rpcpassword, and server=1
    // Also, ensure rpcallowip is set appropriately if not running on the same machine.
    const rpc = new BitcoinRPC({
        host: '127.0.0.1', // Your Bitcoin node's IP
        network: 'regtest', // or 'testnet' or 'mainnet'
        username: 'your_rpc_user',     // Replace with your RPC username
        password: 'your_rpc_password', // Replace with your RPC password
        port: 18443, // Default regtest RPC port (mainnet is 8332, testnet is 18332)
    });

    try {
        const info = await rpc.getBlockchainInfo();
        console.log('Blockchain Info:', info);

        if (info.blocks > 0) {
            // Example: Scan a small range of blocks if available
            const startBlock = Math.max(0, info.blocks - 5); // Scan last 5 blocks or from 0
            const endBlock = info.blocks;
            console.log(`Scanning from block ${startBlock} to ${endBlock}`);

            const reusedSigs = await rpc.findReusedSignatures(startBlock, endBlock);
            if (reusedSigs.length > 0) {
                console.log("\n--- Potential k-Reuse Candidates Found ---");
                reusedSigs.forEach(reuse => {
                    console.log(JSON.stringify(reuse, null, 2));
                });
            } else {
                console.log("\nNo potential k-reuse candidates found in the scanned range.");
            }
        } else {
            console.log('No blocks in the current chain to scan.');
        }

    } catch (error) {
        console.error('Failed to run example:', error);
    }
}

// To run this example:
// 1. Make sure you have a Bitcoin node running (regtest, testnet, or mainnet).
// 2. Configure the BitcoinRPC connection options above.
// 3. If using regtest, generate some blocks and transactions, potentially with k-reuse if testing recovery.
// 4. Uncomment the line below and run `node bitcoin_rpc.js`
// main();
*/

module.exports = BitcoinRPC;
