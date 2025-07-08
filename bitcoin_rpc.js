// bitcoin_rpc.js

const Client = require('bitcoin-core');

class BitcoinRPC {
    constructor(options = {}) {
        this.client = new Client({
            host: options.host || 'localhost', // Default to localhost
            network: options.network || 'mainnet', // Default to mainnet
            username: options.username,
            password: options.password,
            port: options.port || 8332, // Default Bitcoin Core RPC port
            timeout: options.timeout || 30000,
        });
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

    async getBlock(blockHash) {
        try {
            // Assuming verbose output (JSON) by default
            const block = await this.client.getBlock(blockHash, true);
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

    // Placeholder for the signature reuse detection logic
    async findReusedSignatures(startBlockHeight, endBlockHeight) {
        console.log(`Searching for reused signatures from block ${startBlockHeight} to ${endBlockHeight}`);
        // Implementation will involve:
        // 1. Iterating through blocks in the given range.
        // 2. For each block, iterate through its transactions.
        // 3. For each transaction, examine its inputs (vin).
        // 4. For each input, extract the signature and public key (or address).
        // 5. Store encountered signatures and their associated public keys/addresses.
        // 6. If a signature is seen again with a *different* transaction but the *same* public key/address,
        //    it's a potential reuse (especially if it's signing different data).
        //    A simpler check could be to just find identical (signature, pubkey/address) pairs across different tx inputs.

        // This is a complex task and will require careful handling of Bitcoin transaction structures.
        // For now, this is a placeholder.

        const reusedSignatures = []; // Array to store findings

        for (let height = startBlockHeight; height <= endBlockHeight; height++) {
            try {
                const blockHash = await this.client.getBlockHash(height);
                const block = await this.getBlock(blockHash); // Verbose block data

                if (block && block.tx) {
                    for (const txid of block.tx) {
                        const transaction = await this.getRawTransaction(txid, true); // Verbose transaction data

                        if (transaction && transaction.vin) {
                            for (const input of transaction.vin) {
                                // Signatures are usually in input.scriptSig.asm or input.txinwitness
                                // This part needs detailed implementation based on transaction types (P2PKH, P2WPKH, etc.)
                                // For example:
                                // if (input.scriptSig && input.scriptSig.asm) {
                                // const scriptParts = input.scriptSig.asm.split(' ');
                                // const signature = scriptParts[0]; // This is a simplification
                                // const pubkey = scriptParts[1]; // This is a simplification

                                // Add logic to store and compare (signature, pubkey)
                                // }
                            }
                        }
                    }
                }
                console.log(`Processed block ${height}`);
            } catch (error) {
                console.error(`Error processing block ${height}:`, error);
                // Decide how to handle errors: skip block, retry, or stop.
            }
        }
        return reusedSignatures;
    }
}

// Example Usage (primarily for testing purposes, will be removed or refactored)
/*
async function main() {
    // Configuration for a local Bitcoin Core node (regtest example)
    // Ensure your bitcoin.conf is set up with rpcuser, rpcpassword, and server=1
    // Also, ensure rpcallowip is set appropriately if not running on the same machine.
    const rpc = new BitcoinRPC({
        host: '127.0.0.1',
        network: 'regtest', // or 'testnet' or 'mainnet'
        username: 'your_rpc_user',     // Replace with your RPC username
        password: 'your_rpc_password', // Replace with your RPC password
        port: 18443, // Default regtest RPC port (mainnet is 8332, testnet is 18332)
    });

    try {
        const info = await rpc.getBlockchainInfo();
        console.log('Blockchain Info:', info);

        // Example: Get the genesis block hash (height 0) and then the block
        if (info.blocks > 0) {
            const blockHashAtHeight0 = await rpc.client.getBlockHash(0);
            console.log('Block hash at height 0:', blockHashAtHeight0);
            const block0 = await rpc.getBlock(blockHashAtHeight0);
            console.log('Block at height 0:', block0);

            // Example: Find reused signatures (placeholder call)
            // This will require a running node with some blocks.
            // On regtest, you'd need to generate some blocks and transactions.
            // const reused = await rpc.findReusedSignatures(0, info.blocks);
            // console.log('Reused signatures found:', reused);
        } else {
            console.log('No blocks in the current chain to fetch.');
        }

    } catch (error) {
        console.error('Failed to run example:', error);
    }
}

// main(); // Uncomment to run example if testing this file directly with Node.js
*/

module.exports = BitcoinRPC;
