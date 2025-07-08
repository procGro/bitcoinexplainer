# Several interactive elliptic curve and bitcoin demonstrations.

 * [curve playground](https://rawcdn.githack.com/nlitsme/bitcoinexplainer/dc68354d7722b0b18cf887e383adc6fea8405648/curve.html)
 * [various ECDSA calculations](https://rawcdn.githack.com/nlitsme/bitcoinexplainer/dc68354d7722b0b18cf887e383adc6fea8405648/ecdsacrack.html)
    * demonstrate calculation of a publickey, also how to crack a key given a re-used signing secret.
 * [using linear algebra](https://rawcdn.githack.com/nlitsme/bitcoinexplainer/dc68354d7722b0b18cf887e383adc6fea8405648/linearequations.html) to crack groups of related keys.
 * [calculator](https://rawcdn.githack.com/nlitsme/bitcoinexplainer/dc68354d7722b0b18cf887e383adc6fea8405648/calculator.html) - a free form expression calculator.
 * [decode transactions](https://rawcdn.githack.com/nlitsme/bitcoinexplainer/dc68354d7722b0b18cf887e383adc6fea8405648/transaction.html)
 * [run tests](https://rawcdn.githack.com/nlitsme/bitcoinexplainer/dc68354d7722b0b18cf887e383adc6fea8405648/unittest.html) - used while developing, shows how the code is intended to be used.


Note that the javascript code works with both small integers and javascript's bigint numbers.

My elliptic curve implementations is intended to be readable, no attempt was made to make this
cryptographically safe.

The calculations are performed by your browser, no data is sent to a server.


# Installation

Some of the utilities in this project, particularly those related to Bitcoin backend operations (like RPC communication) or cryptographic functions, are designed as Node.js modules. To use them, you'll need Node.js and npm installed.

1.  Clone the repository (if you haven't already).
2.  Navigate to the project directory.
3.  Install dependencies:
    ```bash
    npm install
    ```
    This will install libraries such as `bitcoin-core` (for Bitcoin RPC) and `bitcoinjs-lib` (for various Bitcoin-related functions).

The HTML files can be opened directly in a web browser.

# Features

This project includes a variety of tools and demonstrations related to elliptic curves and Bitcoin. Below are details on some of the key JavaScript modules and functionalities.

## 1. Bitcoin RPC Client (`bitcoin_rpc.js`)

Provides a client to connect to a Bitcoin Core node via RPC.

*   **Functionality**:
    *   Connect to a Bitcoin node (mainnet, testnet, regtest).
    *   Fetch blockchain information (`getBlockchainInfo`).
    *   Fetch block data (`getBlockByHash`).
    *   Fetch raw transaction data (`getRawTransaction`).
    *   `findReusedSignatures(startBlockHeight, endBlockHeight)`: Scans a range of blocks to find transactions where ECDSA nonce (`k`) reuse might have occurred. This is critical for identifying vulnerabilities that could lead to private key exposure. It parses P2PKH, P2WPKH, and P2SH-P2WPKH inputs. (See also "Signature Reuse Scanning" below).
*   **Dependencies**: `bitcoin-core`, `bitcoinjs-lib`
*   **Usage (Node.js)**:
    ```javascript
    const BitcoinRPC = require('./bitcoin_rpc.js');

    // Example for a local regtest node
    const rpc = new BitcoinRPC({
        host: '127.0.0.1',
        network: 'regtest',
        username: 'your_rpc_user',
        password: 'your_rpc_password',
        port: 18443
    });

    async function example() {
        try {
            const info = await rpc.getBlockchainInfo();
            console.log('Blockchain Info:', info);
            if (info.blocks > 0) {
                const blockHash = await rpc.client.getBlockHash(0); // Requires bitcoin-core client directly for some methods
                const block = await rpc.getBlock(blockHash);
                console.log('Genesis Block:', block);
            }
        } catch (error) {
            console.error('RPC Example Error:', error);
        }
    }
    // example();
    ```

## 2. Address Converter (`address_converter.js`)

Handles conversion between various Bitcoin address formats and public keys/scripts.

*   **Functionality**:
    *   Convert public keys to P2PKH, P2WPKH (SegWit Bech32), and P2SH-P2WPKH (SegWit compatibility) addresses.
    *   Convert scripts to P2SH and P2WSH (SegWit Bech2) addresses.
    *   Decode existing Bitcoin addresses to extract their type, hash, and network.
    *   Extract the underlying hash (e.g., HASH160 or witness program) from an address string using `getHashFromAddress()`.
    *   Supports mainnet, testnet, and regtest networks.
*   **Dependencies**: `bitcoinjs-lib`
*   **Usage (Node.js or include in HTML)**:
    ```javascript
    const AddressConverter = require('./address_converter.js');
    const bitcoin = require('bitcoinjs-lib'); // For network objects if needed

    const converter = new AddressConverter(bitcoin.networks.testnet);
    const exPubKeyHex = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
    const exPubKey = Buffer.from(exPubKeyHex, 'hex');

    console.log("Testnet P2PKH:", converter.pubkeyToP2PKH(exPubKey));
    console.log("Testnet P2WPKH:", converter.pubkeyToP2WPKH(exPubKey));

    const p2wpkhAddress = converter.pubkeyToP2WPKH(exPubKey);
    if (p2wpkhAddress) {
        console.log("Decoded P2WPKH:", converter.decodeAddress(p2wpkhAddress));
        console.log("Hash from P2WPKH:", converter.getHashFromAddress(p2wpkhAddress).toString('hex'));
    }
    ```

## 3. Cryptographic Utilities (`crypto_utils.js`)

Provides various hashing functions commonly used in Bitcoin.

*   **Functionality**:
    *   `sha256(data)`: Computes SHA-256 hash.
    *   `hash256(data)`: Computes Double SHA-256 (SHA256(SHA256(data))).
    *   `ripemd160(data)`: Computes RIPEMD-160 hash.
    *   `hash160(data)`: Computes HASH160 (RIPEMD160(SHA256(data))).
    *   `hashMessageForSigning(messageString)`: Computes the hash for a message according to Bitcoin's signed message standard.
    *   `getTransactionId(transactionHex)`: Calculates the traditional transaction ID (txid).
    *   `getWitnessTransactionId(transactionHex)`: Calculates the witness transaction ID (wtxid).
    *   `recoverPrivateKeyFromKReuse(r, s1, h1, s2, h2, curveOrderN)`: Attempts to recover an ECDSA private key if the nonce 'k' was reused in two signatures sharing the same 'r' value. Uses functions from `bignum.js`.
*   **Dependencies**: `bitcoinjs-lib` (for varint encoding), Node.js `crypto` module, `bignum.js`.
*   **Usage (Node.js or include in HTML)**:
    ```javascript
    const CryptoUtils = require('./crypto_utils.js');

    const message = "Hello Bitcoin!";
    console.log("SHA256('test'):", CryptoUtils.sha256('test').toString('hex'));
    console.log("HASH160('test pubkey data'):", CryptoUtils.hash160('test pubkey data').toString('hex'));
    console.log("Bitcoin Signed Message Hash:", CryptoUtils.hashMessageForSigning(message).toString('hex'));

    const rawTxHex = "0100000001....00000000"; // Replace with actual raw tx hex
    // console.log("Transaction ID:", CryptoUtils.getTransactionId(rawTxHex));
    ```

## 4. Expression Calculator Enhancements (`expression.js`, `calculator.html`)

The expression parser used in `calculator.html` has been improved.

*   **Comment Support**: The calculator now ignores comments. Lines starting with `//` or `#` are treated as comments.
    *   Example: `1 + 1 # This is a comment` will evaluate to `2`.
*   **Unary Operator Support**: The parser now supports unary `+` and `-` operators.
    *   Example: `-5 + 10` will evaluate to `5`. `-(1+2)` will evaluate to `-3`.

## 5. Real Elliptic Curve Grid Display (`realcurve.html`)

The `realcurve.html` page has been updated to display a grid of several real-valued elliptic curves.

*   **Functionality**: Shows a 2x2 grid of curves (`y^2 = x^3 + ax + b`) with different `a` and `b` parameters. Each curve is plotted on a separate canvas, labeled with its parameters and discriminant. This provides a visual comparison of how `a` and `b` affect the curve's shape.

## 6. Real-Valued Logarithms (`real.js`)

The `RealNumbers` class in `real.js` (used by `realcurve.html` and potentially other modules) now supports logarithm calculations.

*   **Functionality**:
    *   `ln(value)`: Natural logarithm.
    *   `log10(value)`: Base-10 logarithm.
    *   `log2(value)`: Base-2 logarithm.
    *   `log(base, value)`: Logarithm with a custom base.
*   **Usage (within a context using `RealNumbers`)**:
    ```javascript
    // const R = new RealNumbers();
    // const val = R.value(100);
    // console.log("ln(100):", R.ln(val).toString());       // ~4.605
    // console.log("log10(100):", R.log10(val).toString()); // 2
    // console.log("log2(100):", R.log(R.value(2), val).toString()); // ~6.643
    ```

## 7. Improved Annotated Value Display (`transaction.html`)

The display of annotated transaction details in `transaction.html` has been enhanced.

*   **Functionality**: When viewing the annotated structure of a transaction, hovering over elements like `<script>`, `<txnid>`, `<varlen>`, etc., will now show a tooltip (using the browser's native `title` attribute) displaying the attributes of that XML node (e.g., `tag: "in"`, `value: "0123af..."`). This provides more context without cluttering the main display.

## 8. Signature Reuse Scanning and Private Key Recovery (`scan_reuse.js`)

A Node.js script to scan a range of Bitcoin blocks for ECDSA `k`-value reuse and attempt private key recovery.

*   **Functionality**:
    *   Connects to a Bitcoin Core node using RPC.
    *   Scans specified blocks using `bitcoin_rpc.js#findReusedSignatures` to identify pairs of signatures from the same public key that share the same `r` value but sign different message hashes.
    *   For each identified pair, it attempts to recover the private key using `crypto_utils.js#recoverPrivateKeyFromKReuse`.
    *   If successful, it verifies the recovered private key by deriving its public key and comparing it to the original. It then derives and prints P2PKH and P2WPKH addresses.
*   **Dependencies**: `bitcoin_rpc.js`, `crypto_utils.js`, `bitcoinjs-lib`, `ecpair`.
*   **Usage (Node.js CLI)**:
    ```bash
    node scan_reuse.js --startBlock <block_height> [options]
    ```
*   **Command-Line Options**:
    *   `--startBlock <number>`: (Required) The block height to start scanning from.
    *   `--endBlock <number>`: (Optional) The block height to end scanning at. Defaults to scanning only the `startBlock`.
    *   `--network <mainnet|testnet|regtest>`: (Optional) Defaults to `mainnet`.
    *   `--host <ip/hostname>`: (Optional) RPC host. Defaults to `localhost`.
    *   `--port <number>`: (Optional) RPC port (defaults based on network).
    *   `--user <username>`: (Optional) RPC username.
    *   `--pass <password>`: (Optional) RPC password.
*   **Example**:
    ```bash
    node scan_reuse.js --network regtest --startBlock 110 --endBlock 120 --user myrpcuser --pass myrpcpassword
    ```
*   **Output**: The script logs its progress, details of any k-reuse candidates found, and the results of private key recovery attempts, including the recovered private key (hex) and derived addresses if successful.

# Remaining To-Do Items

The original `todo` list has been significantly addressed. Any remaining items or new ideas can be tracked here.
(The original list of todos from the README is now largely completed by the features above).
The `findReusedSignatures` function in `bitcoin_rpc.js` could be extended to support more script types (P2PK, P2MS, P2WSH, Taproot) for broader analysis.

# AUTHOR

Willem Hengeveld <itsme@xs4all.nl>
(Contributions by AI Assistant)

