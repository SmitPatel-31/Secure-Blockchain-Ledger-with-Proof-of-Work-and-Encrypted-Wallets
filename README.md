# Secure Blockchain Ledger

Secure-Blockchain-Ledger-with-Proof-of-Work-and-Encrypted-Wallets is a C++17 reference implementation of a minimal blockchain. It provides a command-line interface for creating wallets, signing transactions, mining proof-of-work blocks, persisting the ledger to disk, and validating integrity using OpenSSL-backed cryptography.

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Build](#build)
- [Run](#run)
- [CLI Walkthrough](#cli-walkthrough)
- [Data & Persistence](#data--persistence)
- [Encrypted Wallet API](#encrypted-wallet-api)
- [Extending the Project](#extending-the-project)
- [Troubleshooting](#troubleshooting)

## Overview
The application models a simplified blockchain suitable for learning and experimentation. Each block links to its predecessor via a SHA-256 hash and is mined by searching for a nonce that produces a hash with a given number of leading zeros. Transactions are signed with RSA key pairs and verified during validation to protect the chain from tampering.

A lightweight CLI binary, `secure-blockchain`, allows you to:
- Create encrypted wallets (public / private RSA keys stored with AES-256-CBC)
- Load previously saved wallets into the current session
- Create signed transactions between wallets
- Mine pending transactions into new blocks using proof-of-work
- Persist and reload the chain from `data/chain.json`
- Validate the entire chain, including signatures and hash continuity

## Features
- **Proof-of-Work Mining** — Adjustable difficulty target (default 4 leading zeros) enforced when mining new blocks.
- **RSA-Secured Transactions** — Each transaction digest is signed with the sender’s private key and verified against the stored public key.
- **JSON Ledger Persistence** — Blocks and mempool entries are serialized to disk, enabling reload across sessions.
- **Encrypted Wallet Utility** — `Wallet` provides AES-256-CBC encrypted private key storage backed by PBKDF2 key derivation.
- **Self-Validation** — End-to-end chain validation recomputes hashes, checks previous-hash links, and ensures transaction signatures are authentic.
- **Modular C++ Codebase** — Blocks, transactions, crypto primitives, and wallet management are isolated for reuse or extension.

## Project Structure
- `src/main.cpp` — Interactive CLI for wallet management, transactions, mining, and validation.
- `src/blockchain.cpp` / `src/blockchain.h` — Core blockchain logic, mempool management, JSON persistence.
- `src/block.cpp` / `src/block.h` — Block representation, hashing, and proof-of-work mining loop.
- `src/transaction.cpp` / `src/transaction.h` — Transaction digest construction and signature verification.
- `src/crypto_utils.cpp` / `src/crypto_utils.h` — OpenSSL wrappers for SHA-256, RSA key generation, signing, and verification.
- `src/wallet.cpp` / `src/wallet.h` — Password-based encrypted wallet loading/saving (AES-256-CBC + PBKDF2).
- `data/` — Default location for the persisted chain JSON.
- `CMakeLists.txt` — Build configuration targeting C++17 with OpenSSL.

## Prerequisites
- CMake **3.15+**
- A C++17-capable compiler (GCC, Clang, or MSVC)
- OpenSSL development headers and libraries (e.g., `libssl-dev` on Debian/Ubuntu, `openssl` via Homebrew on macOS)

Verify OpenSSL headers are discoverable by CMake before building.

## Build
```bash
mkdir -p build
cd build
cmake ..
cmake --build .
```

The resulting executable is placed at `build/secure-blockchain`.

## Run
From the `build/` directory, run:
```bash
cd build
./secure-blockchain
```

Alternatively, invoke it from the repository root via `./build/secure-blockchain`.

On first launch, a new chain is created at the configured difficulty. Subsequent runs automatically reload any previously persisted ledger from `data/chain.json`.

## CLI Walkthrough
The CLI prints a menu each loop iteration. The most common workflow is:

1. **Create wallet** — Generates a fresh RSA key pair, encrypts the private key with the password you supply, and saves it (default `data/wallets/<label>.wallet`).
2. **Load wallet** — Imports an existing encrypted wallet file back into the session after you provide the correct password.
3. **Make transaction** — Choose a sender wallet, receiver wallet, and amount. Transactions are signed with the sender’s private key (prompted password) and added to the mempool.
4. **Mine block** — Select a miner wallet to receive the block reward (reward logic can be added). Mining consumes the mempool and persists the block once proof-of-work is satisfied.
5. **Print chain** — View block indices, hash previews, and transaction counts.
6. **Validate chain** — Re-run integrity checks: hash linkage, difficulty rule, and signature verification.

Enter `0` to exit. The application attempts to save the chain on every mutation and before shutdown; failures are reported in the console.

### Tips
- At least two wallets are required to create a transaction (sender and receiver).
- Mining requires at least one wallet to serve as the miner.
- Leaving a prompt blank cancels the current action; EOF (`Ctrl+D`/`Ctrl+Z`) exits the program.

## Data & Persistence
- Ledger state is persisted as JSON in `data/chain.json`.
- Encrypted wallet files are stored wherever you choose (default `data/wallets/`). Each file contains a base64-encoded record of the encrypted private key alongside the public key, salt, and IV.
- Each block stores index, previous hash, timestamp, nonce, hash, and an array of serialized transactions.
- Pending (unmined) transactions remain in the `mempool` section until mined.
- The blockchain automatically creates the `data/` directory if it does not exist.

To reset the ledger, delete `data/chain.json` before launching the CLI (or keep backups for experimentation).

## Encrypted Wallet API
The CLI uses the encrypted wallet API exposed in `src/wallet.h`, and you can also work with it directly from your own code:

```cpp
#include "wallet.h"

int main() {
    Wallet wallet = Wallet::Create("strong-password");
    wallet.Save("wallets/alice.wallet");  // AES-256-CBC encrypted private key

    Wallet loaded = Wallet::Load("wallets/alice.wallet", "strong-password");
    std::string signature = loaded.sign("hello chain", "strong-password");
}
```

Under the hood:
- Private keys are encrypted with AES-256-CBC.
- Keys are derived via PBKDF2 (100,000 iterations, 128-bit salt).
- Files are base64-encoded `key=value` pairs for interoperability.

Use this API from custom tooling or scripts to create/load wallets outside the bundled CLI.

## Extending the Project
Consider experimenting with:
- Adding transaction fees and coinbase rewards during mining.
- Persisting wallet metadata and balances.
- Replacing the CLI workflow with a REST API or graphical dashboard.
- Increasing difficulty dynamically based on chain length or mining speed.
- Implementing unit tests (e.g., using Catch2 or GoogleTest) for critical components.

## Troubleshooting
- **CMake cannot find OpenSSL** — Ensure OpenSSL is installed and available on your system path. On macOS, run `brew install openssl` and pass `-DOPENSSL_ROOT_DIR=$(brew --prefix openssl)` to CMake if needed.
- **Encrypted wallet load failure** — When using the `Wallet` API, an incorrect password causes load/sign operations to throw. Re-enter the password used when saving.
- **Chain fails validation** — Corrupted or manually edited `data/chain.json` files will be rejected. Delete the file to start fresh if necessary.

Enjoy experimenting with your secure blockchain ledger!
