#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "blockchain.h"
#include "crypto_utils.h"
#include "transaction.h"

namespace {

struct Wallet {
    std::string label;
    std::string publicKey;
    std::string privateKey;
};

bool promptLine(const std::string& message, std::string& output) {
    std::cout << message;
    std::cout.flush();
    if (!std::getline(std::cin, output)) {
        return false;
    }
    return true;
}

void printWallets(const std::vector<Wallet>& wallets) {
    if (wallets.empty()) {
        std::cout << "No wallets available. Create one first.\n";
        return;
    }

    std::cout << "Wallets:\n";
    for (std::size_t i = 0; i < wallets.size(); ++i) {
        std::string preview = wallets[i].publicKey;
        if (preview.size() > 24) {
            preview = preview.substr(0, 24) + "...";
        }
        std::cout << "  [" << i << "] " << wallets[i].label << " (" << preview << ")\n";
    }
}

bool selectWallet(const std::vector<Wallet>& wallets,
                  const std::string& message,
                  int& indexOut) {
    std::string input;
    while (true) {
        if (!promptLine(message, input)) {
            return false;
        }
        if (input.empty()) {
            indexOut = -1;
            return true;
        }
        try {
            const std::size_t idx = std::stoul(input);
            if (idx < wallets.size()) {
                indexOut = static_cast<int>(idx);
                return true;
            }
        } catch (const std::exception&) {
        }
        std::cout << "Invalid selection. Enter index or press Enter to cancel.\n";
    }
}

bool handleCreateWallet(std::vector<Wallet>& wallets) {
    Wallet wallet;
    if (!promptLine("Enter wallet label (optional): ", wallet.label)) {
        return false;
    }
    if (wallet.label.empty()) {
        wallet.label = "Wallet " + std::to_string(wallets.size());
    }

    if (!generateKeyPair(wallet.publicKey, wallet.privateKey)) {
        std::cout << "Failed to create wallet.\n";
        return true;
    }

    wallets.push_back(std::move(wallet));
    std::cout << "Created wallet #" << (wallets.size() - 1) << " ("
              << wallets.back().label << ")\n";
    return true;
}

bool handleMakeTransaction(const std::vector<Wallet>& wallets,
                           Blockchain& chain,
                           const std::string& storagePath) {
    if (wallets.size() < 2) {
        std::cout << "Need at least two wallets to create a transaction.\n";
        return true;
    }

    printWallets(wallets);

    int senderIdx = -1;
    if (!selectWallet(wallets, "Select sender wallet index (blank to cancel): ", senderIdx)) {
        return false;
    }
    if (senderIdx < 0) {
        std::cout << "Transaction cancelled.\n";
        return true;
    }

    int receiverIdx = -1;
    if (!selectWallet(wallets, "Select receiver wallet index (blank to cancel): ", receiverIdx)) {
        return false;
    }
    if (receiverIdx < 0) {
        std::cout << "Transaction cancelled.\n";
        return true;
    }
    if (senderIdx == receiverIdx) {
        std::cout << "Sender and receiver must be different.\n";
        return true;
    }

    std::string amountLine;
    if (!promptLine("Enter amount: ", amountLine)) {
        return false;
    }
    if (amountLine.empty()) {
        std::cout << "Amount entry cancelled.\n";
        return true;
    }

    double amount = 0.0;
    try {
        amount = std::stod(amountLine);
    } catch (const std::exception&) {
        std::cout << "Invalid amount.\n";
        return true;
    }
    if (amount <= 0.0) {
        std::cout << "Amount must be positive.\n";
        return true;
    }

    Transaction tx{};
    tx.senderPub = wallets[senderIdx].publicKey;
    tx.receiverPub = wallets[receiverIdx].publicKey;
    tx.amount = amount;

    try {
        tx.signature = signData(tx.digest(), wallets[senderIdx].privateKey);
    } catch (const std::exception& ex) {
        std::cout << "Failed to sign transaction: " << ex.what() << "\n";
        return true;
    }

    chain.addTransaction(tx);
    std::cout << "Transaction queued. Pending transactions: " << chain.pendingCount() << "\n";
    if (!saveChainJson(chain, storagePath)) {
        std::cout << "Warning: failed to save chain to " << storagePath << "\n";
    }
    return true;
}

bool handleMine(Blockchain& chain,
                const std::vector<Wallet>& wallets,
                const std::string& storagePath) {
    if (!chain.hasPending()) {
        std::cout << "No pending transactions to mine.\n";
        return true;
    }
    if (wallets.empty()) {
        std::cout << "Create a wallet to serve as miner first.\n";
        return true;
    }

    printWallets(wallets);

    int minerIdx = -1;
    if (!selectWallet(wallets, "Select miner wallet index (blank to cancel): ", minerIdx)) {
        return false;
    }
    if (minerIdx < 0) {
        std::cout << "Mining cancelled.\n";
        return true;
    }

    const std::size_t before = chain.blocks().size();
    chain.minePending(wallets[minerIdx].publicKey);

    if (chain.blocks().size() > before) {
        const Block& mined = chain.tip();
        const std::string hashPreview =
            mined.hash.size() > 10 ? mined.hash.substr(0, 10) + "..." : mined.hash;
        std::cout << "Mined block #" << mined.index << " (" << hashPreview << ")\n";
        if (saveChainJson(chain, storagePath)) {
            std::cout << "Chain saved to " << storagePath << "\n";
        } else {
            std::cout << "Warning: failed to save chain to " << storagePath << "\n";
        }
    } else {
        std::cout << "No block mined. Pending transactions may have been empty.\n";
    }

    return true;
}

void printChain(const Blockchain& chain) {
    const auto& blocks = chain.blocks();
    if (blocks.empty()) {
        std::cout << "Chain is empty.\n";
        return;
    }
    std::cout << "Chain height: " << blocks.size() - 1 << " ("
              << blocks.size() << " blocks total)\n";
    for (const auto& block : blocks) {
        const std::string hashPreview =
            block.hash.size() > 10 ? block.hash.substr(0, 10) + "..." : block.hash;
        std::cout << "  [" << block.index << "] " << hashPreview
                  << " | tx count: " << block.txs.size() << "\n";
    }
}

void printMenu(const Blockchain& chain, std::size_t walletCount) {
    std::cout << "\n=== Secure Blockchain CLI ===\n";
    std::cout << "Wallets: " << walletCount << " | Pending TX: " << chain.pendingCount()
              << " | Blocks: " << chain.blocks().size() << "\n";
    std::cout << "1) Create wallet\n";
    std::cout << "2) Make transaction\n";
    std::cout << "3) Mine block\n";
    std::cout << "4) Print chain\n";
    std::cout << "5) Validate chain\n";
    std::cout << "0) Exit\n";
}

}  // namespace

int main() {
    try {
        Blockchain chain;
        const std::string storagePath = "data/chain.json";

        if (loadChainJson(chain, storagePath)) {
            std::cout << "Loaded blockchain from " << storagePath << " ("
                      << chain.blocks().size() << " blocks)\n";
        } else {
            std::cout << "Starting new blockchain (difficulty "
                      << chain.getDifficulty() << ")\n";
        }

        std::vector<Wallet> wallets;

        bool running = true;
        while (running) {
            printMenu(chain, wallets.size());

            std::string choice;
            if (!promptLine("Select option: ", choice)) {
                break;
            }

            if (choice == "1") {
                running = handleCreateWallet(wallets);
            } else if (choice == "2") {
                running = handleMakeTransaction(wallets, chain, storagePath);
            } else if (choice == "3") {
                running = handleMine(chain, wallets, storagePath);
            } else if (choice == "4") {
                printChain(chain);
            } else if (choice == "5") {
                std::cout << "Chain validation: "
                          << (chain.validate() ? "OK" : "FAILED") << "\n";
            } else if (choice == "0") {
                running = false;
            } else if (!choice.empty()) {
                std::cout << "Unknown option.\n";
            }
        }

        if (!saveChainJson(chain, storagePath)) {
            std::cout << "Warning: failed to save chain to " << storagePath << "\n";
        }

        std::cout << "Exiting. Goodbye!\n";
    } catch (const std::exception& ex) {
        std::cerr << "Blockchain CLI failed: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
