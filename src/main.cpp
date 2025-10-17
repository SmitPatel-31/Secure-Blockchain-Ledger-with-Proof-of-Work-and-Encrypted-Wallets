#include <cctype>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "blockchain.h"
#include "transaction.h"
#include "wallet.h"

namespace {

struct WalletEntry {
    std::string label;
    std::string path;
    Wallet wallet;

    WalletEntry(std::string labelIn, std::string pathIn, Wallet walletIn)
        : label(std::move(labelIn)),
          path(std::move(pathIn)),
          wallet(std::move(walletIn)) {}
};

bool promptLine(const std::string& message, std::string& output) {
    std::cout << message;
    std::cout.flush();
    if (!std::getline(std::cin, output)) {
        return false;
    }
    return true;
}

std::string keyPreview(const std::string& key) {
    if (key.size() <= 24) {
        return key;
    }
    return key.substr(0, 24) + "...";
}

std::string sanitizeLabelForPath(const std::string& label, std::size_t indexFallback) {
    std::string slug;
    slug.reserve(label.size());
    for (const unsigned char ch : label) {
        if (std::isalnum(ch)) {
            slug.push_back(static_cast<char>(std::tolower(ch)));
        } else if (ch == '-' || ch == '_' || ch == ' ') {
            slug.push_back('_');
        }
    }
    if (slug.empty()) {
        slug = "wallet_" + std::to_string(indexFallback);
    }
    return slug;
}

std::string defaultWalletPath(const std::string& label, std::size_t indexFallback) {
    const std::string slug = sanitizeLabelForPath(label, indexFallback);
    const std::filesystem::path storage = std::filesystem::path("data") /
                                          "wallets" /
                                          (slug + ".wallet");
    return storage.string();
}

void printWallets(const std::vector<WalletEntry>& wallets) {
    if (wallets.empty()) {
        std::cout << "No wallets available. Create or load one first.\n";
        return;
    }

    std::cout << "Wallets:\n";
    for (std::size_t i = 0; i < wallets.size(); ++i) {
        const std::string preview = keyPreview(wallets[i].wallet.publicKey());
        std::cout << "  [" << i << "] " << wallets[i].label << " (" << preview << ")\n";
        std::cout << "       file: " << wallets[i].path << "\n";
    }
}

bool selectWallet(const std::vector<WalletEntry>& wallets,
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

bool handleCreateWallet(std::vector<WalletEntry>& wallets) {
    std::string label;
    if (!promptLine("Enter wallet label (optional): ", label)) {
        return false;
    }

    std::string password;
    if (!promptLine("Enter wallet password: ", password)) {
        return false;
    }
    if (password.empty()) {
        std::cout << "Password is required to create an encrypted wallet.\n";
        return true;
    }

    std::string confirm;
    if (!promptLine("Confirm wallet password: ", confirm)) {
        return false;
    }
    if (confirm != password) {
        std::cout << "Passwords do not match. Wallet not created.\n";
        return true;
    }

    std::string path;
    if (!promptLine("Enter wallet storage path (optional): ", path)) {
        return false;
    }
    const std::size_t nextIndex = wallets.size();
    if (path.empty()) {
        path = defaultWalletPath(label, nextIndex);
    }
    std::string finalizedLabel = label;
    if (finalizedLabel.empty()) {
        finalizedLabel = "Wallet " + std::to_string(nextIndex);
    }

    try {
        Wallet wallet = Wallet::Create(password);
        if (!wallet.Save(path)) {
            std::cout << "Failed to save wallet to " << path << "\n";
            return true;
        }
        wallets.emplace_back(std::move(finalizedLabel), path, std::move(wallet));
        const auto& entry = wallets.back();
        std::cout << "Created wallet #" << (wallets.size() - 1) << " (" << entry.label << ")\n";
        std::cout << "Saved encrypted wallet to " << entry.path << "\n";
    } catch (const std::exception& ex) {
        std::cout << "Failed to create wallet: " << ex.what() << "\n";
    }

    password.clear();
    confirm.clear();
    return true;
}

bool handleLoadWallet(std::vector<WalletEntry>& wallets) {
    std::string path;
    if (!promptLine("Enter wallet file path: ", path)) {
        return false;
    }
    if (path.empty()) {
        std::cout << "Load cancelled.\n";
        return true;
    }

    std::string password;
    if (!promptLine("Enter wallet password: ", password)) {
        return false;
    }
    if (password.empty()) {
        std::cout << "Password is required to load an encrypted wallet.\n";
        return true;
    }

    std::string label;
    if (!promptLine("Enter wallet label (optional): ", label)) {
        return false;
    }

    try {
        Wallet wallet = Wallet::Load(path, password);
        if (label.empty()) {
            label = std::filesystem::path(path).stem().string();
            if (label.empty()) {
                label = "Wallet " + std::to_string(wallets.size());
            }
        }
        wallets.emplace_back(std::move(label), path, std::move(wallet));
        std::cout << "Loaded wallet #" << (wallets.size() - 1)
                  << " (" << wallets.back().label << ")\n";
    } catch (const std::exception& ex) {
        std::cout << "Failed to load wallet: " << ex.what() << "\n";
    }

    password.clear();
    return true;
}

bool handleMakeTransaction(const std::vector<WalletEntry>& wallets,
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
    tx.senderPub = wallets[senderIdx].wallet.publicKey();
    tx.receiverPub = wallets[receiverIdx].wallet.publicKey();
    tx.amount = amount;

    std::string senderPassword;
    if (!promptLine("Enter password for sender wallet: ", senderPassword)) {
        return false;
    }
    if (senderPassword.empty()) {
        std::cout << "Password is required to sign the transaction.\n";
        return true;
    }

    try {
        tx.signature = wallets[senderIdx].wallet.sign(tx.digest(), senderPassword);
    } catch (const std::exception& ex) {
        std::cout << "Failed to sign transaction: " << ex.what() << "\n";
        return true;
    }

    senderPassword.clear();

    chain.addTransaction(tx);
    std::cout << "Transaction queued. Pending transactions: " << chain.pendingCount() << "\n";
    if (!saveChainJson(chain, storagePath)) {
        std::cout << "Warning: failed to save chain to " << storagePath << "\n";
    }
    return true;
}

bool handleMine(Blockchain& chain,
                const std::vector<WalletEntry>& wallets,
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
    chain.minePending(wallets[minerIdx].wallet.publicKey());

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
    std::cout << "2) Load wallet\n";
    std::cout << "3) Make transaction\n";
    std::cout << "4) Mine block\n";
    std::cout << "5) Print chain\n";
    std::cout << "6) Validate chain\n";
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

        std::vector<WalletEntry> wallets;

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
                running = handleLoadWallet(wallets);
            } else if (choice == "3") {
                running = handleMakeTransaction(wallets, chain, storagePath);
            } else if (choice == "4") {
                running = handleMine(chain, wallets, storagePath);
            } else if (choice == "5") {
                printChain(chain);
            } else if (choice == "6") {
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
