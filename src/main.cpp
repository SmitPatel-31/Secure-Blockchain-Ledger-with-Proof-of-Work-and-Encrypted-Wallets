#include <iostream>
#include <stdexcept>

#include "crypto_utils.h"
#include "wallet.h"

int main() {
    std::cout << "Secure Blockchain — WIP" << std::endl;

    const std::string password = "smit123";
    const std::string walletPath = "data/wallets/demo.wallet";
    const std::string payload = "wallet-check";

    try {
        Wallet wallet = Wallet::Create(password);
        if (!wallet.Save(walletPath)) {
            std::cerr << "Failed to save wallet to " << walletPath << std::endl;
            return 1;
        }

        Wallet loaded = Wallet::Load(walletPath, password);
        const std::string signature = loaded.sign(payload, password);
        const bool verified = verifySignature(payload, signature, loaded.publicKey());

        std::cout << "Wallet created and saved to: " << walletPath << std::endl;
        std::cout << "Signature verification: " << (verified ? "OK" : "FAIL") << std::endl;
    } catch (const std::exception& ex) {
        std::cerr << "Wallet test failed: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
