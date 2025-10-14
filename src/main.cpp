#include <iostream>
#include <stdexcept>

#include "crypto_utils.h"
#include "transaction.h"

namespace {

struct EphemeralWallet {
    std::string publicKey;
    std::string privateKey;
};

EphemeralWallet createWallet() {
    EphemeralWallet wallet;
    if (!generateKeyPair(wallet.publicKey, wallet.privateKey)) {
        throw std::runtime_error("Key generation failed");
    }
    
    return wallet;
}

}  // namespace

int main() {
    try {
        const EphemeralWallet sender = createWallet();
        const EphemeralWallet receiver = createWallet();

        Transaction tx{};
        tx.senderPub = sender.publicKey;
        tx.receiverPub = receiver.publicKey;
        tx.amount = 42.5;
        tx.signature = signData(tx.digest(), sender.privateKey);

        std::cout << "TX verify (valid): " << (tx.verify() ? "OK" : "REJECTED") << std::endl;

        Transaction tampered = tx;
        tampered.amount += 10.0;
        std::cout << "TX verify (tampered): " << (tampered.verify() ? "OK" : "REJECTED") << std::endl;
    } catch (const std::exception& ex) {
        std::cerr << "Transaction test failed: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
