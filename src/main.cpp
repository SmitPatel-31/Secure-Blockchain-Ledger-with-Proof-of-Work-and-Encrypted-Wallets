#include <iostream>
#include <stdexcept>

#include "crypto_utils.h"

int main() {
    std::cout << "Secure Blockchain — WIP" << std::endl;

    std::string publicKey;
    std::string privateKey;
    if (!generateKeyPair(publicKey, privateKey)) {
        std::cerr << "Key generation failed" << std::endl;
        return 1;
    }

    const std::string message = "hello";
    try {
        const std::string signature = signData(message, privateKey);
        const bool verified = verifySignature(message, signature, publicKey);
        const bool tamperedVerified = verifySignature("hallo", signature, publicKey);

        std::cout << "Sign/verify: " << (verified ? "OK" : "FAIL")
                  << "; Tamper check: " << (!tamperedVerified ? "PASSED" : "FAILED") << std::endl;
    } catch (const std::exception& ex) {
        std::cerr << "Signing or verification error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
