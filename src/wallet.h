#pragma once

#include <string>
#include <vector>

class Wallet {
public:
    static Wallet Create(const std::string& password);
    static Wallet Load(const std::string& path, const std::string& password);

    bool Save(const std::string& path) const;

    std::string publicKey() const { return publicKeyPem_; }

    std::string sign(const std::string& data, const std::string& password) const;

private:
    Wallet(std::string publicKeyPem,
           std::vector<unsigned char> encryptedPrivateKey,
           std::vector<unsigned char> iv,
           std::vector<unsigned char> salt);

    std::string decryptPrivateKey(const std::string& password) const;

    std::string publicKeyPem_;
    std::vector<unsigned char> encryptedPrivateKey_;
    std::vector<unsigned char> iv_;
    std::vector<unsigned char> salt_;
};
