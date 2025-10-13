#include "wallet.h"

#include "crypto_utils.h"

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr std::size_t kAesKeySize = 32;   // 256-bit key
constexpr std::size_t kAesIvSize = 16;    // 128-bit IV for CBC
constexpr std::size_t kSaltSize = 16;     // 128-bit salt
constexpr int kPbkdf2Iterations = 100000; // PBKDF2 rounds

using BioChainPtr = std::unique_ptr<BIO, decltype(&BIO_free_all)>;

BioChainPtr makeBase64Chain(BIO* first, BIO* second) {
    if (!first || !second) {
        if (first) {
            BIO_free(first);
        }
        if (second) {
            BIO_free(second);
        }
        throw std::runtime_error("Failed to allocate BIO");
    }
    BIO_set_flags(first, BIO_FLAGS_BASE64_NO_NL);
    BIO* chain = BIO_push(first, second);
    if (!chain) {
        BIO_free(first);
        BIO_free(second);
        throw std::runtime_error("Failed to create BIO chain");
    }
    return BioChainPtr(chain, &BIO_free_all);
}

std::string base64Encode(const unsigned char* data, std::size_t len) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    auto chain = makeBase64Chain(b64, mem);

    const int written = BIO_write(chain.get(), data, static_cast<int>(len));
    if (written <= 0 || static_cast<std::size_t>(written) != len) {
        throw std::runtime_error("Failed to write data for base64 encoding");
    }
    if (BIO_flush(chain.get()) != 1) {
        throw std::runtime_error("Failed to flush base64 encoder");
    }
    BUF_MEM* bufferPtr = nullptr;
    BIO_get_mem_ptr(chain.get(), &bufferPtr);
    if (!bufferPtr || !bufferPtr->data || bufferPtr->length == 0) {
        return {};
    }
    return std::string(bufferPtr->data, bufferPtr->length);
}

std::string base64Encode(const std::vector<unsigned char>& data) {
    if (data.empty()) {
        return {};
    }
    return base64Encode(data.data(), data.size());
}

std::string base64Encode(const std::string& data) {
    if (data.empty()) {
        return {};
    }
    return base64Encode(reinterpret_cast<const unsigned char*>(data.data()), data.size());
}

std::vector<unsigned char> base64Decode(const std::string& input) {
    if (input.empty()) {
        return {};
    }

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(input.data(), static_cast<int>(input.size()));
    auto chain = makeBase64Chain(b64, mem);

    std::vector<unsigned char> output(input.size(), 0);
    std::size_t offset = 0;
    while (true) {
        const int read = BIO_read(chain.get(),
                                  output.data() + offset,
                                  static_cast<int>(output.size() - offset));
        if (read > 0) {
            offset += static_cast<std::size_t>(read);
            continue;
        }
        if (read == 0) {
            break;
        }
        throw std::runtime_error("Failed to decode base64 data");
    }
    output.resize(offset);
    return output;
}

std::vector<unsigned char> randomBytes(std::size_t size) {
    std::vector<unsigned char> buffer(size);
    if (RAND_bytes(buffer.data(), static_cast<int>(buffer.size())) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
    return buffer;
}

std::vector<unsigned char> deriveKey(const std::string& password,
                                     const std::vector<unsigned char>& salt) {
    std::vector<unsigned char> key(kAesKeySize);
    if (PKCS5_PBKDF2_HMAC(password.data(),
                          static_cast<int>(password.size()),
                          salt.data(),
                          static_cast<int>(salt.size()),
                          kPbkdf2Iterations,
                          EVP_sha256(),
                          static_cast<int>(key.size()),
                          key.data()) != 1) {
        throw std::runtime_error("Failed to derive key");
    }
    return key;
}

std::vector<unsigned char> encryptAes256Cbc(const std::string& plaintext,
                                            const std::vector<unsigned char>& key,
                                            const std::vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to allocate cipher context");
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int outLen1 = 0;
    int outLen2 = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }
    if (EVP_EncryptUpdate(ctx,
                          ciphertext.data(),
                          &outLen1,
                          reinterpret_cast<const unsigned char*>(plaintext.data()),
                          static_cast<int>(plaintext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + outLen1, &outLen2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    EVP_CIPHER_CTX_free(ctx);

    ciphertext.resize(static_cast<std::size_t>(outLen1 + outLen2));
    return ciphertext;
}

std::string decryptAes256Cbc(const std::vector<unsigned char>& ciphertext,
                             const std::vector<unsigned char>& key,
                             const std::vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to allocate cipher context");
    }

    std::vector<unsigned char> plaintext(ciphertext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int outLen1 = 0;
    int outLen2 = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }
    if (EVP_DecryptUpdate(ctx,
                          plaintext.data(),
                          &outLen1,
                          ciphertext.data(),
                          static_cast<int>(ciphertext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + outLen1, &outLen2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Invalid password or corrupted wallet");
    }
    EVP_CIPHER_CTX_free(ctx);

    plaintext.resize(static_cast<std::size_t>(outLen1 + outLen2));
    return std::string(plaintext.begin(), plaintext.end());
}

}  // namespace

Wallet::Wallet(std::string publicKeyPem,
               std::vector<unsigned char> encryptedPrivateKey,
               std::vector<unsigned char> iv,
               std::vector<unsigned char> salt)
    : publicKeyPem_(std::move(publicKeyPem)),
      encryptedPrivateKey_(std::move(encryptedPrivateKey)),
      iv_(std::move(iv)),
      salt_(std::move(salt)) {}

Wallet Wallet::Create(const std::string& password) {
    std::string publicKeyPem;
    std::string privateKeyPem;
    if (!generateKeyPair(publicKeyPem, privateKeyPem)) {
        throw std::runtime_error("Failed to generate key pair");
    }
    auto salt = randomBytes(kSaltSize);
    auto iv = randomBytes(kAesIvSize);
    const auto key = deriveKey(password, salt);
    auto encrypted = encryptAes256Cbc(privateKeyPem, key, iv);
    return Wallet(std::move(publicKeyPem), std::move(encrypted), std::move(iv), std::move(salt));
}

Wallet Wallet::Load(const std::string& path, const std::string& password) {
    std::ifstream in(path, std::ios::in);
    if (!in) {
        throw std::runtime_error("Failed to open wallet file: " + path);
    }

    std::map<std::string, std::string> kv;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) {
            continue;
        }
        const auto pos = line.find('=');
        if (pos == std::string::npos) {
            throw std::runtime_error("Invalid line in wallet file");
        }
        std::string key = line.substr(0, pos);
        std::string value = line.substr(pos + 1);
        kv[std::move(key)] = std::move(value);
    }

    const auto publicKeyIt = kv.find("public_key");
    const auto saltIt = kv.find("salt");
    const auto ivIt = kv.find("iv");
    const auto cipherIt = kv.find("cipher");

    if (publicKeyIt == kv.end() || saltIt == kv.end() || ivIt == kv.end() || cipherIt == kv.end()) {
        throw std::runtime_error("Wallet file missing required fields");
    }

    const auto publicKeyBytes = base64Decode(publicKeyIt->second);
    const auto salt = base64Decode(saltIt->second);
    const auto iv = base64Decode(ivIt->second);
    const auto cipher = base64Decode(cipherIt->second);

    std::string publicKeyPem(publicKeyBytes.begin(), publicKeyBytes.end());
    Wallet wallet(std::move(publicKeyPem),
                  std::move(cipher),
                  std::move(iv),
                  std::move(salt));

    // Validate password by attempting decryption.
    (void)wallet.decryptPrivateKey(password);

    return wallet;
}

bool Wallet::Save(const std::string& path) const {
    try {
        const std::filesystem::path filePath(path);
        const auto parent = filePath.parent_path();
        if (!parent.empty()) {
            std::filesystem::create_directories(parent);
        }

        std::ofstream out(path, std::ios::out | std::ios::trunc);
        if (!out) {
            return false;
        }

        out << "public_key=" << base64Encode(publicKeyPem_) << '\n';
        out << "salt=" << base64Encode(salt_) << '\n';
        out << "iv=" << base64Encode(iv_) << '\n';
        out << "cipher=" << base64Encode(encryptedPrivateKey_) << '\n';

        return static_cast<bool>(out);
    } catch (const std::exception&) {
        return false;
    }
}

std::string Wallet::sign(const std::string& data, const std::string& password) const {
    const std::string privateKeyPem = decryptPrivateKey(password);
    return signData(data, privateKeyPem);
}

std::string Wallet::decryptPrivateKey(const std::string& password) const {
    const auto key = deriveKey(password, salt_);
    return decryptAes256Cbc(encryptedPrivateKey_, key, iv_);
}
