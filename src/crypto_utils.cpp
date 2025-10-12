#include "crypto_utils.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace {

using EVPKeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using EVPKeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using DigestCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

std::string bioToString(BIO* bio) {
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    if (mem == nullptr || mem->data == nullptr || mem->length == 0) {
        return {};
    }
    return std::string(mem->data, mem->length);
}

EVPKeyPtr loadPrivateKey(const std::string& pem) {
    BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), &BIO_free);
    if (!bio) {
        throw std::runtime_error("Failed to allocate BIO for private key");
    }
    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
    if (!key) {
        throw std::runtime_error("Failed to parse private key PEM");
    }
    return EVPKeyPtr(key, &EVP_PKEY_free);
}

EVPKeyPtr loadPublicKey(const std::string& pem) {
    BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), &BIO_free);
    if (!bio) {
        return EVPKeyPtr(nullptr, &EVP_PKEY_free);
    }
    EVP_PKEY* key = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
    return EVPKeyPtr(key, &EVP_PKEY_free);
}

}  // namespace

std::string sha256(const std::string& input) {
    DigestCtxPtr ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (!ctx) {
        throw std::runtime_error("Failed to allocate digest context");
    }
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }
    if (EVP_DigestUpdate(ctx.get(), input.data(), input.size()) != 1) {
        throw std::runtime_error("EVP_DigestUpdate failed");
    }
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen = 0;
    if (EVP_DigestFinal_ex(ctx.get(), hash, &hashLen) != 1) {
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < hashLen; ++i) {
        oss << std::setw(2) << static_cast<int>(hash[i]);
    }
    return oss.str();
}

bool generateKeyPair(std::string& publicKeyPem, std::string& privateKeyPem) {
    publicKeyPem.clear();
    privateKeyPem.clear();

    EVPKeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), &EVP_PKEY_CTX_free);
    if (!ctx) {
        return false;
    }
    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        return false;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 2048) <= 0) {
        return false;
    }

    EVP_PKEY* rawKey = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &rawKey) <= 0) {
        return false;
    }
    EVPKeyPtr key(rawKey, &EVP_PKEY_free);

    BioPtr privBio(BIO_new(BIO_s_mem()), &BIO_free);
    if (!privBio) {
        return false;
    }
    if (PEM_write_bio_PrivateKey(privBio.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        return false;
    }

    BioPtr pubBio(BIO_new(BIO_s_mem()), &BIO_free);
    if (!pubBio) {
        return false;
    }
    if (PEM_write_bio_PUBKEY(pubBio.get(), key.get()) != 1) {
        return false;
    }

    privateKeyPem = bioToString(privBio.get());
    publicKeyPem = bioToString(pubBio.get());

    return !publicKeyPem.empty() && !privateKeyPem.empty();
}

std::string signData(const std::string& data, const std::string& privateKeyPem) {
    EVPKeyPtr key = loadPrivateKey(privateKeyPem);
    if (!key) {
        throw std::runtime_error("Invalid private key");
    }

    DigestCtxPtr ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (!ctx) {
        throw std::runtime_error("Failed to allocate signing context");
    }
    if (EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, key.get()) != 1) {
        throw std::runtime_error("EVP_DigestSignInit failed");
    }
    if (EVP_DigestSignUpdate(ctx.get(), data.data(), data.size()) != 1) {
        throw std::runtime_error("EVP_DigestSignUpdate failed");
    }

    size_t signatureLen = 0;
    if (EVP_DigestSignFinal(ctx.get(), nullptr, &signatureLen) != 1) {
        throw std::runtime_error("EVP_DigestSignFinal sizing failed");
    }

    std::string signature(signatureLen, '\0');
    if (EVP_DigestSignFinal(ctx.get(), reinterpret_cast<unsigned char*>(signature.data()), &signatureLen) != 1) {
        throw std::runtime_error("EVP_DigestSignFinal failed");
    }
    signature.resize(signatureLen);

    return signature;
}

bool verifySignature(const std::string& data,
                     const std::string& signature,
                     const std::string& publicKeyPem) {
    EVPKeyPtr key = loadPublicKey(publicKeyPem);
    if (!key) {
        return false;
    }

    DigestCtxPtr ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (!ctx) {
        return false;
    }
    if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, key.get()) != 1) {
        return false;
    }
    if (EVP_DigestVerifyUpdate(ctx.get(), data.data(), data.size()) != 1) {
        return false;
    }
    const int result = EVP_DigestVerifyFinal(ctx.get(),
                                             reinterpret_cast<const unsigned char*>(signature.data()),
                                             signature.size());
    return result == 1;
}
