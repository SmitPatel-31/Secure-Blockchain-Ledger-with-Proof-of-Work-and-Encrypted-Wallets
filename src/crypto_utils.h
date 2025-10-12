#pragma once

#include <string>

std::string sha256(const std::string& input);

bool generateKeyPair(std::string& publicKeyPem, std::string& privateKeyPem);

std::string signData(const std::string& data, const std::string& privateKeyPem);

bool verifySignature(const std::string& data,
                     const std::string& signature,
                     const std::string& publicKeyPem);
