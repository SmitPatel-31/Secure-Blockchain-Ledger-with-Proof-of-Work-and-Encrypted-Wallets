#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "transaction.h"

struct Block {
    int index = 0;
    std::string prevHash;
    std::vector<Transaction> txs;
    long timestamp = 0;
    uint64_t nonce = 0;
    std::string hash;

    Block();

    std::string calcHash() const;
    void mine(int difficulty);
};
