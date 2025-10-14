#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "block.h"

class Blockchain {
public:
    explicit Blockchain(int difficultyTarget = 4);

    void addTransaction(const Transaction& tx);
    void minePending(const std::string& minerPub);
    bool validate() const;

    const Block& tip() const;
    const std::vector<Block>& blocks() const;
    bool hasPending() const;
    std::size_t pendingCount() const;
    int getDifficulty() const;

private:
    std::vector<Block> chain;
    int difficulty;
    std::vector<Transaction> mempool;

    friend bool saveChainJson(const Blockchain& chain, const std::string& path);
    friend bool loadChainJson(Blockchain& chain, const std::string& path);
};

bool saveChainJson(const Blockchain& chain, const std::string& path);
bool loadChainJson(Blockchain& chain, const std::string& path);
