#include "block.h"

#include "crypto_utils.h"

#include <chrono>
#include <sstream>
#include <stdexcept>

namespace {

long currentTimestamp() {
    const auto now = std::chrono::system_clock::now();
    return static_cast<long>(
        std::chrono::system_clock::to_time_t(now));
}

}  // namespace

Block::Block() : timestamp(currentTimestamp()) {}

std::string Block::calcHash() const {
    std::ostringstream oss;
    oss << index << prevHash << timestamp << nonce;
    for (const auto& tx : txs) {
        oss << tx.digest();
    }
    return sha256(oss.str());
}

void Block::mine(int difficulty) {
    if (difficulty < 0) {
        throw std::invalid_argument("Difficulty must be non-negative");
    }

    const std::string target(static_cast<size_t>(difficulty), '0');

    nonce = 0;
    hash = calcHash();
    while (difficulty > 0 && hash.compare(0, static_cast<size_t>(difficulty), target) != 0) {
        ++nonce;
        hash = calcHash();
    }
}
