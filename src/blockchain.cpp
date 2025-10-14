#include "blockchain.h"

#include <cctype>
#include <cstdint>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <limits>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <filesystem>
#include <iterator>
#include <sstream>

namespace {

Block createGenesis(int difficulty) {
    Block genesis;
    genesis.index = 0;
    genesis.prevHash = "0";
    genesis.nonce = 0;
    genesis.hash = genesis.calcHash();
    if (difficulty > 0) {
        // Genesis blocks are typically pre-defined; skip mining enforcement.
    }
    return genesis;
}

bool hasRequiredPrefix(const std::string& hash, int difficulty) {
    if (difficulty <= 0) {
        return true;
    }
    const std::string target(static_cast<size_t>(difficulty), '0');
    return hash.compare(0, static_cast<size_t>(difficulty), target) == 0;
}

}  // namespace

Blockchain::Blockchain(int difficultyTarget)
    : difficulty(difficultyTarget) {
    if (difficultyTarget < 0) {
        throw std::invalid_argument("Difficulty must be non-negative");
    }
    chain.push_back(createGenesis(difficulty));
}

void Blockchain::addTransaction(const Transaction& tx) {
    mempool.push_back(tx);
}

void Blockchain::minePending(const std::string& minerPub) {
    static_cast<void>(minerPub);

    if (mempool.empty()) {
        return;
    }

    Block block;
    block.index = static_cast<int>(chain.size());
    block.prevHash = chain.back().hash;
    block.txs = std::move(mempool);
    block.mine(difficulty);
    chain.push_back(std::move(block));
    mempool.clear();
}

bool Blockchain::validate() const {
    if (chain.empty()) {
        return true;
    }

    for (size_t i = 0; i < chain.size(); ++i) {
        const Block& block = chain[i];
        if (block.hash != block.calcHash()) {
            return false;
        }

        if (i == 0) {
            if (block.prevHash != "0") {
                return false;
            }
        } else {
            const Block& prev = chain[i - 1];
            if (block.prevHash != prev.hash) {
                return false;
            }
        }

        if (i > 0 && !hasRequiredPrefix(block.hash, difficulty)) {
            return false;
        }

        for (const auto& tx : block.txs) {
            if (!tx.verify()) {
                return false;
            }
        }
    }

    return true;
}

const Block& Blockchain::tip() const {
    return chain.back();
}

const std::vector<Block>& Blockchain::blocks() const {
    return chain;
}

bool Blockchain::hasPending() const {
    return !mempool.empty();
}

std::size_t Blockchain::pendingCount() const {
    return mempool.size();
}

int Blockchain::getDifficulty() const {
    return difficulty;
}

namespace {

std::string escapeJson(const std::string& input) {
    std::string escaped;
    escaped.reserve(input.size());
    for (const char ch : input) {
        switch (ch) {
            case '\\':
                escaped += "\\\\";
                break;
            case '"':
                escaped += "\\\"";
                break;
            case '\n':
                escaped += "\\n";
                break;
            case '\r':
                escaped += "\\r";
                break;
            case '\t':
                escaped += "\\t";
                break;
            default:
                escaped.push_back(ch);
                break;
        }
    }
    return escaped;
}

std::string formatAmount(double amount) {
    std::ostringstream oss;
    oss << std::setprecision(17) << amount;
    return oss.str();
}

struct JsonValue {
    enum class Type { Null, Bool, Number, String, Array, Object };

    Type type = Type::Null;
    double number = 0.0;
    bool boolean = false;
    std::string string;
    std::vector<JsonValue> array;
    std::map<std::string, JsonValue> object;
};

class JsonParser {
public:
    explicit JsonParser(std::string src) : data(std::move(src)) {}

    JsonValue parse() {
        skipWhitespace();
        JsonValue value = parseValue();
        skipWhitespace();
        if (!eof()) {
            throw std::runtime_error("Unexpected trailing data in JSON");
        }
        return value;
    }

private:
    JsonValue parseValue() {
        if (eof()) {
            throw std::runtime_error("Unexpected end of JSON data");
        }

        char ch = peek();
        if (ch == '"') {
            JsonValue v;
            v.type = JsonValue::Type::String;
            v.string = parseString();
            return v;
        }
        if (ch == '{') {
            return parseObject();
        }
        if (ch == '[') {
            return parseArray();
        }
        if (ch == 't') {
            advanceLiteral("true");
            JsonValue v;
            v.type = JsonValue::Type::Bool;
            v.boolean = true;
            return v;
        }
        if (ch == 'f') {
            advanceLiteral("false");
            JsonValue v;
            v.type = JsonValue::Type::Bool;
            v.boolean = false;
            return v;
        }
        if (ch == 'n') {
            advanceLiteral("null");
            JsonValue v;
            v.type = JsonValue::Type::Null;
            return v;
        }
        if (ch == '-' || std::isdigit(static_cast<unsigned char>(ch))) {
            JsonValue v;
            v.type = JsonValue::Type::Number;
            v.number = parseNumber();
            return v;
        }
        throw std::runtime_error("Invalid JSON value");
    }

    JsonValue parseObject() {
        expect('{');
        JsonValue v;
        v.type = JsonValue::Type::Object;
        skipWhitespace();
        if (peek() == '}') {
            advance();
            return v;
        }
        while (true) {
            skipWhitespace();
            if (peek() != '"') {
                throw std::runtime_error("Expected string key in JSON object");
            }
            std::string key = parseString();
            skipWhitespace();
            expect(':');
            skipWhitespace();
            JsonValue value = parseValue();
            v.object.emplace(std::move(key), std::move(value));
            skipWhitespace();
            if (peek() == '}') {
                advance();
                break;
            }
            expect(',');
        }
        return v;
    }

    JsonValue parseArray() {
        expect('[');
        JsonValue v;
        v.type = JsonValue::Type::Array;
        skipWhitespace();
        if (peek() == ']') {
            advance();
            return v;
        }
        while (true) {
            skipWhitespace();
            v.array.push_back(parseValue());
            skipWhitespace();
            if (peek() == ']') {
                advance();
                break;
            }
            expect(',');
        }
        return v;
    }

    double parseNumber() {
        std::size_t start = pos;
        if (peek() == '-') {
            advance();
        }
        while (!eof() && std::isdigit(static_cast<unsigned char>(peek()))) {
            advance();
        }
        if (!eof() && peek() == '.') {
            advance();
            while (!eof() && std::isdigit(static_cast<unsigned char>(peek()))) {
                advance();
            }
        }
        if (!eof() && (peek() == 'e' || peek() == 'E')) {
            advance();
            if (!eof() && (peek() == '+' || peek() == '-')) {
                advance();
            }
            while (!eof() && std::isdigit(static_cast<unsigned char>(peek()))) {
                advance();
            }
        }
        const std::string numberStr = data.substr(start, pos - start);
        try {
            size_t processed = 0;
            const double value = std::stod(numberStr, &processed);
            if (processed != numberStr.size()) {
                throw std::runtime_error("Invalid number");
            }
            return value;
        } catch (const std::exception&) {
            throw std::runtime_error("Invalid number in JSON");
        }
    }

    std::string parseString() {
        expect('"');
        std::string result;
        while (!eof()) {
            char ch = advance();
            if (ch == '"') {
                break;
            }
            if (ch == '\\') {
                if (eof()) {
                    throw std::runtime_error("Invalid escape in JSON string");
                }
                char esc = advance();
                switch (esc) {
                    case '"':
                    case '\\':
                    case '/':
                        result.push_back(esc);
                        break;
                    case 'b':
                        result.push_back('\b');
                        break;
                    case 'f':
                        result.push_back('\f');
                        break;
                    case 'n':
                        result.push_back('\n');
                        break;
                    case 'r':
                        result.push_back('\r');
                        break;
                    case 't':
                        result.push_back('\t');
                        break;
                    default:
                        throw std::runtime_error("Unsupported escape in JSON string");
                }
            } else {
                result.push_back(ch);
            }
        }
        return result;
    }

    void skipWhitespace() {
        while (!eof() && std::isspace(static_cast<unsigned char>(peek()))) {
            advance();
        }
    }

    char peek() const {
        if (eof()) {
            throw std::runtime_error("Unexpected end of JSON data");
        }
        return data[pos];
    }

    char advance() {
        if (eof()) {
            throw std::runtime_error("Unexpected end of JSON data");
        }
        return data[pos++];
    }

    void expect(char expected) {
        if (peek() != expected) {
            throw std::runtime_error("Unexpected character in JSON");
        }
        advance();
    }

    void advanceLiteral(const char* literal) {
        for (const char* p = literal; *p != '\0'; ++p) {
            if (eof() || peek() != *p) {
                throw std::runtime_error("Invalid literal in JSON");
            }
            advance();
        }
    }

    bool eof() const {
        return pos >= data.size();
    }

    std::string data;
    std::size_t pos = 0;
};

const JsonValue* getObjectValue(const JsonValue& object, const std::string& key) {
    const auto it = object.object.find(key);
    if (it == object.object.end()) {
        return nullptr;
    }
    return &it->second;
}

int jsonToInt(const JsonValue& value) {
    if (value.type != JsonValue::Type::Number) {
        throw std::runtime_error("Expected numeric JSON value for integer");
    }
    const double rounded = std::round(value.number);
    if (std::fabs(rounded - value.number) > std::numeric_limits<double>::epsilon()) {
        throw std::runtime_error("Non-integer JSON number where integer expected");
    }
    return static_cast<int>(rounded);
}

long jsonToLong(const JsonValue& value) {
    if (value.type != JsonValue::Type::Number) {
        throw std::runtime_error("Expected numeric JSON value for long");
    }
    const double rounded = std::round(value.number);
    if (std::fabs(rounded - value.number) > std::numeric_limits<double>::epsilon()) {
        throw std::runtime_error("Non-integer JSON number where integer expected");
    }
    return static_cast<long>(rounded);
}

uint64_t jsonToUint64(const JsonValue& value) {
    if (value.type != JsonValue::Type::Number) {
        throw std::runtime_error("Expected numeric JSON value for nonce");
    }
    const double rounded = std::round(value.number);
    if (rounded < 0 || std::fabs(rounded - value.number) > std::numeric_limits<double>::epsilon()) {
        throw std::runtime_error("Invalid nonce value");
    }
    return static_cast<uint64_t>(rounded);
}

double jsonToDouble(const JsonValue& value) {
    if (value.type != JsonValue::Type::Number) {
        throw std::runtime_error("Expected numeric JSON value for amount");
    }
    return value.number;
}

std::string jsonToString(const JsonValue& value) {
    if (value.type != JsonValue::Type::String) {
        throw std::runtime_error("Expected string JSON value");
    }
    return value.string;
}

Transaction parseTransaction(const JsonValue& value) {
    if (value.type != JsonValue::Type::Object) {
        throw std::runtime_error("Transaction entry must be an object");
    }
    Transaction tx{};
    const JsonValue* senderVal = getObjectValue(value, "sender");
    const JsonValue* receiverVal = getObjectValue(value, "receiver");
    const JsonValue* amountVal = getObjectValue(value, "amount");
    const JsonValue* signatureVal = getObjectValue(value, "signature");
    if (!senderVal || !receiverVal || !amountVal || !signatureVal) {
        throw std::runtime_error("Incomplete transaction data in JSON");
    }
    tx.senderPub = jsonToString(*senderVal);
    tx.receiverPub = jsonToString(*receiverVal);
    tx.amount = jsonToDouble(*amountVal);
    tx.signature = jsonToString(*signatureVal);
    return tx;
}

}  // namespace

bool saveChainJson(const Blockchain& chain, const std::string& path) {
    namespace fs = std::filesystem;
    try {
        const fs::path targetPath(path);
        if (!targetPath.parent_path().empty()) {
            fs::create_directories(targetPath.parent_path());
        }

        std::ofstream out(path, std::ios::trunc);
        if (!out) {
            return false;
        }

        out << "{\n";
        out << "  \"difficulty\": " << chain.difficulty << ",\n";
        out << "  \"chain\": [\n";
        for (std::size_t i = 0; i < chain.chain.size(); ++i) {
            const Block& block = chain.chain[i];
            out << "    {\n";
            out << "      \"index\": " << block.index << ",\n";
            out << "      \"prevHash\": \"" << escapeJson(block.prevHash) << "\",\n";
            out << "      \"timestamp\": " << block.timestamp << ",\n";
            out << "      \"nonce\": " << block.nonce << ",\n";
            out << "      \"hash\": \"" << escapeJson(block.hash) << "\",\n";
            out << "      \"txs\": [\n";
            for (std::size_t t = 0; t < block.txs.size(); ++t) {
                const Transaction& tx = block.txs[t];
                out << "        {\n";
                out << "          \"sender\": \"" << escapeJson(tx.senderPub) << "\",\n";
                out << "          \"receiver\": \"" << escapeJson(tx.receiverPub) << "\",\n";
                out << "          \"amount\": " << formatAmount(tx.amount) << ",\n";
                out << "          \"signature\": \"" << escapeJson(tx.signature) << "\"\n";
                out << "        }";
                if (t + 1 < block.txs.size()) {
                    out << ",";
                }
                out << "\n";
            }
            out << "      ]\n";
            out << "    }";
            if (i + 1 < chain.chain.size()) {
                out << ",";
            }
            out << "\n";
        }
        out << "  ],\n";
        out << "  \"mempool\": [\n";
        for (std::size_t i = 0; i < chain.mempool.size(); ++i) {
            const Transaction& tx = chain.mempool[i];
            out << "    {\n";
            out << "      \"sender\": \"" << escapeJson(tx.senderPub) << "\",\n";
            out << "      \"receiver\": \"" << escapeJson(tx.receiverPub) << "\",\n";
            out << "      \"amount\": " << formatAmount(tx.amount) << ",\n";
            out << "      \"signature\": \"" << escapeJson(tx.signature) << "\"\n";
            out << "    }";
            if (i + 1 < chain.mempool.size()) {
                out << ",";
            }
            out << "\n";
        }
        out << "  ]\n";
        out << "}\n";
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool loadChainJson(Blockchain& chain, const std::string& path) {
    std::ifstream in(path);
    if (!in) {
        return false;
    }

    std::string content((std::istreambuf_iterator<char>(in)),
                        std::istreambuf_iterator<char>());
    if (content.empty()) {
        return false;
    }

    try {
        JsonParser parser(content);
        JsonValue root = parser.parse();
        if (root.type != JsonValue::Type::Object) {
            throw std::runtime_error("Root JSON value must be an object");
        }

        const JsonValue* difficultyVal = getObjectValue(root, "difficulty");
        const JsonValue* chainVal = getObjectValue(root, "chain");
        const JsonValue* mempoolVal = getObjectValue(root, "mempool");
        if (!difficultyVal || !chainVal || !mempoolVal) {
            throw std::runtime_error("Missing required keys in chain file");
        }

        const int newDifficulty = jsonToInt(*difficultyVal);
        if (chainVal->type != JsonValue::Type::Array ||
            mempoolVal->type != JsonValue::Type::Array) {
            throw std::runtime_error("Invalid array values in chain file");
        }

        std::vector<Block> newChain;
        newChain.reserve(chainVal->array.size());
        for (const auto& blockVal : chainVal->array) {
            if (blockVal.type != JsonValue::Type::Object) {
                throw std::runtime_error("Block entry must be an object");
            }
            Block block;
            const JsonValue* indexVal = getObjectValue(blockVal, "index");
            const JsonValue* prevHashVal = getObjectValue(blockVal, "prevHash");
            const JsonValue* timestampVal = getObjectValue(blockVal, "timestamp");
            const JsonValue* nonceVal = getObjectValue(blockVal, "nonce");
            const JsonValue* hashVal = getObjectValue(blockVal, "hash");
            const JsonValue* txsVal = getObjectValue(blockVal, "txs");
            if (!indexVal || !prevHashVal || !timestampVal || !nonceVal || !hashVal || !txsVal) {
                throw std::runtime_error("Incomplete block data in JSON");
            }
            block.index = jsonToInt(*indexVal);
            block.prevHash = jsonToString(*prevHashVal);
            block.timestamp = jsonToLong(*timestampVal);
            block.nonce = jsonToUint64(*nonceVal);
            block.hash = jsonToString(*hashVal);
            if (txsVal->type != JsonValue::Type::Array) {
                throw std::runtime_error("Block transactions must be an array");
            }
            for (const auto& txVal : txsVal->array) {
                block.txs.push_back(parseTransaction(txVal));
            }
            newChain.push_back(std::move(block));
        }

        std::vector<Transaction> newMempool;
        newMempool.reserve(mempoolVal->array.size());
        for (const auto& txVal : mempoolVal->array) {
            newMempool.push_back(parseTransaction(txVal));
        }

        const auto oldChain = chain.chain;
        const auto oldMempool = chain.mempool;
        const int oldDifficulty = chain.difficulty;

        chain.chain = std::move(newChain);
        chain.mempool = std::move(newMempool);
        chain.difficulty = newDifficulty;

        if (!chain.validate()) {
            chain.chain = oldChain;
            chain.mempool = oldMempool;
            chain.difficulty = oldDifficulty;
            return false;
        }

        return true;
    } catch (const std::exception&) {
        return false;
    }
}
