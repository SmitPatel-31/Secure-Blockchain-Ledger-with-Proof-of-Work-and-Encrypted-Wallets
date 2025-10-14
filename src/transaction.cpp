#include "transaction.h"

#include "crypto_utils.h"

#include <iomanip>
#include <sstream>
#include <string>

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

}  // namespace

std::string Transaction::digest() const {
    std::ostringstream oss;
    oss << "{\"sender\":\"" << escapeJson(senderPub) << "\""
        << ",\"receiver\":\"" << escapeJson(receiverPub) << "\""
        << ",\"amount\":" << formatAmount(amount) << "}";
    return oss.str();
}

bool Transaction::verify() const {
    if (senderPub.empty() || signature.empty()) {
        return false;
    }
    return verifySignature(digest(), signature, senderPub);
}
