#pragma once

#include <string>

struct Transaction {
    std::string senderPub;
    std::string receiverPub;
    double amount = 0.0;
    std::string signature;

    std::string digest() const;
    bool verify() const;
};
