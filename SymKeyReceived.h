#pragma once
#include "ReceivedMessage.h"
#include "CryptoManager.h"

// Decrypts and stores the received AES symmetric key.
class SymKeyReceived : public ReceivedMessage {
public:
    SymKeyReceived(const Message& msg, const std::string& sender_name, CryptoManager& crypto)
        : ReceivedMessage(msg, sender_name), crypto(crypto) {
    }
    void display() override;
private:
    CryptoManager& crypto;
};