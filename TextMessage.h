#pragma once
#include "ReceivedMessage.h"
#include "CryptoManager.h"

// Decrypts and displays a text message.
class TextMessage : public ReceivedMessage {
public:
    TextMessage(const Message& msg, const std::string& sender_name, CryptoManager& crypto)
        : ReceivedMessage(msg, sender_name), crypto(crypto) {
    }
    void display() override;
private:
    CryptoManager& crypto;
};