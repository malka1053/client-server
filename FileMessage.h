#pragma once
#include "ReceivedMessage.h"
#include "CryptoManager.h"

// Decrypts and saves a received file message.
class FileMessage : public ReceivedMessage {
public:
    FileMessage(const Message& msg, const std::string& sender_name, CryptoManager& crypto)
        : ReceivedMessage(msg, sender_name), crypto(crypto) {
    }
    void display() override;
private:
    CryptoManager& crypto;
};