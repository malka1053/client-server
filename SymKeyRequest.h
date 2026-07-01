#pragma once
#include "ReceivedMessage.h"

// Displays a symmetric key request message.
class SymKeyRequest : public ReceivedMessage {
public:
    SymKeyRequest(const Message& msg, const std::string& sender_name)
        : ReceivedMessage(msg, sender_name) {
    }
    void display() override;
};