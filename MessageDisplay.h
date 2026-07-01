#pragma once
#include "message.h"
#include "CryptoManager.h"
#include <string>

// Creates the appropriate ReceivedMessage subclass and calls display().
class MessageDisplay {
public:
    MessageDisplay(CryptoManager& crypto);
    void printMessage(const Message& msg, const std::string& sender_name);
private:
    CryptoManager& crypto;
};