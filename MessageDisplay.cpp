#include "MessageDisplay.h"
#include "SymKeyRequest.h"
#include "SymKeyReceived.h"
#include "TextMessage.h"
#include "FileMessage.h"
#include <iostream>
#include <memory>

MessageDisplay::MessageDisplay(CryptoManager& crypto) : crypto(crypto) {}

// Creates the appropriate ReceivedMessage subclass based on message type and calls display().
// Creates the appropriate ReceivedMessage subclass based on message type and calls display().
// MSG_TYPE_SYM_KEY_REQUEST : prints a symmetric key request notification.
// MSG_TYPE_SYM_KEY_SEND   : decrypts and stores the received AES key via CryptoManager.
// MSG_TYPE_TEXT_MESSAGE   : decrypts and prints the message text.
// MSG_TYPE_FILE           : decrypts and saves the file to disk.
// Unknown types are handled inline with a fallback print and early return.
void MessageDisplay::printMessage(const Message& msg, const std::string& sender_name) {
    std::unique_ptr<ReceivedMessage> received;

    switch (msg.type) {
    case MSG_TYPE_SYM_KEY_REQUEST:
        received = std::make_unique<SymKeyRequest>(msg, sender_name);
        break;
    case MSG_TYPE_SYM_KEY_SEND:
        received = std::make_unique<SymKeyReceived>(msg, sender_name, crypto);
        break;
    case MSG_TYPE_TEXT_MESSAGE:
        received = std::make_unique<TextMessage>(msg, sender_name, crypto);
        break;
    case MSG_TYPE_FILE:
        received = std::make_unique<FileMessage>(msg, sender_name, crypto);
        break;
    default:
        std::cout << "From: " << sender_name << "\nContent:" << std::endl;
        std::cout << "Unknown message type (" << static_cast<int>(msg.type) << ")" << std::endl;
        std::cout << "-----<EOM>-----\n" << std::endl;
        return;
    }

    received->display();
}