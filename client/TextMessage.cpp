#include "TextMessage.h"
#include <iostream>

// Decrypts and prints the text message content using AES.
void TextMessage::display() {
    std::cout << "From: " << sender_name << "\nContent:" << std::endl;
    if (!crypto.hasSymmetricKey(msg.from_client)) {
        std::cout << "can't decrypt message" << std::endl;
    }
    else {
        try {
            std::cout << crypto.decryptWithAES(msg.from_client, msg.content) << std::endl;
        }
        catch (const std::exception&) {
            std::cout << "can't decrypt message" << std::endl;
        }
    }
    std::cout << "-----<EOM>-----\n" << std::endl;
}
