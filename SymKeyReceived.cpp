#include "SymKeyReceived.h"
#include <iostream>

// Decrypts the received symmetric key using RSA and stores it in CryptoManager.
void SymKeyReceived::display() {
    std::cout << "From: " << sender_name << "\nContent:" << std::endl;
    try {
        std::string decrypted = crypto.decryptWithRSA(msg.content);
        std::vector<uint8_t> key(decrypted.begin(), decrypted.end());
        crypto.saveSymmetricKey(msg.from_client, key);
        std::cout << "symmetric key received" << std::endl;
    }
    catch (const std::exception&) {
        std::cout << "can't decrypt message" << std::endl;
    }
    std::cout << "-----<EOM>-----\n" << std::endl;
}