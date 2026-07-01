#include "FileMessage.h"
#include <iostream>
#include <fstream>
#include <filesystem>

// Decrypts and saves the received file to the temp directory.
void FileMessage::display() {
    std::cout << "From: " << sender_name << "\nContent:" << std::endl;
    if (!crypto.hasSymmetricKey(msg.from_client)) {
        std::cout << "can't decrypt message" << std::endl;
    }
    else {
        try {
            std::string decrypted = crypto.decryptWithAES(msg.from_client, msg.content);
            auto filepath = std::filesystem::temp_directory_path() /
                ("received_" + std::to_string(msg.id) + ".bin");
            std::ofstream out(filepath, std::ios::binary);
            if (out) {
                out.write(decrypted.data(), static_cast<std::streamsize>(decrypted.size()));
                std::cout << filepath.string() << std::endl;
            }
            else {
                std::cout << "can't decrypt message" << std::endl;
            }
        }
        catch (const std::exception&) {
            std::cout << "can't decrypt message" << std::endl;
        }
    }
    std::cout << "-----<EOM>-----\n" << std::endl;
}