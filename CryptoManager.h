#pragma once
#include <vector>
#include <map>
#include <string>
#include <cstdint>
#include "protocol.h"
#include "RSAWrapper.h"

// Manages all encryption operations and symmetric key storage
class CryptoManager {
public:
    CryptoManager(RSAPrivateWrapper& rsa);

    // Symmetric key storage
    bool hasSymmetricKey(const uint8_t* target_id) const;
    void saveSymmetricKey(const uint8_t* target_id, const std::vector<uint8_t>& key);
    std::vector<uint8_t> getSymmetricKey(const uint8_t* target_id) const;

    // Encryption
    std::vector<uint8_t> encryptWithAES(const uint8_t* target_id, const std::string& plaintext);
    std::vector<uint8_t> encryptWithRSA(const std::vector<uint8_t>& public_key,
        const std::vector<uint8_t>& data);

    // Decryption
    std::string decryptWithAES(const uint8_t* sender_id,
        const std::vector<uint8_t>& ciphertext);
    std::string decryptWithRSA(const std::vector<uint8_t>& ciphertext);

private:
    RSAPrivateWrapper& rsa;
    std::map<std::string, std::vector<uint8_t>> symmetric_keys;

    static std::string idToString(const uint8_t* id);
};

