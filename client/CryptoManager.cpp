#include "CryptoManager.h"
#include "AESWrapper.h"
#include "message.h"
#include <stdexcept>

// Initializes CryptoManager with a reference to the client's RSA private key.

CryptoManager::CryptoManager(RSAPrivateWrapper& rsa) : rsa(rsa) {}

// Converts a raw 16-byte client ID to a hex string for use as a map key.
std::string CryptoManager::idToString(const uint8_t* id) {
    return ResponseParser::clientIdToString(id);
}

// Returns true if a symmetric key exists for the given client ID.
bool CryptoManager::hasSymmetricKey(const uint8_t* target_id) const {
    return symmetric_keys.count(idToString(target_id)) > 0;
}

// Stores a symmetric key associated with the given client ID.
void CryptoManager::saveSymmetricKey(const uint8_t* target_id, const std::vector<uint8_t>& key) {
    symmetric_keys[idToString(target_id)] = key;
}

// Returns the symmetric key for the given client ID.
// Throws runtime_error if no key exists for that client.
std::vector<uint8_t> CryptoManager::getSymmetricKey(const uint8_t* target_id) const {
    auto it = symmetric_keys.find(idToString(target_id));
    if (it == symmetric_keys.end())
        throw std::runtime_error("No symmetric key for client");
    return it->second;
}

// Encrypts plaintext using the AES symmetric key stored for the given target client.
// Returns the encrypted bytes.
std::vector<uint8_t> CryptoManager::encryptWithAES(const uint8_t* target_id,
    const std::string& plaintext) {
    auto key = getSymmetricKey(target_id);
    AESWrapper aes(key.data(), static_cast<unsigned int>(key.size()));
    std::string encrypted = aes.encrypt(plaintext.c_str(),
        static_cast<unsigned int>(plaintext.size()));
    return std::vector<uint8_t>(encrypted.begin(), encrypted.end());
}

// Encrypts data using the given RSA public key.
// Returns the encrypted bytes.
std::vector<uint8_t> CryptoManager::encryptWithRSA(const std::vector<uint8_t>& public_key,
    const std::vector<uint8_t>& data) {
    std::string pub_str(public_key.begin(), public_key.end());
    RSAPublicWrapper rsa_pub(pub_str);
    std::string data_str(data.begin(), data.end());
    std::string encrypted = rsa_pub.encrypt(data_str);
    return std::vector<uint8_t>(encrypted.begin(), encrypted.end());
}

// Decrypts ciphertext using the AES symmetric key stored for the given sender client.
// Returns the decrypted plaintext string.
std::string CryptoManager::decryptWithAES(const uint8_t* sender_id,
    const std::vector<uint8_t>& ciphertext) {
    auto key = getSymmetricKey(sender_id);
    AESWrapper aes(key.data(), static_cast<unsigned int>(key.size()));
    return aes.decrypt(reinterpret_cast<const char*>(ciphertext.data()),
        static_cast<unsigned int>(ciphertext.size()));
}

// Decrypts ciphertext using the client's RSA private key.
// Returns the decrypted plaintext string.
std::string CryptoManager::decryptWithRSA(const std::vector<uint8_t>& ciphertext) {
    std::string cipher_str(ciphertext.begin(), ciphertext.end());
    return rsa.decrypt(cipher_str);
}
