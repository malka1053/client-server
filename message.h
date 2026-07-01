#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include "protocol.h"

struct ClientInfo {
    uint8_t id[CLIENT_ID_SIZE];
    std::string name;
};

struct PublicKeyResponse {
    uint8_t client_id[CLIENT_ID_SIZE];
    std::vector<uint8_t> public_key;
};

struct Message {
    uint32_t id;
    uint8_t from_client[CLIENT_ID_SIZE];
    uint8_t type;
    std::vector<uint8_t> content;
};

class ResponseParser {
public:
    // Parses the client list payload into a vector of ClientInfo
    static std::vector<ClientInfo> parseClientList(const std::vector<uint8_t>& payload);

    // Parses the public key payload into a PublicKeyResponse
    static PublicKeyResponse parsePublicKey(const std::vector<uint8_t>& payload);

    // Parses the waiting messages payload into a vector of Message
    static std::vector<Message> parseMessages(const std::vector<uint8_t>& payload);

    // Converts raw bytes to hex string representation
    static std::string bytesToHex(const uint8_t* bytes, size_t length);

    // Converts hex string to raw bytes
    static void hexToBytes(const std::string& hex, uint8_t* bytes, size_t length);

    // Returns client ID as hex string
    static std::string clientIdToString(const uint8_t* client_id);
};
#pragma once
