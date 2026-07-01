#include "message.h"
#include "protocol.h"
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <boost/endian/conversion.hpp>

// Parses a flat byte payload into a list of ClientInfo structs.
// Each entry is exactly CLIENT_ID_SIZE + USERNAME_MAX_SIZE bytes:
// [16 bytes client_id][255 bytes null-terminated username].
std::vector<ClientInfo> ResponseParser::parseClientList(const std::vector<uint8_t>& payload) {
    std::vector<ClientInfo> clients;

    size_t offset = 0;
    while (offset + CLIENT_ID_SIZE + USERNAME_MAX_SIZE <= payload.size()) {
        ClientInfo client;

        // Copy client ID (16 bytes)
        std::copy(payload.begin() + offset,
            payload.begin() + offset + CLIENT_ID_SIZE,
            client.id);
        offset += CLIENT_ID_SIZE;

        // Parse null-terminated username
        const char* name_ptr = reinterpret_cast<const char*>(payload.data() + offset);
        client.name = std::string(name_ptr);
        offset += USERNAME_MAX_SIZE;

        clients.push_back(client);
    }

    return clients;
}
// Parses a public key response payload into a PublicKeyResponse struct.
// Expected layout: [16 bytes client_id][160 bytes public_key].
// Throws std::runtime_error if the payload is too short.
PublicKeyResponse ResponseParser::parsePublicKey(const std::vector<uint8_t>& payload) {
    if (payload.size() < CLIENT_ID_SIZE + PUBLIC_KEY_SIZE) {
        throw std::runtime_error("server responded with an error");
    }

    PublicKeyResponse response;

    // Copy client ID (16 bytes)
    std::copy(payload.begin(),
        payload.begin() + CLIENT_ID_SIZE,
        response.client_id);

    // Copy public key (160 bytes)
    response.public_key = std::vector<uint8_t>(
        payload.begin() + CLIENT_ID_SIZE,
        payload.begin() + CLIENT_ID_SIZE + PUBLIC_KEY_SIZE
    );

    return response;
}
// Parses a waiting-messages payload into a list of Message structs.
// Each message is variable length with the layout:
// [16 bytes from_client_id][4 bytes message_id LE][1 byte type][4 bytes content_size LE][content_size bytes content].
// Stops parsing if there are not enough bytes left for a complete message header.
std::vector<Message> ResponseParser::parseMessages(const std::vector<uint8_t>& payload) {
    std::vector<Message> messages;

    size_t offset = 0;
    while (offset < payload.size()) {
        // Minimum message size: client_id + id + type + content_size
        if (offset + CLIENT_ID_SIZE + 4 + 1 + 4 > payload.size()) {
            break;
        }

        Message msg;

        // Copy sender client ID (16 bytes)
        std::copy(payload.begin() + offset,
            payload.begin() + offset + CLIENT_ID_SIZE,
            msg.from_client);
        offset += CLIENT_ID_SIZE;

        // Message ID - little-endian (4 bytes)
        uint32_t id_le;
        std::copy(payload.begin() + offset,
            payload.begin() + offset + 4,
            reinterpret_cast<uint8_t*>(&id_le));
        msg.id = boost::endian::little_to_native(id_le);
        offset += 4;

        // Message type (1 byte)
        msg.type = payload[offset];
        offset += 1;

        // Content size - little-endian (4 bytes)
        uint32_t content_size_le;
        std::copy(payload.begin() + offset,
            payload.begin() + offset + 4,
            reinterpret_cast<uint8_t*>(&content_size_le));
        uint32_t content_size = boost::endian::little_to_native(content_size_le);
        offset += 4;

        // Message content
        if (offset + content_size <= payload.size()) {
            msg.content = std::vector<uint8_t>(
                payload.begin() + offset,
                payload.begin() + offset + content_size
            );
            offset += content_size;
        }

        messages.push_back(msg);
    }

    return messages;
}
// Converts a raw byte array of the given length into a lowercase hex string.
// Used for displaying client IDs and keys in human-readable form.
std::string ResponseParser::bytesToHex(const uint8_t* bytes, size_t length) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; i++) {
        oss << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return oss.str();
}
// Converts a raw byte array of the given length into a lowercase hex string.
// Used for displaying client IDs and keys in human-readable form.
void ResponseParser::hexToBytes(const std::string& hex, uint8_t* bytes, size_t length) {
    for (size_t i = 0; i < length; i++) {
        std::string byte_str = hex.substr(i * 2, 2);
        bytes[i] = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
    }
}
// Converts a 16-byte client ID to a 32-character lowercase hex string.
// Convenience wrapper around bytesToHex for the fixed CLIENT_ID_SIZE length.
std::string ResponseParser::clientIdToString(const uint8_t* client_id) {
    return bytesToHex(client_id, CLIENT_ID_SIZE);
}
