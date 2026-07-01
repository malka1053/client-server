#include "protocol.h"
#include <stdexcept>
#include <boost/endian/conversion.hpp>


// Builds a binary request header of HEADER_SIZE bytes in the protocol format:
// [16 bytes client_id][1 byte version][2 bytes code LE][4 bytes payload_size LE].
// Used internally by all pack* functions before appending their specific payload.
std::vector<uint8_t> Protocol::packRequestHeader(
    const uint8_t* client_id,
    uint16_t code,
    uint32_t payload_size
) {
    std::vector<uint8_t> header(HEADER_SIZE);

    // Copy client ID (16 bytes)
    std::copy(client_id, client_id + CLIENT_ID_SIZE, header.begin());

    // Version (1 byte)
    header[CLIENT_ID_SIZE] = VERSION;

    // Request code - little-endian (2 bytes)
    uint16_t code_le = boost::endian::native_to_little(code);
    const uint8_t* code_ptr = reinterpret_cast<const uint8_t*>(&code_le);
    std::copy(code_ptr, code_ptr + sizeof(code_le), header.begin() + CLIENT_ID_SIZE + 1);

    // Payload size - little-endian (4 bytes)
    uint32_t payload_le = boost::endian::native_to_little(payload_size);
    const uint8_t* payload_ptr = reinterpret_cast<const uint8_t*>(&payload_le);
    std::copy(payload_ptr, payload_ptr + sizeof(payload_le), header.begin() + CLIENT_ID_SIZE + 3);

    return header;
}


// Parses a 7-byte server response header into a ResponseHeader struct.
// Layout: [1 byte version][2 bytes code LE][4 bytes payload_size LE].
// Throws std::runtime_error if the buffer is shorter than 7 bytes.
ResponseHeader Protocol::unpackResponseHeader(const std::vector<uint8_t>& data) {
    if (data.size() < 7) {
        throw std::runtime_error("Invalid response header size");
    }

    ResponseHeader header;

    // Version (1 byte)
    header.version = data[0];

    // Response code - little-endian (2 bytes)
    uint16_t code_le;
    std::copy(data.begin() + 1, data.begin() + 3, reinterpret_cast<uint8_t*>(&code_le));
    header.code = boost::endian::little_to_native(code_le);

    // Payload size - little-endian (4 bytes)
    uint32_t payload_le;
    std::copy(data.begin() + 3, data.begin() + 7, reinterpret_cast<uint8_t*>(&payload_le));
    header.payload_size = boost::endian::little_to_native(payload_le);

    return header;
}


// Builds a REQ_REGISTER request with an empty client_id (not yet assigned).
// Payload layout: [255 bytes username, null-terminated, zero-padded][160 bytes public_key].
// Throws std::runtime_error if public_key is not exactly PUBLIC_KEY_SIZE bytes.
std::vector<uint8_t> Protocol::packRegisterRequest(
    const std::string& username,
    const std::vector<uint8_t>& public_key
) {
    if (public_key.size() != PUBLIC_KEY_SIZE) {
        throw std::runtime_error("Invalid public key size");
    }

    uint8_t empty_id[CLIENT_ID_SIZE] = { 0 };
    uint32_t payload_size = USERNAME_MAX_SIZE + PUBLIC_KEY_SIZE;

    auto request = packRequestHeader(empty_id, REQ_REGISTER, payload_size);

    // Fixed-size username field (null-terminated, padded with zeros)
    std::vector<uint8_t> username_bytes(USERNAME_MAX_SIZE, 0);
    size_t len = std::min(username.length(), size_t(USERNAME_MAX_SIZE - 1));
    std::copy(username.begin(), username.begin() + len, username_bytes.begin());
    request.insert(request.end(), username_bytes.begin(), username_bytes.end());

    request.insert(request.end(), public_key.begin(), public_key.end());

    return request;
}


// Builds a REQ_CLIENT_LIST request with no payload.
// The server responds with a list of all registered clients except the requester.
std::vector<uint8_t> Protocol::packClientListRequest(const uint8_t* client_id) {
    return packRequestHeader(client_id, REQ_CLIENT_LIST, 0);
}


// Builds a REQ_PUBLIC_KEY request with the target client's ID as the payload.
// The server responds with the target's stored RSA public key.
std::vector<uint8_t> Protocol::packPublicKeyRequest(
    const uint8_t* client_id,
    const uint8_t* target_client_id
) {
    auto request = packRequestHeader(client_id, REQ_PUBLIC_KEY, CLIENT_ID_SIZE);
    request.insert(request.end(), target_client_id, target_client_id + CLIENT_ID_SIZE);
    return request;
}


// Builds a REQ_WAITING_MESSAGES request with no payload.
// The server responds with all pending messages for this client and clears them.
std::vector<uint8_t> Protocol::packWaitingMessagesRequest(const uint8_t* client_id) {
    return packRequestHeader(client_id, REQ_WAITING_MESSAGES, 0);
}


// Builds a REQ_SEND_MESSAGE request.
// Payload layout: [16 bytes to_client_id][1 byte msg_type][4 bytes content_size LE][content bytes].
// msg_type must be one of: MSG_TYPE_SYM_KEY_REQUEST, MSG_TYPE_SYM_KEY_SEND,
// MSG_TYPE_TEXT_MESSAGE, or MSG_TYPE_FILE.
std::vector<uint8_t> Protocol::packSendMessageRequest(
    const uint8_t* from_client_id,
    const uint8_t* to_client_id,
    uint8_t msg_type,
    const std::vector<uint8_t>& content
) {
    uint32_t payload_size = CLIENT_ID_SIZE + 1 + 4 + static_cast<uint32_t>(content.size());
    auto request = packRequestHeader(from_client_id, REQ_SEND_MESSAGE, payload_size);

    // Target client ID (16 bytes)
    request.insert(request.end(), to_client_id, to_client_id + CLIENT_ID_SIZE);

    // Message type (1 byte)
    request.push_back(msg_type);

    // Content size - little-endian (4 bytes)
    uint32_t content_size_le = boost::endian::native_to_little(static_cast<uint32_t>(content.size()));
    const uint8_t* cs_ptr = reinterpret_cast<const uint8_t*>(&content_size_le);
    request.insert(request.end(), cs_ptr, cs_ptr + sizeof(content_size_le));

    // Message content
    request.insert(request.end(), content.begin(), content.end());

    return request;
}
