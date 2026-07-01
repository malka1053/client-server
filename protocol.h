#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <boost/endian/conversion.hpp>

constexpr uint8_t VERSION = 2;
constexpr size_t CLIENT_ID_SIZE = 16;
constexpr size_t USERNAME_MAX_SIZE = 255;
constexpr size_t PUBLIC_KEY_SIZE = 160;
constexpr size_t HEADER_SIZE = 23;

// Request codes
constexpr uint16_t REQ_REGISTER = 700;
constexpr uint16_t REQ_CLIENT_LIST = 701;
constexpr uint16_t REQ_PUBLIC_KEY = 702;
constexpr uint16_t REQ_SEND_MESSAGE = 703;
constexpr uint16_t REQ_WAITING_MESSAGES = 704;
constexpr uint16_t REQ_EXIT = 0;

// Menu codes
constexpr uint16_t MENU_REGISTER = 110;
constexpr uint16_t MENU_CLIENT_LIST = 120;
constexpr uint16_t MENU_PUBLIC_KEY = 130;
constexpr uint16_t MENU_WAITING_MESSAGES = 140;
constexpr uint16_t MENU_SEND_TEXT = 150;
constexpr uint16_t MENU_SEND_SYM_KEY_REQUEST = 151;
constexpr uint16_t MENU_SEND_SYM_KEY = 152;
constexpr uint16_t MENU_SEND_FILE = 153;

// Response codes
constexpr uint16_t RES_REGISTRATION_SUCCESS = 2100;
constexpr uint16_t RES_CLIENT_LIST = 2101;
constexpr uint16_t RES_PUBLIC_KEY = 2102;
constexpr uint16_t RES_MESSAGE_SENT = 2103;
constexpr uint16_t RES_WAITING_MESSAGES = 2104;
constexpr uint16_t RES_GENERAL_ERROR = 9000;

// Message types
constexpr uint8_t MSG_TYPE_SYM_KEY_REQUEST = 1;
constexpr uint8_t MSG_TYPE_SYM_KEY_SEND = 2;
constexpr uint8_t MSG_TYPE_TEXT_MESSAGE = 3;
constexpr uint8_t MSG_TYPE_FILE = 4;

struct RequestHeader {
    uint8_t client_id[CLIENT_ID_SIZE];
    uint8_t version;
    uint16_t code;
    uint32_t payload_size;
};

struct ResponseHeader {
    uint8_t version;
    uint16_t code;
    uint32_t payload_size;
};

class Protocol {
public:
    // Builds 23-byte request header with little-endian encoding for wire transmission
    static std::vector<uint8_t> packRequestHeader(
        const uint8_t* client_id,
        uint16_t code,
        uint32_t payload_size
    );

    // Parses binary response header from server
    static ResponseHeader unpackResponseHeader(const std::vector<uint8_t>& data);

    // Registration uses null client_id (not yet assigned by server)
    static std::vector<uint8_t> packRegisterRequest(
        const std::string& username,
        const std::vector<uint8_t>& public_key
    );

    static std::vector<uint8_t> packClientListRequest(const uint8_t* client_id);

    static std::vector<uint8_t> packPublicKeyRequest(
        const uint8_t* client_id,
        const uint8_t* target_client_id
    );

    static std::vector<uint8_t> packWaitingMessagesRequest(const uint8_t* client_id);

    static std::vector<uint8_t> packSendMessageRequest(
        const uint8_t* from_client_id,
        const uint8_t* to_client_id,
        uint8_t msg_type,
        const std::vector<uint8_t>& content
    );
};