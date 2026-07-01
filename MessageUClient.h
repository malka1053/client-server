#pragma once
#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <boost/asio.hpp>
#include "protocol.h"
#include "message.h"
#include "RSAWrapper.h"
#include "CryptoManager.h"
#include "MessageDisplay.h"

constexpr const char* SERVER_INFO_FILE = "server.info";
constexpr const char* MY_INFO_FILE = "me.info";

class MessageUClient {
public:
    MessageUClient();
    ~MessageUClient() = default;
    void run();

private:
    // --- State ---
    std::string                        server_ip;
    std::string                        server_port;
    boost::asio::io_context            io_context;
    boost::asio::ip::tcp::socket       sock;
    uint8_t                            client_id[CLIENT_ID_SIZE];
    std::string                        username;
    std::unique_ptr<RSAPrivateWrapper> rsa_private;
    bool                               registered;
    std::unique_ptr<CryptoManager>     crypto;
    std::unique_ptr<MessageDisplay>    display;

    // --- File helpers ---
    void loadServerInfo();
    bool loadMyInfo();
    void saveMyInfo();

    // --- Network helpers ---
    bool connect();
    void disconnect();
    bool sendRequest(const std::vector<uint8_t>& request);
    std::vector<uint8_t> receiveResponse();

    // --- Client lookup helpers ---
    bool findClientByName(const std::vector<ClientInfo>& clients,
        const std::string& name, uint8_t* out_id) const;
    std::vector<ClientInfo> fetchClientList();
    bool resolveClientByName(const std::string& name, uint8_t* out_id);

    // --- Menu actions ---
    void registerClient();
    void requestClientList();
    void requestPublicKey();
    void requestWaitingMessages();
    void sendTextMessage();
    void requestSymmetricKey();
    void sendSymmetricKey();
    void sendFile();
    void showMenu() const;
};
