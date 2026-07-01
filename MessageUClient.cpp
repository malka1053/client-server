#include "MessageUClient.h"
#include "Base64Wrapper.h"
#include <iostream>
#include <fstream>
#include <algorithm>
#include <filesystem>
#include "AESWrapper.h"

using boost::asio::ip::tcp;


//  Constructor
// Initializes the client with default port, zeroed client_id, and no registration.
// Attempts to load server address from myport.info and existing identity from me.info.
MessageUClient::MessageUClient()
    : server_port("1357"), sock(io_context), registered(false)
{
    std::fill(std::begin(client_id), std::end(client_id), 0);
    loadServerInfo();
    loadMyInfo();
}


// ------------------------------------------------------------------ //
//  File helpers
// ------------------------------------------------------------------ //

// Reads server IP and port from myport.info in the format "ip:port".
// If no colon is found, treats the entire line as the port and defaults IP to 127.0.0.1.
// Throws std::runtime_error if the file cannot be opened.
void MessageUClient::loadServerInfo() {
    std::ifstream file(SERVER_INFO_FILE);
    if (!file)
        throw std::runtime_error("Could not open " + std::string(SERVER_INFO_FILE));
    std::string line;
    if (std::getline(file, line)) {
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            server_ip = line.substr(0, colon);
            server_port = line.substr(colon + 1);
        }
        else {
            server_ip = "127.0.0.1";
            server_port = line;
        }
    }
    std::cout << "SERVER: " << server_ip << ":" << server_port << std::endl;
}
// Reads username, hex client_id, and Base64-encoded RSA private key from me.info.
// Reconstructs the RSAPrivateWrapper, CryptoManager, and MessageDisplay from the stored key.
// Returns false silently if the file does not exist (first run).
// Returns false with a warning if the file exists but is malformed or unreadable.
bool MessageUClient::loadMyInfo() {
    std::ifstream file(MY_INFO_FILE);
    if (!file) return false;
    try {
        std::string client_id_hex, line, private_key_b64;
        if (!std::getline(file, username))      return false;
        if (!std::getline(file, client_id_hex)) return false;
        while (std::getline(file, line)) private_key_b64 += line;
        if (private_key_b64.empty()) return false;

        ResponseParser::hexToBytes(client_id_hex, client_id, CLIENT_ID_SIZE);
        rsa_private = std::make_unique<RSAPrivateWrapper>(Base64Wrapper::decode(private_key_b64));
        crypto = std::make_unique<CryptoManager>(*rsa_private);
        display = std::make_unique<MessageDisplay>(*crypto);
        registered = true;
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Warning: could not load " << MY_INFO_FILE << " (" << e.what() << ")" << std::endl;
        registered = false;
        return false;
    }
}
// Persists the current client identity to me.info.
// Writes username, hex-encoded client_id, and Base64-encoded RSA private key, one per line.
// Throws std::runtime_error if the file cannot be created.
void MessageUClient::saveMyInfo() {
    std::ofstream file(MY_INFO_FILE);
    if (!file)
        throw std::runtime_error("Could not create " + std::string(MY_INFO_FILE));
    file << username << "\n"
        << ResponseParser::bytesToHex(client_id, CLIENT_ID_SIZE) << "\n"
        << Base64Wrapper::encode(rsa_private->getPrivateKey()) << "\n";
}

// ------------------------------------------------------------------ //
//  Network helpers
// ------------------------------------------------------------------ //


// Resolves server_ip:server_port and opens a TCP connection.
// Returns true on success, false on connection failure (logs the error).
bool MessageUClient::connect() {
    try {
        tcp::resolver resolver(io_context);
        boost::asio::connect(sock, resolver.resolve(server_ip, server_port));
        return true;
    }
    catch (const boost::system::system_error& e) {
        std::cerr << "Connection failed: " << e.what() << std::endl;
        return false;
    }
}


// Gracefully shuts down and closes the TCP socket if it is open.
// Errors during shutdown are ignored to ensure the socket is always closed.
void MessageUClient::disconnect() {
    if (sock.is_open()) {
        boost::system::error_code ec;
        sock.shutdown(tcp::socket::shutdown_both, ec);
        sock.close(ec);
    }
}


// Sends a fully packed request buffer to the server over the open socket.
// Returns false silently if the write fails.
bool MessageUClient::sendRequest(const std::vector<uint8_t>& request) {
    try {
        boost::asio::write(sock, boost::asio::buffer(request));
        return true;
    }
    catch (const boost::system::system_error&) { return false; }
}


// Reads a 7-byte response header, then reads the payload indicated by payload_size.
// Throws std::runtime_error if the server returns RES_GENERAL_ERROR.
// Returns the payload bytes (empty vector if payload_size is 0).
std::vector<uint8_t> MessageUClient::receiveResponse() {
    std::vector<uint8_t> header(7);
    boost::asio::read(sock, boost::asio::buffer(header));
    auto resp_header = Protocol::unpackResponseHeader(header);
    if (resp_header.code == RES_GENERAL_ERROR)
        throw std::runtime_error("Server responded with an error");
    std::vector<uint8_t> payload(resp_header.payload_size);
    if (resp_header.payload_size > 0)
        boost::asio::read(sock, boost::asio::buffer(payload));
    return payload;
}

// ------------------------------------------------------------------ //
//  Client lookup helpers
// ------------------------------------------------------------------ //


// Searches a client list for an entry matching the given name.
// Copies the matching client_id into out_id if found.
// Returns false if no match is found.
bool MessageUClient::findClientByName(const std::vector<ClientInfo>& clients,
    const std::string& name, uint8_t* out_id) const {
    auto it = std::find_if(clients.begin(), clients.end(),
        [&name](const ClientInfo& c) { return c.name == name; });
    if (it == clients.end()) return false;
    std::copy(std::begin(it->id), std::end(it->id), out_id);
    return true;
}


// Sends a client list request to the server and returns the parsed result.
std::vector<ClientInfo> MessageUClient::fetchClientList() {
    sendRequest(Protocol::packClientListRequest(client_id));
    return ResponseParser::parseClientList(receiveResponse());
}


// Fetches the full client list and searches it for the given name.
// Copies the resolved client_id into out_id on success.
// Prints an error message and returns false if the name is not found.
bool MessageUClient::resolveClientByName(const std::string& name, uint8_t* out_id) {
    if (!findClientByName(fetchClientList(), name, out_id)) {
        std::cout << "Server responded with an error" << std::endl;
        return false;
    }
    return true;
}

// ------------------------------------------------------------------ //
//  Menu actions
// ------------------------------------------------------------------ //


// Registers a new client: prompts for a username, generates an RSA key pair,
// sends the registration request with the public key, stores the returned client_id,
// and persists the identity to me.info.
void MessageUClient::registerClient() {
    if (registered) { std::cout << "Already registered as: " << username << std::endl; return; }

    std::cout << "Enter your username: ";
    std::getline(std::cin, username);

    rsa_private = std::make_unique<RSAPrivateWrapper>();
    crypto = std::make_unique<CryptoManager>(*rsa_private);
    display = std::make_unique<MessageDisplay>(*crypto);

    std::string pub_key_str = rsa_private->getPublicKey();
    std::vector<uint8_t> public_key(pub_key_str.begin(), pub_key_str.end());

    if (!connect()) throw std::runtime_error("server responded with an error");
    if (!sendRequest(Protocol::packRegisterRequest(username, public_key)))
        throw std::runtime_error("server responded with an error");

    auto response = receiveResponse();
    if (response.size() >= CLIENT_ID_SIZE) {
        std::copy(response.begin(), response.begin() + CLIENT_ID_SIZE, client_id);
        registered = true;
        saveMyInfo();
        std::cout << "Registration successful! ID: "
            << ResponseParser::clientIdToString(client_id) << std::endl;
    }
    disconnect();
}


// Fetches and prints the list of all registered clients (name and hex client_id).
void MessageUClient::requestClientList() {
    if (!connect()) throw std::runtime_error("server responded with an error");
    auto clients = fetchClientList();
    std::cout << "\n=== Client List ===" << std::endl;
    if (!clients.empty())
        for (const auto& c : clients)
            std::cout << c.name  << std::endl;
    else
        std::cout << "No other clients" << std::endl;
    disconnect();
}


// Prompts for a target client name, resolves their client_id, and requests their public key.
// Prints the size of the received public key on success.
void MessageUClient::requestPublicKey() {
    std::string target_name;
    std::cout << "Enter client name: ";
    std::getline(std::cin, target_name);

    if (!connect()) throw std::runtime_error("server responded with an error");
    uint8_t target_id[CLIENT_ID_SIZE];
    if (!resolveClientByName(target_name, target_id)) { disconnect(); return; }

    sendRequest(Protocol::packPublicKeyRequest(client_id, target_id));
    auto response = ResponseParser::parsePublicKey(receiveResponse());
    std::cout << "Public key received (" << response.public_key.size() << " bytes)" << std::endl;
    disconnect();
}


// Fetches the client list (for name resolution), then retrieves and displays all waiting messages.
// Each message is dispatched to MessageDisplay::printMessage which handles decryption by type.
void MessageUClient::requestWaitingMessages() {
    if (!connect()) throw std::runtime_error("server responded with an error");

    auto clients = fetchClientList();
    std::map<std::string, std::string> id_to_name;
    for (const auto& c : clients)
        id_to_name[ResponseParser::clientIdToString(c.id)] = c.name;

    sendRequest(Protocol::packWaitingMessagesRequest(client_id));
    auto messages = ResponseParser::parseMessages(receiveResponse());

    std::cout << "\n=== Waiting Messages ===" << std::endl;
    if (messages.empty()) { std::cout << "No messages" << std::endl; disconnect(); return; }

    for (const auto& msg : messages) {
        std::string sid = ResponseParser::clientIdToString(msg.from_client);
        std::string name = id_to_name.count(sid) ? id_to_name[sid] : "Unknown";
        display->printMessage(msg, name);
    }
    disconnect();
}


// Prompts for a target name and message text, encrypts the text with the stored AES key,
// and sends it as MSG_TYPE_TEXT_MESSAGE. Requires a symmetric key to already exist for the target.
void MessageUClient::sendTextMessage() {
    std::string target_name, message;
    std::cout << "Enter client name: ";   std::getline(std::cin, target_name);

    if (!connect()) throw std::runtime_error("server responded with an error");
    uint8_t target_id[CLIENT_ID_SIZE];
    if (!resolveClientByName(target_name, target_id)) { disconnect(); return; }
    if (!crypto->hasSymmetricKey(target_id)) {
        std::cout << "No symmetric key for " << target_name << ". Use option 151/152 first." << std::endl;
        disconnect(); return;
    }

    std::cout << "Enter message: ";
    std::getline(std::cin, message);

    auto encrypted = crypto->encryptWithAES(target_id, message);
    sendRequest(Protocol::packSendMessageRequest(client_id, target_id, MSG_TYPE_TEXT_MESSAGE, encrypted));
    receiveResponse();
    std::cout << "Message sent successfully" << std::endl;
    disconnect();
}


// Sends an empty MSG_TYPE_SYM_KEY_REQUEST message to the target client,
// asking them to respond with their symmetric key.
void MessageUClient::requestSymmetricKey() {
    std::string target_name;
    std::cout << "Enter client name: ";
    std::getline(std::cin, target_name);

    if (!connect()) throw std::runtime_error("server responded with an error");
    uint8_t target_id[CLIENT_ID_SIZE];
    if (!resolveClientByName(target_name, target_id)) { disconnect(); return; }

    sendRequest(Protocol::packSendMessageRequest(client_id, target_id, MSG_TYPE_SYM_KEY_REQUEST, {}));
    receiveResponse();
    std::cout << "Symmetric key request sent to " << target_name << std::endl;
    disconnect();
}


// Generates a new AES key, fetches the target's public key, encrypts the AES key with RSA,
// sends it as MSG_TYPE_SYM_KEY_SEND, and stores the key locally for future use.
void MessageUClient::sendSymmetricKey() {
    std::string target_name;
    std::cout << "Enter client name: ";
    std::getline(std::cin, target_name);

    if (!connect()) throw std::runtime_error("server responded with an error");
    uint8_t target_id[CLIENT_ID_SIZE];
    if (!resolveClientByName(target_name, target_id)) { disconnect(); return; }

    sendRequest(Protocol::packPublicKeyRequest(client_id, target_id));
    auto pubkey_response = ResponseParser::parsePublicKey(receiveResponse());

    AESWrapper aes;
    std::vector<uint8_t> sym_key(aes.getKey(), aes.getKey() + AESWrapper::DEFAULT_KEYLENGTH);
    auto encrypted_key = crypto->encryptWithRSA(pubkey_response.public_key, sym_key);

    sendRequest(Protocol::packSendMessageRequest(client_id, target_id, MSG_TYPE_SYM_KEY_SEND, encrypted_key));
    receiveResponse();

    crypto->saveSymmetricKey(target_id, sym_key);
    std::cout << "Symmetric key sent to " << target_name << std::endl;
    disconnect();
}


// Prompts for a recipient name and local filename, reads the file as binary,
// encrypts the contents with the stored AES key, and sends it as MSG_TYPE_FILE.
// Requires a symmetric key to already exist for the target.
void MessageUClient::sendFile() {
    std::string target_name, filename;
    std::cout << "Enter recipient name: ";
    std::getline(std::cin, target_name);

    if (!connect()) throw std::runtime_error("server responded with an error");
    uint8_t target_id[CLIENT_ID_SIZE];
    if (!resolveClientByName(target_name, target_id)) { disconnect(); return; }
    if (!crypto->hasSymmetricKey(target_id)) {
        std::cout << "No symmetric key for " << target_name << ". Use option 151/152 first." << std::endl;
        disconnect(); return;
    }

    std::cout << "Enter filename: ";
    std::getline(std::cin, filename);

    std::filesystem::path filepath(filename);
    if (!std::filesystem::exists(filepath)) { std::cout << "file not found" << std::endl; disconnect(); return; }

    std::ifstream file(filepath, std::ios::binary);
    if (!file) { std::cout << "file not found" << std::endl; disconnect(); return; }

    std::string contents((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    auto encrypted = crypto->encryptWithAES(target_id, contents);

    sendRequest(Protocol::packSendMessageRequest(client_id, target_id, MSG_TYPE_FILE, encrypted));
    receiveResponse();
    std::cout << "File sent successfully" << std::endl;
    disconnect();
}

// ------------------------------------------------------------------ //
//  Menu
// ------------------------------------------------------------------ //


// Prints the main menu options to stdout.
void MessageUClient::showMenu() const {
    std::cout << "\nMessageU client at your service.\n"
        << "110) Register\n120) Request for clients list\n"
        << "130) Request for public key\n140) Request for waiting messages\n"
        << "150) Send a text message\n151) Send a request for symmetric key\n"
        << "152) Send your symmetric key\n153) Send a file\n0) Exit client\n? ";
}


// Main event loop: displays the menu, reads user input, validates it as a numeric command,
// and dispatches to the appropriate action. Requires registration before any action except 110.
// All exceptions from actions are caught and reported as a generic server error message.
void MessageUClient::run() {
    if (registered)
        std::cout << "Loaded existing registration for: " << username << std::endl;

    std::string choice;
    while (true) {
        showMenu();
        if (!std::getline(std::cin, choice) || choice.empty()) continue;

        bool valid = std::all_of(choice.begin(), choice.end(),
            [](char c) { return std::isdigit(c) != 0; });
        if (!valid) { std::cout << "server responded with an error" << std::endl; continue; }

        int cmd = std::stoi(choice);
        if (cmd == 0) { std::cout << "GOODBYE!" << std::endl; return; }
        if (cmd != 110 && !registered) { std::cout << "Please register first" << std::endl; continue; }

        try {
            switch (cmd) {
            case 110: registerClient();         break;
            case 120: requestClientList();      break;
            case 130: requestPublicKey();       break;
            case 140: requestWaitingMessages(); break;
            case 150: sendTextMessage();        break;
            case 151: requestSymmetricKey();    break;
            case 152: sendSymmetricKey();       break;
            case 153: sendFile();               break;
            default:  std::cout << "server responded with an error" << std::endl;
            }
        }
        catch (const std::exception&) {
            std::cerr << "server responded with an error" << std::endl;
        }
    }
}
