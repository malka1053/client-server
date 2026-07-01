#pragma once
#include "message.h"
#include <string>

// Abstract base class for all incoming message types.
// Each subclass knows how to display itself.
class ReceivedMessage {
public:
    explicit ReceivedMessage(const Message& msg, const std::string& sender_name)
        : msg(msg), sender_name(sender_name) {
    }

    virtual void display() = 0;
    virtual ~ReceivedMessage() = default;

protected:
    const Message& msg;
    const std::string& sender_name;
};
