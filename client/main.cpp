#include "MessageUClient.h"
#include <iostream>
// Entry point: creates a MessageUClient instance and starts the main loop.
// Returns 1 on fatal error, 0 on clean exit.
int main() {
    try {
        MessageUClient client;
        client.run();
    }
    catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
