#include "SymKeyRequest.h"
#include <iostream>

// Prints a notification that the sender is requesting a symmetric key.
void SymKeyRequest::display() {
    std::cout << "From: " << sender_name << "\nContent:" << std::endl;
    std::cout << "Request for symmetric key" << std::endl;
    std::cout << "-----<EOM>-----\n" << std::endl;
}
