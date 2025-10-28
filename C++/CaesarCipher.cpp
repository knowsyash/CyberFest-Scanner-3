#include <iostream>
#include <string>
#include <limits> // Used for clearing input buffer

// Function to encrypt a string using Caesar Cipher
std::string encrypt(std::string text, int s) {
    std::string result = "";

    // Traverse text
    for (int i = 0; i < text.length(); i++) {
        // Apply transformation to each character
        char c = text[i];

        // Encrypt uppercase characters
        if (isupper(c)) {
            // (c - 'A' + s) % 26 gives the new position (0-25)
            // + 'A' converts it back to ASCII uppercase
            result += char(int(c - 'A' + s) % 26 + 'A');
        }
        // Encrypt lowercase characters
        else if (islower(c)) {
            // (c - 'a' + s) % 26 gives the new position (0-25)
            // + 'a' converts it back to ASCII lowercase
            result += char(int(c - 'a' + s) % 26 + 'a');
        }
        // Keep non-alphabetic characters as they are
        else {
            result += c;
        }
    }
    return result;
}

// Function to decrypt a string using Caesar Cipher
std::string decrypt(std::string text, int s) {
    std::string result = "";

    // Traverse text
    for (int i = 0; i < text.length(); i++) {
        // Apply transformation to each character
        char c = text[i];

        // Decrypt uppercase characters
        if (isupper(c)) {
            // (c - 'A' - s + 26) % 26 handles negative modulo
            // + 'A' converts it back to ASCII uppercase
            result += char(int(c - 'A' - s + 26) % 26 + 'A');
        }
        // Decrypt lowercase characters
        else if (islower(c)) {
            // (c - 'a' - s + 26) % 26 handles negative modulo
            // + 'a' converts it back to ASCII lowercase
            result += char(int(c - 'a' - s + 26) % 26 + 'a');
        }
        // Keep non-alphabetic characters as they are
        else {
            result += c;
        }
    }
    return result;
}

// Helper function to clear input buffer
void clearInputBuffer() {
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

int main() {
    std::string text;
    int shift;
    int choice;

    std::cout << "--- Caesar Cipher Tool ---" << std::endl;

    // Get user's choice: encrypt or decrypt
    while (true) {
        std::cout << "\nChoose an option:" << std::endl;
        std::cout << "1. Encrypt" << std::endl;
        std::cout << "2. Decrypt" << std::endl;
        std::cout << "Enter choice (1 or 2): ";
        
        if (std::cin >> choice && (choice == 1 || choice == 2)) {
            clearInputBuffer(); // Clear the newline character
            break;
        } else {
            std::cout << "Invalid input. Please enter 1 or 2." << std::endl;
            std::cin.clear(); // Clear error flags
            clearInputBuffer(); // Clear the bad input
        }
    }

    // Get the message from the user
    std::cout << "\nEnter your message: ";
    std::getline(std::cin, text);

    // Get the shift key from the user
    while (true) {
        std::cout << "Enter shift key (a number from 1 to 25): ";
        if (std::cin >> shift && shift >= 1 && shift <= 25) {
            clearInputBuffer(); // Clear the newline character
            break;
        } else {
            std::cout << "Invalid input. Please enter a number between 1 and 25." << std::endl;
            std::cin.clear(); // Clear error flags
            clearInputBuffer(); // Clear the bad input
        }
    }
    
    // Ensure shift is within 0-25 range
    shift = shift % 26;

    // Perform encryption or decryption
    if (choice == 1) {
        std::string encryptedText = encrypt(text, shift);
        std::cout << "\n--- Result ---" << std::endl;
        std::cout << "Text: " << text << std::endl;
        std::cout << "Shift: " << shift << std::endl;
        std::cout << "Encrypted Text: " << encryptedText << std::endl;
    } else if (choice == 2) {
        std::string decryptedText = decrypt(text, shift);
        std::cout << "\n--- Result ---" << std::endl;
        std::cout << "Text: " << text << std::endl;
        std::cout << "Shift: " << shift << std::endl;
        std::cout << "Decrypted Text: " << decryptedText << std::endl;
    }

    return 0;
}