#include <iostream>
#include <string>
#include <vector>
#include <thread>   // For std::this_thread::sleep_for
#include <chrono>   // For std::chrono::milliseconds
#include <iomanip>  // For std::setw (to format output)

// --- The "Server" Side ---
// This is the account the simulator is trying to breach.
const std::string correctUsername = "admin";
const std::string correctPassword = "P@ssw0rd123";

/**
 * @brief Simulates a server's login check.
 * @param username The username being attempted.
 * @param password The password being attempted.
 * @return true if credentials are correct, false otherwise.
 */
bool attemptLogin(const std::string& username, const std::string& password) {
    // Simulate network/database delay.
    // A real server takes time to process a login, which is what
    // makes brute-force attacks slow.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Check if the credentials are correct
    return (username == correctUsername && password == correctPassword);
}

// --- The "Attacker" Side ---
int main() {
    std::cout << "--- Brute Force Login Simulator ---" << std::endl;

    std::string targetUsername = "admin";
    
    // This is the "dictionary" of common passwords.
    // The attacker will try every password in this list.
    std::vector<std::string> passwordList = {
        "123456",
        "password",
        "123456789",
        "welcome",
        "admin",
        "qwerty",
        "sunshine",
        "monkey",
        "princess",
        "shadow",
        "P@ssw0rd123", // <-- The correct password is in the list
        "dragon",
        "football",
        "iloveyou"
    };

    std::cout << "Targeting user: " << targetUsername << std::endl;
    std::cout << "Loaded " << passwordList.size() << " passwords from dictionary." << std::endl;
    std::cout << "Starting attack...\n" << std::endl;
    std::cout << "---------------------------------" << std::endl;

    bool passwordFound = false;
    std::string foundPassword = "";

    // Start a timer to see how long the attack takes
    auto startTime = std::chrono::high_resolution_clock::now();

    // Loop through every password in the dictionary
    for (const std::string& currentPassword : passwordList) {
        
        // std::left and std::setw create aligned columns for clean output
        std::cout << "Attempting: " << std::left << std::setw(15) << currentPassword;

        // Try to log in with the current password
        if (attemptLogin(targetUsername, currentPassword)) {
            passwordFound = true;
            foundPassword = currentPassword;
            std::cout << " [SUCCESS]" << std::endl;
            break; // Stop the attack, password is found
        } else {
            std::cout << " [FAILED]" << std::endl;
        }
    }

    // Stop the timer
    auto endTime = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = endTime - startTime;

    std::cout << "---------------------------------" << std::endl;
    if (passwordFound) {
        std::cout << "\n✅ Attack Successful!" << std::endl;
        std::cout << "Password for '" << targetUsername << "' is: " << foundPassword << std::endl;
    } else {
        std::cout << "\n❌ Attack Failed." << std::endl;
        std::cout << "Password was not in the dictionary." << std::endl;
    }

    // Set precision for displaying time
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "\nTotal time taken: " << duration.count() << " seconds." << std::endl;

    return 0;
}