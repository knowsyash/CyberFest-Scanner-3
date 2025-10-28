// safe_console_logger.cpp
// Build: g++ safe_console_logger.cpp -o safe_console_logger
#include <iostream>
#include <fstream>
#include <string>
#include <chrono>
#include <ctime>

int main() {
    std::ofstream out("console_log.txt", std::ios::app);
    if (!out) {
        std::cerr << "Cannot open console_log.txt for writing\n";
        return 1;
    }

    std::cout << "This program records what you type here into console_log.txt.\n";
    std::cout << "Type lines and press Enter. Type '/quit' to exit.\n\n";

    std::string line;
    while (true) {
        if (!std::getline(std::cin, line)) break;
        if (line == "/quit") break;

        // Timestamp
        auto now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);

        out << std::ctime(&t) << ": " << line << "\n";
        out.flush();
        std::cout << "[saved]\n";
    }

    out.close();
    std::cout << "Exiting. Log saved to console_log.txt\n";
    return 0;
}
