// port_scanner.cpp
// Build: g++ -std=c++17 -pthread port_scanner.cpp -o port_scanner
// Usage example:
//   ./port_scanner --host example.com --ports 1-1024 --timeout 0.5 --workers 100 --save result.json

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <mutex>
#include <queue>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

// -------------------- Utilities --------------------
void usage() {
    std::cout <<
    "Usage: port_scanner --host <host> [--ports <port-list>] [--timeout <sec>] [--workers <n>] [--save <file>]\n"
    "  --host    | -H   target hostname or IP (required)\n"
    "  --ports   | -p   e.g. 22,80,443 or 1-1024 (default 1-1024)\n"
    "  --timeout | -t   socket timeout seconds (default 0.5)\n"
    "  --workers | -w   concurrent workers (default 100)\n"
    "  --save    | -s   save JSON results to file (optional)\n";
}

// Parse ports like "22,80,443,8000-8100" or "1-1024"
std::vector<int> parse_ports(const std::string &s) {
    std::vector<int> out;
    std::stringstream ss(s);
    std::string part;
    std::set<int> seen;
    while (std::getline(ss, part, ',')) {
        auto dash = part.find('-');
        if (dash != std::string::npos) {
            int a = std::stoi(part.substr(0, dash));
            int b = std::stoi(part.substr(dash + 1));
            if (a > b) std::swap(a,b);
            for (int p = std::max(1,a); p <= std::min(65535,b); ++p) seen.insert(p);
        } else {
            int p = std::stoi(part);
            if (p >= 1 && p <= 65535) seen.insert(p);
        }
    }
    for (int p : seen) out.push_back(p);
    return out;
}

// Resolve hostname to IPv4 string. Throws runtime_error on failure.
std::string resolve_ipv4(const std::string &host) {
    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM;
    int rc = getaddrinfo(host.c_str(), nullptr, &hints, &res);
    if (rc != 0 || !res) {
        throw std::runtime_error(std::string("DNS resolution failed: ") + gai_strerror(rc));
    }
    char ipbuf[INET_ADDRSTRLEN]{};
    sockaddr_in *sin = reinterpret_cast<sockaddr_in*>(res->ai_addr);
    inet_ntop(AF_INET, &sin->sin_addr, ipbuf, sizeof(ipbuf));
    freeaddrinfo(res);
    return std::string(ipbuf);
}

// Non-blocking connect with timeout_ms. Returns true on success (port open).
bool try_connect_with_timeout(const std::string &ip, int port, int timeout_ms, std::string &banner) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    // set non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) { close(sock); return false; }
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    int rc = connect(sock, (sockaddr*)&addr, sizeof(addr));
    if (rc == 0) {
        // connected immediately
    } else {
        if (errno != EINPROGRESS) { close(sock); return false; }
        fd_set wf;
        FD_ZERO(&wf);
        FD_SET(sock, &wf);
        timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        int sel = select(sock + 1, nullptr, &wf, nullptr, &tv);
        if (sel <= 0) { close(sock); return false; } // timeout or error
        int so_error = 0;
        socklen_t len = sizeof(so_error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error != 0) { close(sock); return false; }
    }

    // connected: try to read a short banner (non-blocking with small timeout)
    fd_set rf;
    FD_ZERO(&rf);
    FD_SET(sock, &rf);
    timeval tv2;
    tv2.tv_sec = 0;
    tv2.tv_usec = 800000; // 800 ms (similar to your python)
    int r = select(sock + 1, &rf, nullptr, nullptr, &tv2);
    if (r > 0 && FD_ISSET(sock, &rf)) {
        char buf[1024];
        ssize_t n = recv(sock, buf, sizeof(buf)-1, 0);
        if (n > 0) {
            buf[n] = '\0';
            banner = std::string(buf);
        }
    }

    close(sock);
    return true;
}

// -------------------- Thread pool scanning --------------------
struct Result { int port; bool open; std::string banner; };

void worker_thread(const std::string &ip, const std::vector<int> &ports,
                   std::atomic<size_t> &idx, int timeout_ms,
                   std::mutex &out_mtx, std::vector<Result> &results)
{
    while (true) {
        size_t i = idx.fetch_add(1);
        if (i >= ports.size()) break;
        int port = ports[i];
        std::string banner;
        bool open = try_connect_with_timeout(ip, port, timeout_ms, banner);
        {
            std::lock_guard<std::mutex> lk(out_mtx);
            if (open) {
                std::cout << "[OPEN]  " << port;
                if (!banner.empty()) {
                    // sanitize banner for single-line printing
                    std::string b = banner;
                    for (char &c : b) if (c == '\n' || c == '\r') c = ' ';
                    std::cout << "  — banner: " << b;
                }
                std::cout << "\n";
            } else {
                // optional: print closed ports (comment out to reduce noise)
                // std::cout << "[CLOSED] " << port << "\n";
            }
        }
        results.push_back({port, open, banner});
    }
}

// -------------------- main --------------------
int main(int argc, char* argv[]) {
    if (argc == 1) { usage(); return 1; }

    std::string host;
    std::string ports_arg = "1-1024";
    double timeout_sec = 0.5;
    int workers = 100;
    std::string save_file;

    // simple argv parsing
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if ((a == "--host" || a == "-H") && i+1 < argc) host = argv[++i];
        else if ((a == "--ports" || a == "-p") && i+1 < argc) ports_arg = argv[++i];
        else if ((a == "--timeout" || a == "-t") && i+1 < argc) timeout_sec = std::stod(argv[++i]);
        else if ((a == "--workers" || a == "-w") && i+1 < argc) workers = std::stoi(argv[++i]);
        else if ((a == "--save" || a == "-s") && i+1 < argc) save_file = argv[++i];
        else { std::cerr << "Unknown arg: " << a << "\n"; usage(); return 1; }
    }

    if (host.empty()) { std::cerr << "Host required.\n"; usage(); return 1; }

    std::vector<int> ports;
    try {
        ports = parse_ports(ports_arg);
        if (ports.empty()) throw std::runtime_error("no ports parsed");
    } catch (...) {
        std::cerr << "Failed to parse ports.\n";
        return 1;
    }

    std::string ip;
    try {
        ip = resolve_ipv4(host);
    } catch (const std::exception &ex) {
        std::cerr << "❌ " << ex.what() << "\n";
        return 2;
    }

    std::cout << "🔎 Scanning " << ports.size() << " ports on " << host << " (" << ip << ")\n";
    std::cout << "Started at: " << std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()) << "\n";

    std::atomic<size_t> idx(0);
    std::mutex out_mtx;
    std::vector<std::thread> pool;
    std::vector<Result> results; results.reserve(ports.size());
    results.clear();

    int timeout_ms = static_cast<int>(timeout_sec * 1000.0);

    for (int i = 0; i < workers; ++i) {
        pool.emplace_back(worker_thread, ip, std::cref(ports),
                          std::ref(idx), timeout_ms, std::ref(out_mtx), std::ref(results));
    }

    for (auto &t : pool) if (t.joinable()) t.join();

    // Collect open ports
    std::vector<Result> open;
    for (auto &r : results) if (r.open) open.push_back(r);

    std::cout << "\n✅ Scan complete\n";
    std::cout << "Open ports (" << open.size() << "):\n";
    for (auto &r : open) {
        if (!r.banner.empty()) {
            std::string b = r.banner;
            for (char &c : b) if (c == '\n' || c == '\r') c = ' ';
            std::cout << " - " << r.port << "  |  " << b << "\n";
        } else {
            std::cout << " - " << r.port << "\n";
        }
    }

    if (!save_file.empty()) {
        // simple JSON emit
        std::ofstream ofs(save_file);
        if (ofs) {
            ofs << "{\n";
            ofs << "  \"target\": \"" << host << "\",\n";
            ofs << "  \"ip\": \"" << ip << "\",\n";
            ofs << "  \"scanned_at\": \"" << std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()) << "\",\n";
            ofs << "  \"open_ports\": [\n";
            for (size_t i = 0; i < open.size(); ++i) {
                ofs << "    { \"port\": " << open[i].port << ", \"banner\": ";
                if (!open[i].banner.empty()) {
                    // escape quotes roughly
                    std::string b = open[i].banner;
                    for (char &c : b) if (c == '\n' || c == '\r') c = ' ';
                    size_t pos = 0;
                    std::string esc;
                    for (char ch : b) {
                        if (ch == '\"') esc += "\\\"";
                        else esc += ch;
                    }
                    ofs << "\"" << esc << "\"";
                } else {
                    ofs << "null";
                }
                ofs << " }";
                if (i + 1 < open.size()) ofs << ",";
                ofs << "\n";
            }
            ofs << "  ]\n}\n";
            std::cout << "\n💾 Results saved to " << save_file << "\n";
        } else {
            std::cout << "❌ Failed to open file for writing: " << save_file << "\n";
        }
    }

    return 0;
}
