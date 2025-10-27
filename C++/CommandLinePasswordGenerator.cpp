// pwman.cpp
// Simple personal command-line password manager (educational).
// Build: g++ -std=c++17 pwman.cpp -o pwman -lcrypto

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <cstring>
#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <sstream>
#include <iomanip>

using u8 = unsigned char;
using bytes = std::vector<u8>;

static const int SALT_LEN = 16;
static const int IV_LEN = 12; // recommended for GCM
static const int TAG_LEN = 16;
static const int KEY_LEN = 32; // 256-bit key
static const int PBKDF2_ITERS = 200000; // reasonable default

// Vault file format (binary):
// [salt (16 bytes)] [iv (12 bytes)] [ciphertext (N bytes)] [tag (16 bytes)]
// ciphertext is encryption of UTF-8 plaintext containing entries lines:
// name|username|password|notes\n

// Utility: print OpenSSL errors
void print_openssl_error() {
    unsigned long e = ERR_get_error();
    while(e) {
        char buf[256];
        ERR_error_string_n(e, buf, sizeof(buf));
        std::cerr << "OpenSSL error: " << buf << "\n";
        e = ERR_get_error();
    }
}

// Derive key using PBKDF2-HMAC-SHA256
bool derive_key(const std::string &password, const bytes &salt, bytes &out_key) {
    out_key.assign(KEY_LEN, 0);
    if (PKCS5_PBKDF2_HMAC(password.c_str(), (int)password.size(),
                          salt.data(), (int)salt.size(),
                          PBKDF2_ITERS, EVP_sha256(),
                          KEY_LEN, out_key.data()) == 0) {
        print_openssl_error();
        return false;
    }
    return true;
}

// AES-256-GCM encrypt
bool aes_gcm_encrypt(const bytes &key, const bytes &plaintext, bytes &iv, bytes &ciphertext, bytes &tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    int len;
    ciphertext.assign(plaintext.size(), 0);
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
        print_openssl_error(); EVP_CIPHER_CTX_free(ctx); return false;
    }
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr)) {
        print_openssl_error(); EVP_CIPHER_CTX_free(ctx); return false;
    }
    if (1 != EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data())) {
        print_openssl_error(); EVP_CIPHER_CTX_free(ctx); return false;
    }
    int outlen = 0;
    if (plaintext.size() > 0) {
        if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), (int)plaintext.size())) {
            print_openssl_error(); EVP_CIPHER_CTX_free(ctx); return false;
        }
        outlen += len;
    }
    int tmplen;
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data()+outlen, &tmplen)) {
        print_openssl_error(); EVP_CIPHER_CTX_free(ctx); return false;
    }
    outlen += tmplen;
    tag.assign(TAG_LEN, 0);
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag.data())) {
        print_openssl_error(); EVP_CIPHER_CTX_free(ctx); return false;
    }
    ciphertext.resize(outlen);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// AES-256-GCM decrypt
bool aes_gcm_decrypt(const bytes &key, const bytes &iv, const bytes &ciphertext, const bytes &tag, bytes &plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
        print_openssl_error(); EVP_CIPHER_CTX_free(ctx); return false;
    }
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr)) {
        print_openssl_error(); EVP_CIPHER_CTX_free(ctx); return false;
    }
    if (1 != EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data())) {
        print_openssl_error(); EVP_CIPHER_CTX_free(ctx); return false;
    }
    plaintext.assign(ciphertext.size(), 0);
    int len;
    if (ciphertext.size() > 0) {
        if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), (int)ciphertext.size())) {
            print_openssl_error(); EVP_CIPHER_CTX_free(ctx); return false;
        }
    }
    // set expected tag
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag.size(), (void*)tag.data())) {
        print_openssl_error(); EVP_CIPHER_CTX_free(ctx); return false;
    }
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data()+len, &len);
    EVP_CIPHER_CTX_free(ctx);
    if (ret <= 0) {
        // authentication failed
        return false;
    }
    return true;
}

// High-level: encrypt vault content with a new random salt+iv
bool encrypt_vault(const std::string &master, const std::string &plaintext, bytes &out_blob) {
    bytes salt(SALT_LEN), iv(IV_LEN);
    if (1 != RAND_bytes(salt.data(), SALT_LEN)) return false;
    if (1 != RAND_bytes(iv.data(), IV_LEN)) return false;
    bytes key;
    if (!derive_key(master, salt, key)) return false;
    bytes pt(plaintext.begin(), plaintext.end());
    bytes ct, tag;
    if (!aes_gcm_encrypt(key, pt, iv, ct, tag)) return false;
    // assemble: salt || iv || ct || tag
    out_blob.clear();
    out_blob.insert(out_blob.end(), salt.begin(), salt.end());
    out_blob.insert(out_blob.end(), iv.begin(), iv.end());
    out_blob.insert(out_blob.end(), ct.begin(), ct.end());
    out_blob.insert(out_blob.end(), tag.begin(), tag.end());
    return true;
}

// High-level: decrypt the blob to plaintext
bool decrypt_vault(const std::string &master, const bytes &blob, std::string &out_plaintext) {
    if ((int)blob.size() < SALT_LEN + IV_LEN + TAG_LEN) return false;
    size_t pos = 0;
    bytes salt(blob.begin(), blob.begin()+SALT_LEN); pos += SALT_LEN;
    bytes iv(blob.begin()+pos, blob.begin()+pos+IV_LEN); pos += IV_LEN;
    size_t tag_pos = blob.size() - TAG_LEN;
    bytes ct(blob.begin()+pos, blob.begin()+tag_pos);
    bytes tag(blob.begin()+tag_pos, blob.end());
    bytes key;
    if (!derive_key(master, salt, key)) return false;
    bytes pt;
    if (!aes_gcm_decrypt(key, iv, ct, tag, pt)) return false;
    out_plaintext.assign(pt.begin(), pt.end());
    return true;
}

// Simple vault format (in plaintext before encryption):
// Each line: name|username|password|notes
// We'll keep an in-memory map<string,tuple...>

struct Entry {
    std::string user;
    std::string pass;
    std::string notes;
};

using Vault = std::map<std::string, Entry>;

Vault parse_plain_vault(const std::string &s) {
    Vault v;
    std::istringstream iss(s);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.empty()) continue;
        // split into 4 parts by first 3 '|' occurrences
        size_t p1 = line.find('|');
        if (p1 == std::string::npos) continue;
        size_t p2 = line.find('|', p1+1);
        if (p2 == std::string::npos) continue;
        size_t p3 = line.find('|', p2+1);
        if (p3 == std::string::npos) continue;
        std::string name = line.substr(0, p1);
        std::string user = line.substr(p1+1, p2-p1-1);
        std::string pass = line.substr(p2+1, p3-p2-1);
        std::string notes = line.substr(p3+1);
        v[name] = Entry{user, pass, notes};
    }
    return v;
}

std::string serialize_vault(const Vault &v) {
    std::ostringstream oss;
    for (auto &kv : v) {
        // escape newlines not necessary as we forbid newline in fields by input
        oss << kv.first << "|" << kv.second.user << "|" << kv.second.pass << "|" << kv.second.notes << "\n";
    }
    return oss.str();
}

// file IO helpers
bool write_file(const std::string &path, const bytes &data) {
    std::ofstream f(path, std::ios::binary);
    if (!f) return false;
    f.write((const char*)data.data(), data.size());
    return true;
}
bool read_file(const std::string &path, bytes &out) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return false;
    std::streamsize sz = f.tellg();
    f.seekg(0, std::ios::beg);
    out.resize(sz);
    if (!f.read((char*)out.data(), sz)) return false;
    return true;
}

// Prompt helpers (no-echo for password)
std::string prompt_hidden(const std::string &prompt) {
    std::string pw;
#if defined(_WIN32)
    // Windows implementation - fallback to visible input (simple)
    std::cout << prompt;
    std::getline(std::cin, pw);
#else
    std::cout << prompt;
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    std::getline(std::cin, pw);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << "\n";
#endif
    return pw;
}

std::string prompt(const std::string &p) {
    std::string s;
    std::cout << p;
    std::getline(std::cin, s);
    return s;
}

// high-level vault operations
bool load_vault(const std::string &vault_path, const std::string &master, Vault &out_v) {
    bytes blob;
    if (!read_file(vault_path, blob)) {
        return false;
    }
    std::string plain;
    if (!decrypt_vault(master, blob, plain)) {
        return false;
    }
    out_v = parse_plain_vault(plain);
    return true;
}

bool save_vault(const std::string &vault_path, const std::string &master, const Vault &v) {
    std::string plain = serialize_vault(v);
    bytes blob;
    if (!encrypt_vault(master, plain, blob)) return false;
    return write_file(vault_path, blob);
}

// small helpers
void show_usage() {
    std::cout << "Usage: pwman <command> [args]\n";
    std::cout << "Commands:\n";
    std::cout << "  init                Create a new vault (vault.dat)\n";
    std::cout << "  add <name>          Add an entry\n";
    std::cout << "  get <name>          Show an entry\n";
    std::cout << "  rm <name>           Remove an entry\n";
    std::cout << "  list                List entry names\n";
    std::cout << "  changemaster        Change master password\n";
    std::cout << "  help                Show this message\n";
}

// main
int main(int argc, char **argv) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    const std::string VAULT_PATH = "vault.dat";

    if (argc < 2) {
        show_usage();
        return 1;
    }
    std::string cmd = argv[1];

    if (cmd == "help") {
        show_usage();
        return 0;
    }

    if (cmd == "init") {
        // create new vault
        if (std::ifstream(VAULT_PATH)) {
            std::cout << "Vault already exists at " << VAULT_PATH << ". Aborting.\n";
            return 1;
        }
        std::string pw1 = prompt_hidden("Choose master password: ");
        std::string pw2 = prompt_hidden("Confirm master password: ");
        if (pw1 != pw2) {
            std::cout << "Passwords did not match.\n";
            return 1;
        }
        Vault v;
        if (!save_vault(VAULT_PATH, pw1, v)) {
            std::cout << "Failed to create vault.\n";
            return 1;
        }
        std::cout << "Vault created at " << VAULT_PATH << "\n";
        return 0;
    }

    if (cmd == "add") {
        if (argc < 3) { std::cout << "Specify name for the entry.\n"; return 1; }
        std::string name = argv[2];
        std::string master = prompt_hidden("Master password: ");
        Vault v;
        if (!load_vault(VAULT_PATH, master, v)) {
            std::cout << "Failed to open vault. Wrong password or vault missing.\n"; return 1;
        }
        if (v.find(name) != v.end()) {
            std::cout << "Entry exists. Overwrite? (y/N): ";
            std::string ans; std::getline(std::cin, ans);
            if (ans != "y" && ans != "Y") { std::cout << "Aborted.\n"; return 1; }
        }
        std::string username = prompt("Username: ");
        std::string password = prompt_hidden("Password: ");
        std::string notes = prompt("Notes: ");
        v[name] = Entry{username, password, notes};
        if (!save_vault(VAULT_PATH, master, v)) {
            std::cout << "Failed to save vault.\n"; return 1;
        }
        std::cout << "Saved entry '" << name << "'.\n";
        return 0;
    }

    if (cmd == "get") {
        if (argc < 3) { std::cout << "Specify name.\n"; return 1; }
        std::string name = argv[2];
        std::string master = prompt_hidden("Master password: ");
        Vault v;
        if (!load_vault(VAULT_PATH, master, v)) {
            std::cout << "Failed to open vault. Wrong password or vault missing.\n"; return 1;
        }
        auto it = v.find(name);
        if (it == v.end()) { std::cout << "No entry named '" << name << "'.\n"; return 1; }
        std::cout << "Name: " << name << "\n";
        std::cout << "Username: " << it->second.user << "\n";
        std::cout << "Password: " << it->second.pass << "\n";
        std::cout << "Notes: " << it->second.notes << "\n";
        return 0;
    }

    if (cmd == "rm") {
        if (argc < 3) { std::cout << "Specify name.\n"; return 1; }
        std::string name = argv[2];
        std::string master = prompt_hidden("Master password: ");
        Vault v;
        if (!load_vault(VAULT_PATH, master, v)) {
            std::cout << "Failed to open vault. Wrong password or vault missing.\n"; return 1;
        }
        auto it = v.find(name);
        if (it == v.end()) { std::cout << "No entry named '" << name << "'.\n"; return 1; }
        v.erase(it);
        if (!save_vault(VAULT_PATH, master, v)) {
            std::cout << "Failed to save vault.\n"; return 1;
        }
        std::cout << "Removed '" << name << "'.\n";
        return 0;
    }

    if (cmd == "list") {
        std::string master = prompt_hidden("Master password: ");
        Vault v;
        if (!load_vault(VAULT_PATH, master, v)) {
            std::cout << "Failed to open vault. Wrong password or vault missing.\n"; return 1;
        }
        std::cout << "Entries:\n";
        for (auto &kv : v) {
            std::cout << " - " << kv.first << "\n";
        }
        return 0;
    }

    if (cmd == "changemaster") {
        std::string oldpw = prompt_hidden("Old master password: ");
        Vault v;
        if (!load_vault(VAULT_PATH, oldpw, v)) {
            std::cout << "Failed to open vault. Wrong password or vault missing.\n"; return 1;
        }
        std::string new1 = prompt_hidden("New master password: ");
        std::string new2 = prompt_hidden("Confirm new master password: ");
        if (new1 != new2) { std::cout << "Passwords do not match.\n"; return 1; }
        if (!save_vault(VAULT_PATH, new1, v)) {
            std::cout << "Failed to re-encrypt vault.\n"; return 1;
        }
        std::cout << "Master password changed.\n";
        return 0;
    }

    std::cout << "Unknown command.\n";
    show_usage();
    return 1;
}
