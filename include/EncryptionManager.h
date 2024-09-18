#ifndef ENCRYPTION_MANAGER_H
#define ENCRYPTION_MANAGER_H

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <vector>
#include <memory>
#include <stdexcept>
#include <fstream>

struct ECKeyDeleter {
    void operator()(EC_KEY* p) const { EC_KEY_free(p); }
};

using UniqueECKey = std::unique_ptr<EC_KEY, ECKeyDeleter>;

class EncryptionManager {
public:
    UniqueECKey generate_key_pair();
    void save_private_key(const std::string& filename, const UniqueECKey& ec_key);
    void save_public_key(const std::string& filename, const UniqueECKey& ec_key);
    UniqueECKey load_public_key(const std::string& filename);
    UniqueECKey load_private_key(const std::string& filename);
    std::vector<uint8_t> load_from_file(const std::string& filename);
    void save_to_file(const std::string& filename, const std::vector<uint8_t>& data);
    void derive_shared_secret(EC_KEY* myKey, EC_KEY* peerKey, std::vector<uint8_t>& secret);
    void encrypt_data(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& secret, std::vector<uint8_t>& ciphertext);
    void decrypt_data(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& secret, std::vector<uint8_t>& plaintext);
};

#endif // ENCRYPTION_MANAGER_H
