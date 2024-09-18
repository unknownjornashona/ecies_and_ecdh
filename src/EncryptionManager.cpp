#include "EncryptionManager.h"

UniqueECKey EncryptionManager::generate_key_pair() {
    UniqueECKey eckey(EC_KEY_new_by_curve_name(NID_secp256k1));
    if (!eckey || !EC_KEY_generate_key(eckey.get())) {
        throw std::runtime_error("Error generating EC key");
    }
    return eckey;
}

void EncryptionManager::save_private_key(const std::string& filename, const UniqueECKey& ec_key) {
    BIO* out = BIO_new_file(filename.c_str(), "w");
    if (!out || !PEM_write_bio_ECPrivateKey(out, ec_key.get(), nullptr, nullptr, 0, nullptr, nullptr)) {
        BIO_free(out);
        throw std::runtime_error("Error writing private key to file");
    }
    BIO_free(out);
}

void EncryptionManager::save_public_key(const std::string& filename, const UniqueECKey& ec_key) {
    BIO* out = BIO_new_file(filename.c_str(), "w");
    if (!out || !PEM_write_bio_EC_PUBKEY(out, ec_key.get())) {
        BIO_free(out);
        throw std::runtime_error("Error writing public key to file");
    }
    BIO_free(out);
}

UniqueECKey EncryptionManager::load_public_key(const std::string& filename) {
    FILE* file = fopen(filename.c_str(), "rb");
    if (!file) throw std::runtime_error("Error opening public key file");
    UniqueECKey ecKey(PEM_read_EC_PUBKEY(file, nullptr, nullptr, nullptr));
    fclose(file);
    if (!ecKey) throw std::runtime_error("Error loading public key");
    return ecKey;
}

UniqueECKey EncryptionManager::load_private_key(const std::string& filename) {
    FILE* file = fopen(filename.c_str(), "rb");
    if (!file) throw std::runtime_error("Error opening private key file");
    UniqueECKey ecKey(PEM_read_ECPrivateKey(file, nullptr, nullptr, nullptr));
    fclose(file);
    if (!ecKey) throw std::runtime_error("Error loading private key");
    return ecKey;
}

std::vector<uint8_t> EncryptionManager::load_from_file(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Error opening file for reading: " + filename);
    }
    return std::vector<uint8_t>(
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>());
}

void EncryptionManager::save_to_file(const std::string& filename, const std::vector<uint8_t>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Error opening file for writing: " + filename);
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

void EncryptionManager::derive_shared_secret(EC_KEY* myKey, EC_KEY* peerKey, std::vector<uint8_t>& secret) {
    secret.resize(32); // Allocate space for AES-256 secret
    int secret_len = ECDH_compute_key(secret.data(), secret.size(),
                                        EC_KEY_get0_public_key(peerKey), myKey, nullptr);
    if (secret_len < 0) {
        throw std::runtime_error("Error deriving shared secret");
    }
    secret.resize(secret_len);
}

void EncryptionManager::encrypt_data(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& secret, std::vector<uint8_t>& ciphertext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    int len;
    unsigned char iv[EVP_MAX_IV_LENGTH];

    // Generate IV
    if (!RAND_bytes(iv, sizeof(iv))) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Could not generate random IV");
    }

    // Initialize encryption
    EVP_EncryptInit_ex(ctx, cipher, nullptr, secret.data(), iv);
    ciphertext.resize(plaintext.size() + EVP_CIPHER_block_size(cipher)); // Reserve enough space

    // Encrypt
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    int ciphertext_len = len;

    // Finalize
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len); // Resize to final length

    EVP_CIPHER_CTX_free(ctx);
    ciphertext.insert(ciphertext.begin(), iv, iv + sizeof(iv)); // Prepend IV
}

void EncryptionManager::decrypt_data(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& secret, std::vector<uint8_t>& plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    int len;

    // Extract IV
    std::vector<uint8_t> iv(ciphertext.begin(), ciphertext.begin() + EVP_MAX_IV_LENGTH);
    std::vector<uint8_t> encData(ciphertext.begin() + EVP_MAX_IV_LENGTH, ciphertext.end());

    // Initialize decryption
    EVP_DecryptInit_ex(ctx, cipher, nullptr, secret.data(), iv.data());

    plaintext.resize(encData.size()); // Reserve space for decrypted data

    // Decrypt
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, encData.data(), encData.size());
    int plaintext_len = len;

    // Finalize
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    plaintext_len += len;
    plaintext.resize(plaintext_len); // Resize to final length

    EVP_CIPHER_CTX_free(ctx);
}
