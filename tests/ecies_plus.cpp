#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <memory>

struct ECKeyDeleter {
    void operator()(EC_KEY* p) const { EC_KEY_free(p); }
};

using UniqueECKey = std::unique_ptr<EC_KEY, ECKeyDeleter>;

class EncryptionManager {
public:
    UniqueECKey generate_key_pair() {
        UniqueECKey eckey(EC_KEY_new_by_curve_name(NID_secp256k1));
        if (!eckey || !EC_KEY_generate_key(eckey.get())) {
            throw std::runtime_error("Error generating EC key");
        }
        return eckey;
    }

    void save_private_key(const std::string& filename, const UniqueECKey& ec_key) {
        BIO* out = BIO_new_file(filename.c_str(), "w");
        if (!out || !PEM_write_bio_ECPrivateKey(out, ec_key.get(), nullptr, nullptr, 0, nullptr, nullptr)) {
            BIO_free(out);
            throw std::runtime_error("Error writing private key to file");
        }
        BIO_free(out);
    }

    void save_public_key(const std::string& filename, const UniqueECKey& ec_key) {
        BIO* out = BIO_new_file(filename.c_str(), "w");
        if (!out || !PEM_write_bio_EC_PUBKEY(out, ec_key.get())) {
            BIO_free(out);
            throw std::runtime_error("Error writing public key to file");
        }
        BIO_free(out);
    }

    UniqueECKey load_public_key(const std::string& filename) {
        FILE* file = fopen(filename.c_str(), "rb");
        if (!file) throw std::runtime_error("Error opening public key file");
        UniqueECKey ecKey(PEM_read_EC_PUBKEY(file, nullptr, nullptr, nullptr));
        fclose(file);
        if (!ecKey) throw std::runtime_error("Error loading public key");
        return ecKey;
    }

    UniqueECKey load_private_key(const std::string& filename) {
        FILE* file = fopen(filename.c_str(), "rb");
        if (!file) throw std::runtime_error("Error opening private key file");
        UniqueECKey ecKey(PEM_read_ECPrivateKey(file, nullptr, nullptr, nullptr));
        fclose(file);
        if (!ecKey) throw std::runtime_error("Error loading private key");
        return ecKey;
    }

    std::vector<uint8_t> load_from_file(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        if (!file.is_open()) {
            throw std::runtime_error("Error opening file for reading: " + filename);
        }
        return std::vector<uint8_t>(
            std::istreambuf_iterator<char>(file),
            std::istreambuf_iterator<char>());
    }

    void save_to_file(const std::string& filename, const std::vector<uint8_t>& data) {
        std::ofstream file(filename, std::ios::binary);
        if (!file.is_open()) {
            throw std::runtime_error("Error opening file for writing: " + filename);
        }
        file.write(reinterpret_cast<const char*>(data.data()), data.size());
        file.close();
    }

    void derive_shared_secret(EC_KEY* myKey, EC_KEY* peerKey, std::vector<uint8_t>& secret) {
        secret.resize(32); // Allocate space for AES-256 secret
        int secret_len = ECDH_compute_key(secret.data(), secret.size(),
                                            EC_KEY_get0_public_key(peerKey), myKey, nullptr);
        if (secret_len < 0) {
            throw std::runtime_error("Error deriving shared secret");
        }
        secret.resize(secret_len);
    }

    void encrypt_data_with_public_key(const std::vector<uint8_t>& plaintext, const UniqueECKey& publicKey, std::vector<uint8_t>& ciphertext) {
        std::vector<uint8_t> sharedSecret(32); // Allocate space for AES-256 secret
        derive_shared_secret(publicKey.get(), publicKey.get(), sharedSecret);

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
        EVP_EncryptInit_ex(ctx, cipher, nullptr, sharedSecret.data(), iv);
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

    void decrypt_data_with_private_key(const std::vector<uint8_t>& ciphertext, const UniqueECKey& privateKey, std::vector<uint8_t>& plaintext) {
        std::vector<uint8_t> sharedSecret(32); // Allocate space for AES-256 secret
        derive_shared_secret(privateKey.get(), privateKey.get(), sharedSecret);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        const EVP_CIPHER* cipher = EVP_aes_256_cbc();
        int len;

        // Extract IV
        std::vector<uint8_t> iv(ciphertext.begin(), ciphertext.begin() + EVP_MAX_IV_LENGTH);
        std::vector<uint8_t> encData(ciphertext.begin() + EVP_MAX_IV_LENGTH, ciphertext.end());

        // Initialize decryption
        EVP_DecryptInit_ex(ctx, cipher, nullptr, sharedSecret.data(), iv.data());

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
};

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] << " <plaintext_file> <ciphertext_file> <decrypted_file> <use_public_key>(0/1)" << std::endl;
        return 1;
    }

    std::string plaintextFile = argv[1];
    std::string ciphertextFile = argv[2];
    std::string decryptedFile = argv[3];
    bool usePublicKey = std::string(argv[4]) == "1"; // 1表示使用公钥加密，0表示使用私钥解密

    try {
        OpenSSL_add_all_algorithms();
        ERR_load_BIO_strings();
        ERR_load_crypto_strings();

        EncryptionManager encryptionManager;

        // Generate key pair
        UniqueECKey myKeyPair = encryptionManager.generate_key_pair();
        encryptionManager.save_private_key("my_private_key.pem", myKeyPair);
        encryptionManager.save_public_key("my_public_key.pem", myKeyPair);

        // Load peer public key
        UniqueECKey peerKey = encryptionManager.load_public_key("my_public_key.pem"); // Use your own for testing

        if (usePublicKey) {
            // 加密过程
            std::vector<uint8_t> plaintext = encryptionManager.load_from_file(plaintextFile);
            std::vector<uint8_t> ciphertext;
            encryptionManager.encrypt_data_with_public_key(plaintext, peerKey, ciphertext);
            encryptionManager.save_to_file(ciphertextFile, ciphertext);
        } else {
            // 解密过程
            std::vector<uint8_t> ciphertext = encryptionManager.load_from_file(ciphertextFile);
            std::vector<uint8_t> decryptedText;
            encryptionManager.decrypt_data_with_private_key(ciphertext, myKeyPair, decryptedText);
            encryptionManager.save_to_file(decryptedFile, decryptedText);
        }

        std::cout << "Success!" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Exception caught: " << e.what() << std::endl;
        ERR_print_errors_fp(stderr);
        return 1;
    }
    return 0;
}
