#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <memory>

class ECKeyWrapper {
public:
    ECKeyWrapper() : key(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) {
        if (!key || !EC_KEY_generate_key(key)) {
            throw std::runtime_error("Failed to generate EC key");
        }
    }

    ~ECKeyWrapper() {
        if (key) {
            EC_KEY_free(key);
        }
    }

    EC_KEY* get() const {
        return key;
    }

private:
    EC_KEY* key;
};

std::vector<unsigned char> derive_shared_secret(EC_KEY* local_key, const EC_POINT* peer_pub_key) {
    std::vector<unsigned char> secret(ECDH_size(local_key));
    int secret_len = ECDH_compute_key(secret.data(), secret.size(), peer_pub_key, local_key, nullptr);
    if (secret_len <= 0) {
        throw std::runtime_error("Failed to derive shared secret");
    }
    secret.resize(secret_len);
    return secret;
}

std::vector<unsigned char> aes_encrypt(const std::vector<unsigned char>& key, const std::vector<unsigned char>& data) {
    std::vector<unsigned char> iv(EVP_MAX_IV_LENGTH);
    RAND_bytes(iv.data(), iv.size());
    std::vector<unsigned char> encrypted(data.size() + EVP_MAX_BLOCK_LENGTH);
    int outlen, tmplen;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create EVP_CIPHER_CTX");

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
    EVP_EncryptUpdate(ctx, encrypted.data(), &outlen, data.data(), data.size());
    EVP_EncryptFinal_ex(ctx, encrypted.data() + outlen, &tmplen);
    EVP_CIPHER_CTX_free(ctx);

    encrypted.resize(outlen + tmplen);
    encrypted.insert(encrypted.begin(), iv.begin(), iv.end());
    return encrypted;
}

std::vector<unsigned char> aes_decrypt(const std::vector<unsigned char>& key, const std::vector<unsigned char>& encrypted_data) {
    std::vector<unsigned char> iv(encrypted_data.begin(), encrypted_data.begin() + EVP_MAX_IV_LENGTH);
    std::vector<unsigned char> data(encrypted_data.begin() + EVP_MAX_IV_LENGTH, encrypted_data.end());
    std::vector<unsigned char> decrypted(data.size());
    int outlen, tmplen;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create EVP_CIPHER_CTX");

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
    EVP_DecryptUpdate(ctx, decrypted.data(), &outlen, data.data(), data.size());
    EVP_DecryptFinal_ex(ctx, decrypted.data() + outlen, &tmplen);
    EVP_CIPHER_CTX_free(ctx);

    decrypted.resize(outlen + tmplen);
    return decrypted;
}

std::vector<unsigned char> read_file(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) throw std::runtime_error("Failed to open file: " + filepath);
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

void write_file(const std::string& filepath, const std::vector<unsigned char>& data) {
    std::ofstream file(filepath, std::ios::binary);
    if (!file) throw std::runtime_error("Failed to open file: " + filepath);
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

int main() {
    try {
        ECKeyWrapper sender_key;  // 生成发送方的密钥对
        ECKeyWrapper receiver_key;  // 生成接收方的密钥对

        const EC_POINT* receiver_pub_key = EC_KEY_get0_public_key(receiver_key.get());

        std::vector<unsigned char> shared_secret = derive_shared_secret(sender_key.get(), receiver_pub_key);

        std::vector<unsigned char> symmetric_key(SHA256_DIGEST_LENGTH);
        SHA256(shared_secret.data(), shared_secret.size(), symmetric_key.data());

        std::vector<unsigned char> file_data = read_file("plaintext.txt");

        std::vector<unsigned char> encrypted_data = aes_encrypt(symmetric_key, file_data);

        write_file("encrypted.dat", encrypted_data);

        const EC_POINT* sender_pub_key = EC_KEY_get0_public_key(sender_key.get());
        std::vector<unsigned char> receiver_shared_secret = derive_shared_secret(receiver_key.get(), sender_pub_key);

        std::vector<unsigned char> receiver_symmetric_key(SHA256_DIGEST_LENGTH);
        SHA256(receiver_shared_secret.data(), receiver_shared_secret.size(), receiver_symmetric_key.data());

        std::vector<unsigned char> encrypted_file_data = read_file("encrypted.dat");

        std::vector<unsigned char> decrypted_data = aes_decrypt(receiver_symmetric_key, encrypted_file_data);

        write_file("decrypted.txt", decrypted_data);

        std::cout << "Encryption and decryption completed successfully." << std::endl;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
