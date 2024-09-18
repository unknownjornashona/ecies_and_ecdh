#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <memory>
#include <string>

// RAII wrapper for EC_KEY to handle automatic memory management
struct ECKeyDeleter {
    void operator()(EC_KEY* p) const { EC_KEY_free(p); }
};

using UniqueECKey = std::unique_ptr<EC_KEY, ECKeyDeleter>;

class KeyPairGenerator {
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
};

int main() {
    try {
        KeyPairGenerator keyGen;

        // 生成密钥对
        UniqueECKey keyPair = keyGen.generate_key_pair();

        // 保存公钥和私钥
        keyGen.save_private_key("private_key.pem", keyPair);
        keyGen.save_public_key("public_key.pem", keyPair);

        std::cout << "公钥和私钥生成成功并保存到文件。" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "发生异常: " << e.what() << std::endl;
        ERR_print_errors_fp(stderr);
        return 1;
    }

    return 0;
}
